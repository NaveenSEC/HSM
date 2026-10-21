/**
 * @file  test_secure_boot_chain.c
 * @brief End-to-end tests of the chain of trust:
 *        HSM secure boot (BM+BL) -> Boot Manager -> Application,
 *        UDS bootloader re-programming with HSM based security access,
 *        image authenticity / integrity / anti roll-back, attack scenarios.
 */
#include "test_helpers.h"
#include "BootManager.h"
#include "Bootloader.h"
#include "ImageVerify.h"
#include "AppHeader.h"
#include "Fls.h"
#include "Hsm.h"
#include "Hsm_KeyStore.h"
#include "Crypto_HsmExt.h"
#include "Csm.h"
#include "hsm_cmac.h"

static uint8 rsp[BL_MAX_BLOCK_LEN + 16];

static uint32 uds(const uint8 *req, uint32 len)
{
    return Tester_Request(req, len, rsp);
}

static void test_virgin_device_starts_bootloader(void)
{
    Ecu_SimSetEntropySeed(1);
    Ecu_FactoryInit(TEST_UID);
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_Reset());
    TEST_ASSERT_EQUAL(BM_REASON_APP_INVALID, BootManager_GetDecision()->reason);
    TEST_ASSERT_EQUAL(IMGV_NO_IMAGE, BootManager_GetDecision()->appResult);
    TEST_ASSERT_EQUAL(HSM_ERC_NO_SECURE_BOOT, BootManager_GetDecision()->hsmBootResult);
    TEST_ASSERT_FALSE(BootManager_GetDecision()->secureBootEnforced);
}

static void test_eol_provisioning_enables_secure_boot(void)
{
    uint8 sreg = 0;
    Hsm_ErrorType erc = 0xFF;
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(E_OK, Crypto_Hsm_GetStatus(&sreg, &erc));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, erc);
    TEST_ASSERT_TRUE((sreg & HSM_SREG_BOOT_OK) != 0);
    TEST_ASSERT_TRUE((sreg & HSM_SREG_BOOT_FINISHED) != 0);
    TEST_ASSERT_TRUE(BootManager_GetDecision()->secureBootEnforced);
    TEST_ASSERT_EQUAL(HSM_LC_IN_FIELD, Hsm_KeyStoreNvm()->lifecycle);
    TEST_ASSERT_TRUE(Hsm_KeyStoreSlot(HSM_KEY_BOOT_MAC)->valid);
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_GetState());
}

static void test_flash_and_boot_application(void)
{
    uint8 req[3] = {0x22, 0xF1, 0x81};
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(1, 0x2345));
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_GetState());
    TEST_ASSERT_EQUAL(BM_REASON_APP_VALID, BootManager_GetDecision()->reason);
    TEST_ASSERT_EQUAL(7, uds(req, 3));
    TEST_ASSERT_EQUAL(1, rsp[6]);
    /* anti roll-back counter committed in HSM */
    TEST_ASSERT_EQUAL(1, Hsm_KeyStoreNvm()->monotonicCounter[APP_ROLLBACK_COUNTER_ID]);
    /* power cycle -> still boots the application */
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_Reset());
}

static void test_update_via_programming_request(void)
{
    uint8 req[3] = {0x22, 0xF1, 0x81};
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(1, 0x1000));
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_GetState());
    /* app receives 10 02 -> sets programming flag -> reset -> bootloader */
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(2, 0x3000));
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_GetState());
    TEST_ASSERT_EQUAL(7, uds(req, 3));
    TEST_ASSERT_EQUAL(2, rsp[6]);
    TEST_ASSERT_EQUAL(2, Hsm_KeyStoreNvm()->monotonicCounter[APP_ROLLBACK_COUNTER_ID]);
}

static void test_programming_request_flow(void)
{
    uint8 req[2] = {0x10, 0x02};
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(1, 0x800));
    TEST_ASSERT_EQUAL(2, uds(req, 2) >= 2 ? 2 : 0);
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_GetState());
    TEST_ASSERT_EQUAL(BM_REASON_PROG_REQUEST, BootManager_GetDecision()->reason);
    /* abort: ECU reset without programming -> flag still set -> bootloader */
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_Reset());
}

static void test_rollback_rejected(void)
{
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(5, 0x1000));
    /* attacker flashes an old, correctly signed but vulnerable version */
    TEST_ASSERT_EQUAL(TESTER_CHECK_FAILED, flash_app(3, 0x1000));
    TEST_ASSERT_EQUAL(IMGV_ROLLBACK, Tester_Info.checkReason);
    /* update not completed: programming request stays active -> bootloader */
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_Reset());
    TEST_ASSERT_EQUAL(BM_REASON_PROG_REQUEST, BootManager_GetDecision()->reason);
    TEST_ASSERT_EQUAL(IMGV_ROLLBACK, ImageVerify_Application(NULL_PTR));
    /* same version may be re-flashed */
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(5, 0x1000));
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_GetState());
}

static void test_tampered_application_in_flash(void)
{
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(1, 0x4000));
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_GetState());
    /* attacker patches one byte of application code (e.g. via JTAG/flash programmer) */
    Fls_SimCorrupt(APP_BODY_START + 0x1234, 0x01);
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_Reset());
    TEST_ASSERT_EQUAL(IMGV_DIGEST_MISMATCH, BootManager_GetDecision()->appResult);
    /* patching the header (e.g. sw version) breaks the header CMAC */
    Fls_SimCorrupt(APP_BODY_START + 0x1234, 0x01);
    Fls_SimCorrupt(APP_START + APPHDR_OFF_SWVER + 3, 0x40);
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_Reset());
    TEST_ASSERT_EQUAL(IMGV_MAC_INVALID, BootManager_GetDecision()->appResult);
    /* attacker also replaces the digest -> MAC still invalid */
    Fls_SimCorrupt(APP_START + APPHDR_OFF_SWVER + 3, 0x40);
    Fls_SimCorrupt(APP_START + APPHDR_OFF_DIGEST, 0xFF);
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_Reset());
    TEST_ASSERT_EQUAL(IMGV_MAC_INVALID, BootManager_GetDecision()->appResult);
    Fls_SimCorrupt(APP_START + APPHDR_OFF_DIGEST, 0xFF);
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_Reset());
}

static void test_image_signed_with_wrong_key_rejected(void)
{
    static uint8 body[0x1000];
    uint8 fakeKey[16] = {0xBA, 0xD0};
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    Backend_BuildDemoAppBody(9, body, sizeof body);
    TEST_ASSERT_EQUAL(E_OK, Backend_BuildAppImage(9, body, sizeof body, fakeKey, test_image, sizeof test_image, &test_image_len));
    TEST_ASSERT_EQUAL(TESTER_CHECK_FAILED, Tester_FlashApplication(test_image, test_image_len, Backend_DemoKeys.diagKey));
    TEST_ASSERT_EQUAL(IMGV_MAC_INVALID, Tester_Info.checkReason);
    TEST_ASSERT_EQUAL(0, Hsm_KeyStoreNvm()->monotonicCounter[APP_ROLLBACK_COUNTER_ID]);
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_Reset());
}

static void test_interrupted_download_recovers(void)
{
    uint8 req[16];
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(1, 0x1000));
    /* start an update, erase, then "power loss" */
    req[0] = 0x10; req[1] = 0x02;
    uds(req, 2);
    TEST_ASSERT_EQUAL(TESTER_OK, Tester_Unlock(Backend_DemoKeys.diagKey));
    req[0] = 0x31; req[1] = 0x01; req[2] = 0xFF; req[3] = 0x00; req[4] = 0x44;
    AppHeader_Put32(&req[5], APP_START); AppHeader_Put32(&req[9], APP_SIZE);
    TEST_ASSERT_EQUAL(5, uds(req, 13));
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_Reset());
    TEST_ASSERT_EQUAL(IMGV_NO_IMAGE, BootManager_GetDecision()->appResult);
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(2, 0x1000));
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_GetState());
}

static void test_tampered_bootloader_halts_and_locks_keys(void)
{
    uint8 mac[16];
    uint32 l = 16;
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(1, 0x1000));
    /* attacker patches the bootloader (e.g. to skip signature checks) */
    Fls_SimCorrupt(BL_START + 0x100, 0x20);
    TEST_ASSERT_EQUAL(ECU_STATE_HALTED, Ecu_Reset());
    TEST_ASSERT_EQUAL(BM_REASON_SECURE_BOOT_FAILED, BootManager_GetDecision()->reason);
    TEST_ASSERT_EQUAL(HSM_ERC_VERIFY_FAILED, Hsm_GetLastBootResult());
    TEST_ASSERT_TRUE((Hsm_GetStatusRegister() & HSM_SREG_BOOT_OK) == 0);
    /* even if code ran anyway, boot protected keys are unusable */
    TEST_ASSERT_EQUAL(IMGV_CRYPTO_ERROR, ImageVerify_Application(NULL_PTR));
    TEST_ASSERT_EQUAL(CRYPTO_E_KEY_NOT_AVAILABLE,
                      Csm_MacGenerate(CSM_JOB_SECOC_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, mac, 4, mac, &l));
    /* the halted ECU does not answer diagnostics */
    {
        uint8 req[2] = {0x3E, 0x00};
        TEST_ASSERT_EQUAL(0, uds(req, 2));
    }
    /* repair (re-flash original BL at the plant) -> boots again */
    Fls_SimCorrupt(BL_START + 0x100, 0x20);
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_Reset());
}

static void test_tampered_boot_manager_halts(void)
{
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(1, 0x1000));
    Fls_SimCorrupt(BM_START + BM_SIZE - 1, 0x80);
    TEST_ASSERT_EQUAL(ECU_STATE_HALTED, Ecu_Reset());
    Fls_SimCorrupt(BM_START + BM_SIZE - 1, 0x80);
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_Reset());
}

static void test_security_access_wrong_key_and_lockout(void)
{
    uint8 req[18];
    uint8 seed1[16];
    uint32 i;
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    req[0] = 0x10; req[1] = 0x02;
    TEST_ASSERT_EQUAL(6, uds(req, 2));

    /* two different seeds (RNG of the HSM) */
    req[0] = 0x27; req[1] = 0x11;
    TEST_ASSERT_EQUAL(18, uds(req, 2));
    memcpy(seed1, &rsp[2], 16);
    TEST_ASSERT_EQUAL(18, uds(req, 2));
    TEST_ASSERT_TRUE(memcmp(seed1, &rsp[2], 16) != 0);

    /* sendKey without matching requestSeed sequence */
    req[0] = 0x27; req[1] = 0x12; memset(&req[2], 0, 16);
    TEST_ASSERT_EQUAL(3, uds(req, 18));
    TEST_ASSERT_EQUAL(UDS_NRC_IK, Tester_Info.lastNrc);    /* seed still pending: wrong key */
    TEST_ASSERT_EQUAL(3, uds(req, 18));
    TEST_ASSERT_EQUAL(UDS_NRC_RSE, Tester_Info.lastNrc);   /* seed consumed */

    for (i = 0; i < 2; i++)
    {
        req[1] = 0x11;
        uds(req, 2);
        req[1] = 0x12;
        uds(req, 18);
    }
    TEST_ASSERT_EQUAL(UDS_NRC_ENOA, Tester_Info.lastNrc);
    req[1] = 0x11;
    uds(req, 2);
    TEST_ASSERT_EQUAL(UDS_NRC_RTDNE, Tester_Info.lastNrc);
    /* even the correct key is refused while locked out */
    TEST_ASSERT_EQUAL(TESTER_SECURITY_FAILED, Tester_Unlock(Backend_DemoKeys.diagKey));
    /* after reset the lockout is released */
    Ecu_Reset();
    req[0] = 0x10; req[1] = 0x02;
    uds(req, 2);
    TEST_ASSERT_EQUAL(TESTER_OK, Tester_Unlock(Backend_DemoKeys.diagKey));
}

static void test_bootloader_protocol_negative_cases(void)
{
    uint8 req[32];
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());

    /* default session: programming services not allowed */
    req[0] = 0x34; req[1] = 0x00; req[2] = 0x44;
    AppHeader_Put32(&req[3], APP_START); AppHeader_Put32(&req[7], 0x100);
    uds(req, 11);
    TEST_ASSERT_EQUAL(UDS_NRC_SNSIAS, Tester_Info.lastNrc);
    req[0] = 0x27; req[1] = 0x11;
    uds(req, 2);
    TEST_ASSERT_EQUAL(UDS_NRC_SNSIAS, Tester_Info.lastNrc);

    /* programming session but locked */
    req[0] = 0x10; req[1] = 0x02;
    uds(req, 2);
    req[0] = 0x31; req[1] = 0x01; req[2] = 0xFF; req[3] = 0x00; req[4] = 0x44;
    AppHeader_Put32(&req[5], APP_START); AppHeader_Put32(&req[9], APP_SIZE);
    uds(req, 13);
    TEST_ASSERT_EQUAL(UDS_NRC_SAD, Tester_Info.lastNrc);

    TEST_ASSERT_EQUAL(TESTER_OK, Tester_Unlock(Backend_DemoKeys.diagKey));
    /* download before erase */
    req[0] = 0x34; req[1] = 0x00; req[2] = 0x44;
    AppHeader_Put32(&req[3], APP_START); AppHeader_Put32(&req[7], 0x100);
    uds(req, 11);
    TEST_ASSERT_EQUAL(UDS_NRC_CNC, Tester_Info.lastNrc);
    /* erase outside of the application area (boot manager!) */
    req[0] = 0x31; req[1] = 0x01; req[2] = 0xFF; req[3] = 0x00; req[4] = 0x44;
    AppHeader_Put32(&req[5], BM_START); AppHeader_Put32(&req[9], FLS_SECTOR_SIZE);
    uds(req, 13);
    TEST_ASSERT_EQUAL(UDS_NRC_ROOR, Tester_Info.lastNrc);
    AppHeader_Put32(&req[5], APP_START); AppHeader_Put32(&req[9], APP_SIZE);
    TEST_ASSERT_EQUAL(5, uds(req, 13));
    /* download into the bootloader area */
    req[0] = 0x34; req[1] = 0x00; req[2] = 0x44;
    AppHeader_Put32(&req[3], BL_START); AppHeader_Put32(&req[7], 0x100);
    uds(req, 11);
    TEST_ASSERT_EQUAL(UDS_NRC_ROOR, Tester_Info.lastNrc);
    /* transfer data without download request */
    req[0] = 0x36; req[1] = 0x01; req[2] = 0xAA;
    uds(req, 3);
    TEST_ASSERT_EQUAL(UDS_NRC_RSE, Tester_Info.lastNrc);
    /* wrong block sequence counter */
    req[0] = 0x34; req[1] = 0x00; req[2] = 0x44;
    AppHeader_Put32(&req[3], APP_START); AppHeader_Put32(&req[7], 0x10);
    TEST_ASSERT_EQUAL(4, uds(req, 11));
    req[0] = 0x36; req[1] = 0x05; req[2] = 0xAA;
    uds(req, 3);
    TEST_ASSERT_EQUAL(UDS_NRC_WBSC, Tester_Info.lastNrc);
    /* transfer exit before all data was received */
    req[0] = 0x37;
    uds(req, 1);
    TEST_ASSERT_EQUAL(UDS_NRC_RSE, Tester_Info.lastNrc);
    /* unsupported service */
    req[0] = 0x2E;
    uds(req, 1);
    TEST_ASSERT_EQUAL(UDS_NRC_SNS, Tester_Info.lastNrc);
    /* session change re-locks security access */
    req[0] = 0x10; req[1] = 0x03;
    uds(req, 2);
    req[0] = 0x10; req[1] = 0x02;
    uds(req, 2);
    req[0] = 0x31; req[1] = 0x01; req[2] = 0xFF; req[3] = 0x01;
    uds(req, 4);
    TEST_ASSERT_EQUAL(UDS_NRC_SAD, Tester_Info.lastNrc);
}

static void test_bootloader_read_dids(void)
{
    uint8 req[3] = {0x22, 0xF1, 0x8C};
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(18, uds(req, 3));
    TEST_ASSERT_EQUAL_MEMORY(TEST_UID, &rsp[3], 15);
    req[1] = 0xFD; req[2] = 0x00;
    TEST_ASSERT_EQUAL(5, uds(req, 3));
    TEST_ASSERT_TRUE((rsp[3] & HSM_SREG_BOOT_OK) != 0);
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, rsp[4]);
    req[1] = 0xF1; req[2] = 0x80;
    TEST_ASSERT_EQUAL(6, uds(req, 3));
    TEST_ASSERT_EQUAL(BL_VERSION_MAJOR, rsp[3]);
}

static void test_get_id_authenticated_by_master_key(void)
{
    uint8 ch[16] = {1,2,3}, out[32], buf[32], mac[16];
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(E_OK, Crypto_Hsm_GetId(ch, out));
    TEST_ASSERT_EQUAL_MEMORY(TEST_UID, out, 15);
    memcpy(buf, ch, 16);
    memcpy(&buf[16], out, 16);  /* UID | SREG */
    Hsm_Cmac(Backend_DemoKeys.masterEcuKey, buf, 32, mac);
    TEST_ASSERT_EQUAL_MEMORY(mac, &out[16], 16);
}

static void test_retry_after_failed_update_without_reset(void)
{
    uint8 req[2] = {0x27, 0x11};
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(4, 0x1000));
    TEST_ASSERT_EQUAL(TESTER_CHECK_FAILED, flash_app(2, 0x1000));  /* roll-back */
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_GetState());
    /* still unlocked: requestSeed answers with the zero seed */
    TEST_ASSERT_EQUAL(18, uds(req, 2));
    TEST_ASSERT_EQUAL(0, rsp[2] | rsp[9] | rsp[17]);
    /* the tester retries immediately with a valid version */
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(5, 0x1000));
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_GetState());
}

int main(void)
{
    printf("Suite: secure boot chain / boot manager / bootloader\n");
    Tester_Info.verbose = FALSE;
    RUN_TEST(test_virgin_device_starts_bootloader);
    RUN_TEST(test_eol_provisioning_enables_secure_boot);
    RUN_TEST(test_flash_and_boot_application);
    RUN_TEST(test_update_via_programming_request);
    RUN_TEST(test_programming_request_flow);
    RUN_TEST(test_rollback_rejected);
    RUN_TEST(test_retry_after_failed_update_without_reset);
    RUN_TEST(test_tampered_application_in_flash);
    RUN_TEST(test_image_signed_with_wrong_key_rejected);
    RUN_TEST(test_interrupted_download_recovers);
    RUN_TEST(test_tampered_bootloader_halts_and_locks_keys);
    RUN_TEST(test_tampered_boot_manager_halts);
    RUN_TEST(test_security_access_wrong_key_and_lockout);
    RUN_TEST(test_bootloader_protocol_negative_cases);
    RUN_TEST(test_bootloader_read_dids);
    RUN_TEST(test_get_id_authenticated_by_master_key);
    return ut_summary("secure_boot_chain");
}

/**
 * @file  test_csm_crypto_stack.c
 * @brief AUTOSAR crypto stack tests (Csm -> CryIf -> Crypto -> HSM):
 *        MAC generate / verify (single call, streaming, truncated, async),
 *        hash, AES ECB/CBC, random, HMAC, SHE key update via CSM key
 *        management, DET error reporting, job queue / cancel.
 */
#include "test_helpers.h"
#include "Csm.h"
#include "Det.h"
#include "Crypto.h"
#include "Crypto_HsmExt.h"
#include "App_Callbacks.h"
#include "hsm_cmac.h"
#include "hsm_sha256.h"
#include "hsm_aes.h"

static const uint8 MSG[64] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10 };

static void setup(void)
{
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
}

static void test_mac_generate_single_call_matches_reference(void)
{
    uint8 mac[16], ref[16];
    uint32 len = 16;
    setup();
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_FLASH_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL,
                                            MSG, 64, mac, &len));
    TEST_ASSERT_EQUAL(16, len);
    Hsm_Cmac(Backend_DemoKeys.flashVerifyKey, MSG, 64, ref);
    TEST_ASSERT_EQUAL_MEMORY(ref, mac, 16);
}

static void test_mac_generate_truncated_output(void)
{
    uint8 mac[16] = {0}, ref[16];
    uint32 len = 4;
    setup();
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_SECOC_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL,
                                            MSG, 20, mac, &len));
    TEST_ASSERT_EQUAL(4, len);
    Hsm_Cmac(Backend_DemoKeys.secocKey, MSG, 20, ref);
    TEST_ASSERT_EQUAL_MEMORY(ref, mac, 4);
    TEST_ASSERT_EQUAL(0, mac[4]);
}

static void test_mac_verify_ok_and_not_ok(void)
{
    uint8 mac[16];
    uint32 len = 16;
    Crypto_VerifyResultType vr = CRYPTO_E_VER_NOT_OK;
    setup();
    Hsm_Cmac(Backend_DemoKeys.flashVerifyKey, MSG, 64, mac);

    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_FLASH_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                                          MSG, 64, mac, 128, &vr));
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_OK, vr);

    mac[0] ^= 0x01;   /* forged MAC */
    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_FLASH_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                                          MSG, 64, mac, 128, &vr));
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_NOT_OK, vr);
    mac[0] ^= 0x01;

    /* modified data */
    {
        uint8 d[64];
        memcpy(d, MSG, 64);
        d[63] ^= 0x80;
        TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_FLASH_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                                              d, 64, mac, 128, &vr));
        TEST_ASSERT_EQUAL(CRYPTO_E_VER_NOT_OK, vr);
    }
    /* wrong key: MAC generated with a different key */
    Hsm_Cmac(Backend_DemoKeys.secocKey, MSG, 64, mac);
    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_FLASH_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                                          MSG, 64, mac, 128, &vr));
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_NOT_OK, vr);
    (void)len;
}

static void test_mac_verify_truncated_bits(void)
{
    uint8 mac[16];
    Crypto_VerifyResultType vr = CRYPTO_E_VER_NOT_OK;
    setup();
    Hsm_Cmac(Backend_DemoKeys.secocKey, MSG, 33, mac);
    mac[5] ^= 0xFF;  /* beyond 40 bits */
    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_SECOC_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                                          MSG, 33, mac, 40, &vr));
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_OK, vr);
    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_SECOC_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                                          MSG, 33, mac, 48, &vr));
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_NOT_OK, vr);
    /* 28 bits: half-byte granularity */
    Hsm_Cmac(Backend_DemoKeys.secocKey, MSG, 33, mac);
    mac[3] ^= 0x0F;  /* low nibble of byte 3 is bits 28..31 -> not compared */
    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_SECOC_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                                          MSG, 33, mac, 28, &vr));
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_OK, vr);
}

static void test_mac_streaming_start_update_finish(void)
{
    uint8 mac[16], ref[16];
    uint32 len = 16;
    Crypto_VerifyResultType vr = CRYPTO_E_VER_NOT_OK;
    setup();
    Hsm_Cmac(Backend_DemoKeys.flashVerifyKey, MSG, 64, ref);

    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_FLASH_MAC_GENERATE, CRYPTO_OPERATIONMODE_START, NULL_PTR, 0, NULL_PTR, NULL_PTR));
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_FLASH_MAC_GENERATE, CRYPTO_OPERATIONMODE_UPDATE, MSG, 7, NULL_PTR, NULL_PTR));
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_FLASH_MAC_GENERATE, CRYPTO_OPERATIONMODE_UPDATE, &MSG[7], 40, NULL_PTR, NULL_PTR));
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_FLASH_MAC_GENERATE, CRYPTO_OPERATIONMODE_UPDATE, &MSG[47], 17, NULL_PTR, NULL_PTR));
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_FLASH_MAC_GENERATE, CRYPTO_OPERATIONMODE_FINISH, NULL_PTR, 0, mac, &len));
    TEST_ASSERT_EQUAL_MEMORY(ref, mac, 16);

    /* streaming verify */
    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_FLASH_MAC_VERIFY, CRYPTO_OPERATIONMODE_STREAMSTART, MSG, 30, NULL_PTR, 0, NULL_PTR));
    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_FLASH_MAC_VERIFY,
                                          CRYPTO_OPERATIONMODE_UPDATE | CRYPTO_OPERATIONMODE_FINISH,
                                          &MSG[30], 34, ref, 128, &vr));
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_OK, vr);

    /* UPDATE without START is rejected */
    TEST_ASSERT_EQUAL(E_NOT_OK, Csm_MacGenerate(CSM_JOB_FLASH_MAC_GENERATE, CRYPTO_OPERATIONMODE_UPDATE, MSG, 4, NULL_PTR, NULL_PTR));
}

static void test_mac_async_with_callback(void)
{
    uint8 mac[16], ref[16];
    uint32 len = 16;
    Crypto_VerifyResultType vr = CRYPTO_E_VER_NOT_OK;
    uint32 before;
    setup();
    TEST_ASSERT_EQUAL(ECU_STATE_BOOTLOADER, Ecu_GetState());  /* no app yet */
    App_CsmNotification.count = 0;
    before = App_CsmNotification.count;

    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_MAC_GENERATE_ASYNC, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 64, mac, &len));
    /* job is queued: same job cannot be started twice */
    TEST_ASSERT_EQUAL(CRYPTO_E_BUSY, Csm_MacGenerate(CSM_JOB_MAC_GENERATE_ASYNC, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 64, mac, &len));
    TEST_ASSERT_EQUAL(before, App_CsmNotification.count);
    Csm_MainFunction();      /* CSM queue -> CryIf -> Crypto queue */
    TEST_ASSERT_EQUAL(before, App_CsmNotification.count);
    Crypto_MainFunction();   /* Crypto driver executes, notifies     */
    TEST_ASSERT_EQUAL(before + 1, App_CsmNotification.count);
    TEST_ASSERT_EQUAL(CSM_JOB_MAC_GENERATE_ASYNC, App_CsmNotification.lastJobId);
    TEST_ASSERT_EQUAL(E_OK, App_CsmNotification.lastResult);
    Hsm_Cmac(Backend_DemoKeys.flashVerifyKey, MSG, 64, ref);
    TEST_ASSERT_EQUAL_MEMORY(ref, mac, 16);

    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_MAC_VERIFY_ASYNC, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 64, ref, 128, &vr));
    Ecu_MainFunction();
    TEST_ASSERT_EQUAL(CSM_JOB_MAC_VERIFY_ASYNC, App_CsmNotification.lastJobId);
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_OK, vr);
}

static void test_async_priority_and_cancel(void)
{
    uint8 m1[16], d1[32];
    uint32 l1 = 16, l2 = 32;
    Crypto_VerifyResultType vr = CRYPTO_E_VER_NOT_OK;
    uint8 ref[16];
    setup();
    App_CsmNotification.count = 0;
    Hsm_Cmac(Backend_DemoKeys.flashVerifyKey, MSG, 16, ref);
    /* three async jobs, higher priority (verify: 15) first */
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_MAC_GENERATE_ASYNC, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 16, m1, &l1));
    TEST_ASSERT_EQUAL(E_OK, Csm_Hash(CSM_JOB_HASH_SHA256_ASYNC, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 3, d1, &l2));
    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_MAC_VERIFY_ASYNC, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 16, ref, 128, &vr));
    /* cancel the hash job before it is processed */
    TEST_ASSERT_EQUAL(E_OK, Csm_CancelJob(CSM_JOB_HASH_SHA256_ASYNC, CRYPTO_OPERATIONMODE_SINGLECALL));
    TEST_ASSERT_EQUAL(1, App_CsmNotification.count);
    TEST_ASSERT_EQUAL(CRYPTO_E_JOB_CANCELED, App_CsmNotification.lastResult);
    Csm_MainFunction();
    Crypto_MainFunction();     /* one job per driver object per cycle */
    TEST_ASSERT_EQUAL(2, App_CsmNotification.count);
    TEST_ASSERT_EQUAL(CSM_JOB_MAC_VERIFY_ASYNC, App_CsmNotification.lastJobId);
    Crypto_MainFunction();
    TEST_ASSERT_EQUAL(3, App_CsmNotification.count);
    TEST_ASSERT_EQUAL(CSM_JOB_MAC_GENERATE_ASYNC, App_CsmNotification.lastJobId);
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_OK, vr);
}

static void test_hash_sha256(void)
{
    uint8 d[32], e[32];
    uint32 l = 32;
    setup();
    TEST_ASSERT_EQUAL(E_OK, Csm_Hash(CSM_JOB_HASH_SHA256, CRYPTO_OPERATIONMODE_SINGLECALL, (const uint8 *)"abc", 3, d, &l));
    ut_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", e);
    TEST_ASSERT_EQUAL_MEMORY(e, d, 32);
    /* streaming */
    l = 32;
    TEST_ASSERT_EQUAL(E_OK, Csm_Hash(CSM_JOB_HASH_SHA256, CRYPTO_OPERATIONMODE_START, NULL_PTR, 0, NULL_PTR, NULL_PTR));
    TEST_ASSERT_EQUAL(E_OK, Csm_Hash(CSM_JOB_HASH_SHA256, CRYPTO_OPERATIONMODE_UPDATE, (const uint8 *)"a", 1, NULL_PTR, NULL_PTR));
    TEST_ASSERT_EQUAL(E_OK, Csm_Hash(CSM_JOB_HASH_SHA256, CRYPTO_OPERATIONMODE_UPDATE, (const uint8 *)"bc", 2, NULL_PTR, NULL_PTR));
    TEST_ASSERT_EQUAL(E_OK, Csm_Hash(CSM_JOB_HASH_SHA256, CRYPTO_OPERATIONMODE_FINISH, NULL_PTR, 0, d, &l));
    TEST_ASSERT_EQUAL_MEMORY(e, d, 32);
    /* truncated result */
    l = 8;
    TEST_ASSERT_EQUAL(E_OK, Csm_Hash(CSM_JOB_HASH_SHA256, CRYPTO_OPERATIONMODE_SINGLECALL, (const uint8 *)"abc", 3, d, &l));
    TEST_ASSERT_EQUAL(8, l);
}

static void test_aes_cbc_ecb_roundtrip(void)
{
    uint8 iv[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8 ct[64], pt[64], ref[64];
    uint32 lc = 64, lp = 64;
    setup();
    TEST_ASSERT_EQUAL(E_OK, Csm_KeyElementSet(CSM_KEY_APP_CIPHER, CRYPTO_KE_CIPHER_IV, iv, 16));
    TEST_ASSERT_EQUAL(E_OK, Csm_Encrypt(CSM_JOB_ENCRYPT_AES_CBC, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 64, ct, &lc));
    Hsm_AesCbcEncrypt(Backend_DemoKeys.cipherKey, iv, MSG, 64, ref);
    TEST_ASSERT_EQUAL_MEMORY(ref, ct, 64);
    TEST_ASSERT_EQUAL(E_OK, Csm_Decrypt(CSM_JOB_DECRYPT_AES_CBC, CRYPTO_OPERATIONMODE_SINGLECALL, ct, 64, pt, &lp));
    TEST_ASSERT_EQUAL_MEMORY(MSG, pt, 64);

    lc = 32; lp = 32;
    TEST_ASSERT_EQUAL(E_OK, Csm_Encrypt(CSM_JOB_ENCRYPT_AES_ECB, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 32, ct, &lc));
    TEST_ASSERT_EQUAL(E_OK, Csm_Decrypt(CSM_JOB_DECRYPT_AES_ECB, CRYPTO_OPERATIONMODE_SINGLECALL, ct, 32, pt, &lp));
    TEST_ASSERT_EQUAL_MEMORY(MSG, pt, 32);

    /* small output buffer */
    lc = 16;
    TEST_ASSERT_EQUAL(CRYPTO_E_SMALL_BUFFER, Csm_Encrypt(CSM_JOB_ENCRYPT_AES_ECB, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 32, ct, &lc));
}

static void test_random_generate(void)
{
    uint8 a[32], b[32];
    uint32 la = 32, lb = 32;
    setup();
    TEST_ASSERT_EQUAL(E_OK, Csm_RandomGenerate(CSM_JOB_RANDOM_GENERATE, a, &la));
    TEST_ASSERT_EQUAL(E_OK, Csm_RandomGenerate(CSM_JOB_RANDOM_GENERATE, b, &lb));
    TEST_ASSERT_TRUE(memcmp(a, b, 32) != 0);
    TEST_ASSERT_EQUAL(E_OK, Csm_RandomSeed(CSM_KEY_FLASH_VERIFY, (const uint8 *)"more entropy", 12));
}

static void test_hmac_sha256_via_csm(void)
{
    uint8 mac[32], ref[32];
    uint32 l = 32;
    Crypto_VerifyResultType vr = CRYPTO_E_VER_NOT_OK;
    setup();
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_HMAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 64, mac, &l));
    Hsm_HmacSha256(Backend_DemoKeys.hmacKey, 32, MSG, 64, ref);
    TEST_ASSERT_EQUAL_MEMORY(ref, mac, 32);
    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_HMAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 64, mac, 256, &vr));
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_OK, vr);
    mac[31] ^= 1;
    TEST_ASSERT_EQUAL(E_OK, Csm_MacVerify(CSM_JOB_HMAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 64, mac, 256, &vr));
    TEST_ASSERT_EQUAL(CRYPTO_E_VER_NOT_OK, vr);
    /* HMAC key cannot be injected in plain after the lifecycle was locked */
    TEST_ASSERT_EQUAL(E_OK, Csm_KeyElementSet(CSM_KEY_HMAC, CRYPTO_KE_MAC_KEY, ref, 32));
    TEST_ASSERT_EQUAL(CRYPTO_E_KEY_WRITE_FAIL, Csm_KeySetValid(CSM_KEY_HMAC));
}

static void test_key_update_via_csm_she_protocol(void)
{
    uint8 newKey[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00};
    uint8 mac[16], ref[16], ctr[4];
    uint32 l = 16, lc = 4;
    setup();
    /* in-field key update of the SecOC key (counter 2) */
    TEST_ASSERT_EQUAL(EOL_OK, Eol_InstallSheKey(CSM_KEY_SECOC, HSM_KEY_3, HSM_KEY_MASTER_ECU_KEY,
                                                Backend_DemoKeys.masterEcuKey, newKey, 2,
                                                HSM_FLAG_KEY_USAGE | HSM_FLAG_BOOT_PROTECTION));
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_SECOC_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 16, mac, &l));
    Hsm_Cmac(newKey, MSG, 16, ref);
    TEST_ASSERT_EQUAL_MEMORY(ref, mac, 16);
    TEST_ASSERT_EQUAL(E_OK, Csm_KeyElementGet(CSM_KEY_SECOC, CRYPTO_KE_CUSTOM_SHE_COUNTER, ctr, &lc));
    TEST_ASSERT_EQUAL(2, ctr[3]);
    /* replay of an old key update (counter 2 again) is rejected by the HSM */
    TEST_ASSERT_EQUAL(EOL_KEY_UPDATE_FAILED, Eol_InstallSheKey(CSM_KEY_SECOC, HSM_KEY_3, HSM_KEY_MASTER_ECU_KEY,
                                                               Backend_DemoKeys.masterEcuKey, newKey, 2, HSM_FLAG_KEY_USAGE));
    /* M1 addressing another slot than the CSM key is rejected */
    TEST_ASSERT_EQUAL(EOL_KEY_UPDATE_FAILED, Eol_InstallSheKey(CSM_KEY_SECOC, HSM_KEY_5, HSM_KEY_MASTER_ECU_KEY,
                                                               Backend_DemoKeys.masterEcuKey, newKey, 3, HSM_FLAG_KEY_USAGE));
    /* secret key material can never be read */
    l = 16;
    TEST_ASSERT_EQUAL(CRYPTO_E_KEY_READ_FAIL, Csm_KeyElementGet(CSM_KEY_SECOC, CRYPTO_KE_MAC_KEY, mac, &l));
    TEST_ASSERT_EQUAL(E_OK, Csm_KeySetValid(CSM_KEY_SECOC));
    TEST_ASSERT_EQUAL(CRYPTO_E_KEY_EMPTY, Csm_KeySetValid(CSM_KEY_RAM));
}

static void test_ram_key_plain_load(void)
{
    uint8 k[16] = {0x42}, mac[16], ref[16];
    uint32 l = 16;
    setup();
    TEST_ASSERT_EQUAL(CRYPTO_E_KEY_EMPTY, Csm_MacGenerate(CSM_JOB_RAMKEY_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 16, mac, &l));
    TEST_ASSERT_EQUAL(E_OK, Csm_KeyElementSet(CSM_KEY_RAM, CRYPTO_KE_MAC_KEY, k, 16));
    TEST_ASSERT_EQUAL(E_OK, Csm_KeySetValid(CSM_KEY_RAM));
    l = 16;
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_RAMKEY_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 16, mac, &l));
    Hsm_Cmac(k, MSG, 16, ref);
    TEST_ASSERT_EQUAL_MEMORY(ref, mac, 16);
}

static void test_det_and_parameter_checks(void)
{
    uint8 mac[16];
    uint32 l = 16;
    Crypto_VerifyResultType vr;
    uint32 n0;
    setup();
    n0 = Det_GetErrorCount();
    /* invalid job id */
    TEST_ASSERT_EQUAL(E_NOT_OK, Csm_MacGenerate(CSM_NUM_JOBS, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 4, mac, &l));
    TEST_ASSERT_EQUAL(n0 + 1, Det_GetErrorCount());
    TEST_ASSERT_EQUAL(CSM_MODULE_ID, Det_GetLastError()->moduleId);
    TEST_ASSERT_EQUAL(CSM_E_PARAM_HANDLE, Det_GetLastError()->errorId);
    /* wrong service type: MacGenerate on a verify job */
    TEST_ASSERT_EQUAL(E_NOT_OK, Csm_MacGenerate(CSM_JOB_FLASH_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 4, mac, &l));
    TEST_ASSERT_EQUAL(CSM_E_SERVICE_TYPE, Det_GetLastError()->errorId);
    /* null pointer */
    TEST_ASSERT_EQUAL(E_NOT_OK, Csm_MacVerify(CSM_JOB_FLASH_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 4, NULL_PTR, 128, &vr));
    TEST_ASSERT_EQUAL(CSM_E_PARAM_POINTER, Det_GetLastError()->errorId);
    /* crypto driver: invalid object */
    TEST_ASSERT_EQUAL(E_NOT_OK, Crypto_ProcessJob(99, NULL_PTR));
    TEST_ASSERT_EQUAL(CRYPTO_MODULE_ID, Det_GetLastError()->moduleId);
    TEST_ASSERT_EQUAL(CRYPTO_E_PARAM_HANDLE, Det_GetLastError()->errorId);
    /* version info */
    {
        Std_VersionInfoType vi;
        Csm_GetVersionInfo(&vi);
        TEST_ASSERT_EQUAL(CSM_MODULE_ID, vi.moduleID);
        Crypto_GetVersionInfo(&vi);
        TEST_ASSERT_EQUAL(CRYPTO_MODULE_ID, vi.moduleID);
    }
}

static void test_boot_protected_key_locked_after_boot_failure(void)
{
    uint8 mac[16];
    uint32 l = 16;
    setup();
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_FLASH_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 16, mac, &l));
    /* host reports a boot failure (SHE CMD_BOOT_FAILURE) */
    TEST_ASSERT_EQUAL(E_OK, Crypto_Hsm_BootFailure());
    l = 16;
    TEST_ASSERT_EQUAL(CRYPTO_E_KEY_NOT_AVAILABLE,
                      Csm_MacGenerate(CSM_JOB_FLASH_MAC_GENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 16, mac, &l));
    /* the diagnostic key (KEY_2) is not boot protected: still usable */
    l = 16;
    TEST_ASSERT_EQUAL(E_OK, Csm_MacGenerate(CSM_JOB_SECACCESS_MAC_GEN, CRYPTO_OPERATIONMODE_SINGLECALL, MSG, 16, mac, &l));
}

int main(void)
{
    printf("Suite: AUTOSAR crypto stack (Csm/CryIf/Crypto -> HSM)\n");
    RUN_TEST(test_mac_generate_single_call_matches_reference);
    RUN_TEST(test_mac_generate_truncated_output);
    RUN_TEST(test_mac_verify_ok_and_not_ok);
    RUN_TEST(test_mac_verify_truncated_bits);
    RUN_TEST(test_mac_streaming_start_update_finish);
    RUN_TEST(test_mac_async_with_callback);
    RUN_TEST(test_async_priority_and_cancel);
    RUN_TEST(test_hash_sha256);
    RUN_TEST(test_aes_cbc_ecb_roundtrip);
    RUN_TEST(test_random_generate);
    RUN_TEST(test_hmac_sha256_via_csm);
    RUN_TEST(test_key_update_via_csm_she_protocol);
    RUN_TEST(test_ram_key_plain_load);
    RUN_TEST(test_det_and_parameter_checks);
    RUN_TEST(test_boot_protected_key_locked_after_boot_failure);
    return ut_summary("csm_crypto_stack");
}

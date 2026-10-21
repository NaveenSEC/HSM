/**
 * @file    ecu_sim_main.c
 * @brief   End-to-end demonstration of the HSM based secure ECU life cycle:
 *          factory -> EOL key provisioning -> secure boot -> UDS flashing ->
 *          application with SecOC -> attack scenarios.
 */
#include <stdio.h>
#include <string.h>
#include "Ecu.h"
#include "Eol.h"
#include "Backend.h"
#include "Tester.h"
#include "BootManager.h"
#include "ImageVerify.h"
#include "MemMap_Layout.h"
#include "AppHeader.h"
#include "Fls.h"
#include "Hsm.h"
#include "App.h"
#include "Csm.h"
#include "Crypto_HsmExt.h"

static const uint8 UID[15] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE };
static uint8  image[APP_HEADER_SIZE + 0x10000];
static uint32 imageLen;
static int    failures;

static void step(const char *title)
{
    printf("\n=== %s ===\n", title);
}

static void expect(int cond, const char *what)
{
    printf("  [%s] %s\n", cond ? " OK " : "FAIL", what);
    if (!cond)
    {
        failures++;
    }
}

static void showBoot(void)
{
    const BootManager_DecisionType *d = BootManager_GetDecision();
    printf("  HSM SREG=0x%02X secure-boot ERC=0x%02X | Boot Manager -> %s (%s, app=%s)\n",
           d->hsmSreg, d->hsmBootResult, BootManager_TargetString(d->target),
           BootManager_ReasonString(d->reason), ImageVerify_ResultString(d->appResult));
}

static Tester_ResultType flash(uint32 version, uint32 size, const uint8 *signKey)
{
    static uint8 body[0x10000];
    Tester_ResultType r;
    Backend_BuildDemoAppBody(version, body, size);
    (void)Backend_BuildAppImage(version, body, size, signKey, image, sizeof(image), &imageLen);
    r = Tester_FlashApplication(image, imageLen, Backend_DemoKeys.diagKey);
    printf("  Tester: flash SW v%u (%u bytes) -> %s (%u UDS requests)\n", (unsigned)version,
           (unsigned)imageLen, Tester_ResultString(r), (unsigned)Tester_Info.requests);
    return r;
}

int main(int argc, char **argv)
{
    uint8 pdu[16];
    uint32 len;
    uint16 speed = 0;

    Tester_Info.verbose = ((argc > 1) && (strcmp(argv[1], "-v") == 0)) ? TRUE : FALSE;
    printf("AUTOSAR HSM / Secure Boot ECU simulation\n");

    step("1. Factory: virgin device (flash erased, HSM NVM empty)");
    Ecu_FactoryInit(UID);
    Ecu_Reset();
    showBoot();
    expect(Ecu_GetState() == ECU_STATE_BOOTLOADER, "no application -> bootloader");

    step("2. End-of-line: SHE key provisioning (M1..M5) via CSM, BOOT_MAC learning, lock lifecycle");
    expect(Eol_ProvisionEcu(UID, &Backend_DemoKeys) == EOL_OK, "MASTER_ECU_KEY, BOOT_MAC_KEY, KEY_1..4, HMAC key installed");
    showBoot();
    expect(BootManager_GetDecision()->secureBootEnforced == TRUE, "HSM secure boot verified Boot Manager + Bootloader");

    step("3. Re-programming via UDS (10 02, 27 11/12, 31 FF00, 34/36/37, 31 FF01, 11 01)");
    expect(flash(1, 0x6000, Backend_DemoKeys.flashVerifyKey) == TESTER_OK, "application v1 programmed");
    showBoot();
    expect(Ecu_GetState() == ECU_STATE_APPLICATION, "application started");

    step("4. Application: SecOC secured communication (MAC generate / verify by HSM)");
    len = sizeof(pdu);
    App_SendVehicleSpeed(88, pdu, &len);
    printf("  TX secured PDU: %02X %02X | FV %02X | MAC %02X %02X %02X\n", pdu[0], pdu[1], pdu[2], pdu[3], pdu[4], pdu[5]);
    expect(App_ReceiveVehicleSpeed(pdu, len, &speed) == SECOC_VERIFICATIONSUCCESS && speed == 88, "RX: MAC verified, speed = 88");
    expect(App_ReceiveVehicleSpeed(pdu, len, &speed) != SECOC_VERIFICATIONSUCCESS, "RX replay of same PDU rejected");
    len = sizeof(pdu);
    App_SendVehicleSpeed(30, pdu, &len);
    pdu[1] ^= 0x7F;
    expect(App_ReceiveVehicleSpeed(pdu, len, &speed) == SECOC_VERIFICATIONFAILURE, "RX manipulated speed rejected");

    step("5. Software update to v2 (programming request from application)");
    expect(flash(2, 0x8000, Backend_DemoKeys.flashVerifyKey) == TESTER_OK, "application v2 programmed");
    showBoot();

    step("6. Attack: downgrade to v1 (correctly signed, but old)");
    expect(flash(1, 0x6000, Backend_DemoKeys.flashVerifyKey) == TESTER_CHECK_FAILED, "roll-back rejected by HSM monotonic counter");
    expect(flash(3, 0x6000, Backend_DemoKeys.flashVerifyKey) == TESTER_OK, "recovery with v3");

    step("7. Attack: image signed with a forged key");
    {
        static const uint8 forged[16] = { 0xBA, 0xD0, 0xBA, 0xD0 };
        expect(flash(4, 0x6000, forged) == TESTER_CHECK_FAILED, "forged image rejected (header CMAC invalid)");
        expect(flash(4, 0x6000, Backend_DemoKeys.flashVerifyKey) == TESTER_OK, "genuine v4 accepted");
    }

    step("8. Attack: application code patched in flash");
    Fls_SimCorrupt(APP_BODY_START + 0x100, 0x01);
    Ecu_Reset();
    showBoot();
    expect(Ecu_GetState() == ECU_STATE_BOOTLOADER, "patched application not started");
    Fls_SimCorrupt(APP_BODY_START + 0x100, 0x01);
    Ecu_Reset();

    step("9. Attack: bootloader patched (e.g. to skip the signature check)");
    Fls_SimCorrupt(BL_START + 0x2000, 0x10);
    Ecu_Reset();
    showBoot();
    expect(Ecu_GetState() == ECU_STATE_HALTED, "HSM secure boot fails -> ECU halted, boot protected keys locked");
    Fls_SimCorrupt(BL_START + 0x2000, 0x10);
    Ecu_Reset();
    showBoot();
    expect(Ecu_GetState() == ECU_STATE_APPLICATION, "original bootloader restored -> application");

    printf("\n%s (%d failure%s)\n", failures == 0 ? "DEMO PASSED" : "DEMO FAILED", failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}

/**
 * @file    BootManager.c
 */
#include "BootManager.h"
#include "BootData.h"
#include "Crypto_HsmExt.h"

static BootManager_DecisionType BootManager_Decision;

static BootManager_TargetType decide(BootManager_TargetType t, BootManager_ReasonType r)
{
    BootManager_Decision.target = t;
    BootManager_Decision.reason = r;
    return t;
}

BootManager_TargetType BootManager_Run(void)
{
    uint8 sreg = 0u;
    Hsm_ErrorType bootErc = HSM_ERC_GENERAL_ERROR;

    BootManager_Decision.appResult = IMGV_NO_IMAGE;
    BootManager_Decision.secureBootEnforced = FALSE;

    /* 1. Result of the HSM secure boot of Boot Manager + Bootloader */
    if (Crypto_Hsm_GetStatus(&sreg, &bootErc) != E_OK)
    {
        return decide(BM_TARGET_HALT, BM_REASON_HSM_ERROR);
    }
    BootManager_Decision.hsmSreg = sreg;
    BootManager_Decision.hsmBootResult = bootErc;

    if ((sreg & HSM_SREG_BOOT_FINISHED) == 0u)
    {
        return decide(BM_TARGET_HALT, BM_REASON_HSM_ERROR);
    }
    if (bootErc == HSM_ERC_VERIFY_FAILED)
    {
        /* Boot code was modified: the HSM already locked all boot protected
         * keys. Fail safe: do not run any further code. */
        (void)Crypto_Hsm_BootFailure();
        return decide(BM_TARGET_HALT, BM_REASON_SECURE_BOOT_FAILED);
    }
    BootManager_Decision.secureBootEnforced = ((sreg & HSM_SREG_BOOT_OK) != 0u) ? TRUE : FALSE;

    /* 2. Application requested a re-programming session */
    if (BootData_IsProgrammingRequested() == TRUE)
    {
        return decide(BM_TARGET_BOOTLOADER, BM_REASON_PROG_REQUEST);
    }

    /* 3. Verify the application (authenticity, integrity, roll-back) */
    BootManager_Decision.appResult = ImageVerify_Application(NULL_PTR);
    if (BootManager_Decision.appResult == IMGV_OK)
    {
        return decide(BM_TARGET_APPLICATION, BM_REASON_APP_VALID);
    }
    return decide(BM_TARGET_BOOTLOADER, BM_REASON_APP_INVALID);
}

const BootManager_DecisionType *BootManager_GetDecision(void)
{
    return &BootManager_Decision;
}

const char *BootManager_TargetString(BootManager_TargetType t)
{
    switch (t)
    {
        case BM_TARGET_APPLICATION: return "APPLICATION";
        case BM_TARGET_BOOTLOADER:  return "BOOTLOADER";
        case BM_TARGET_HALT:        return "HALT";
        default:                    return "?";
    }
}

const char *BootManager_ReasonString(BootManager_ReasonType r)
{
    switch (r)
    {
        case BM_REASON_APP_VALID:          return "application valid";
        case BM_REASON_PROG_REQUEST:       return "programming request";
        case BM_REASON_APP_INVALID:        return "application invalid";
        case BM_REASON_SECURE_BOOT_FAILED: return "HSM secure boot failed";
        case BM_REASON_HSM_ERROR:          return "HSM error";
        default:                           return "?";
    }
}

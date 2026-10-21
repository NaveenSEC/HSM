/**
 * @file    BootManager.h
 * @brief   Boot Manager: first stage executed by the host core after the HSM
 *          released it from reset. Decides which software block to start.
 *
 * Chain of trust:
 *   HSM ROM/firmware --(SHE secure boot: CMAC over BM+BL)--> Boot Manager
 *   Boot Manager     --(CSM: CMAC header + SHA-256 body + roll-back)--> Application
 */
#ifndef BOOTMANAGER_H
#define BOOTMANAGER_H

#include "Std_Types.h"
#include "ImageVerify.h"

typedef enum
{
    BM_TARGET_APPLICATION = 0,
    BM_TARGET_BOOTLOADER,
    BM_TARGET_HALT
} BootManager_TargetType;

typedef enum
{
    BM_REASON_APP_VALID = 0,
    BM_REASON_PROG_REQUEST,
    BM_REASON_APP_INVALID,
    BM_REASON_SECURE_BOOT_FAILED,
    BM_REASON_HSM_ERROR
} BootManager_ReasonType;

typedef struct
{
    BootManager_TargetType target;
    BootManager_ReasonType reason;
    ImageVerify_ResultType appResult;
    uint8                  hsmSreg;
    uint8                  hsmBootResult;
    boolean                secureBootEnforced;
} BootManager_DecisionType;

BootManager_TargetType          BootManager_Run(void);
const BootManager_DecisionType *BootManager_GetDecision(void);
const char                     *BootManager_TargetString(BootManager_TargetType t);
const char                     *BootManager_ReasonString(BootManager_ReasonType r);

#endif

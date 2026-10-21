/**
 * @file    Ecu.h
 * @brief   ECU simulation: power-on / reset sequence (EcuM like), routing of
 *          diagnostic requests to the active software block.
 *
 *   Reset -> HSM (secure boot) -> BSW init (Det, Crypto, CryIf, Csm)
 *         -> Boot Manager -> { Application | Bootloader | HALT }
 */
#ifndef ECU_H
#define ECU_H

#include "Std_Types.h"
#include "BootManager.h"

typedef enum
{
    ECU_STATE_OFF = 0,
    ECU_STATE_APPLICATION,
    ECU_STATE_BOOTLOADER,
    ECU_STATE_HALTED
} Ecu_StateType;

/** Virgin device: erase flash + HSM NVM, program Boot Manager / Bootloader */
void          Ecu_FactoryInit(const uint8 uid[15]);
Ecu_StateType Ecu_Reset(void);
Ecu_StateType Ecu_GetState(void);
uint32        Ecu_GetResetCount(void);
const char   *Ecu_StateString(Ecu_StateType s);

/** Tester -> ECU. Performs the ECU reset if the request triggered one. */
uint32        Ecu_Diag(const uint8 *req, uint32 reqLen, uint8 *resp, uint32 respMax);
void          Ecu_MainFunction(void);

/** Deterministic content of the boot code (BM + BL) for the simulation */
void          Ecu_BuildBootCode(uint8 *bm, uint32 bmLen, uint8 *bl, uint32 blLen);

/** Simulation of the TRNG: deterministic for reproducible tests */
void          Ecu_SimSetEntropySeed(uint32 seed);

#endif

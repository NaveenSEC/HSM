/**
 * @file    Eol.h
 * @brief   End-of-line (EOL) provisioning of the HSM keys through the CSM.
 */
#ifndef EOL_H
#define EOL_H

#include "Std_Types.h"
#include "Backend.h"

typedef enum
{
    EOL_OK = 0,
    EOL_KEY_UPDATE_FAILED,
    EOL_PROOF_MISMATCH,
    EOL_BOOT_MAC_NOT_LEARNED,
    EOL_LIFECYCLE_FAILED
} Eol_ResultType;

/** Install one SHE key with the M1..M5 protocol via CSM, check M4/M5 proof */
Eol_ResultType Eol_InstallSheKey(uint32 csmKeyId, uint8 sheKeyId, uint8 authId,
                                 const uint8 authKey[16], const uint8 newKey[16],
                                 uint32 counter, uint8 flags);

/**
 * @brief Complete EOL sequence:
 *  1. MASTER_ECU_KEY, BOOT_MAC_KEY, application keys (SHE protocol)
 *  2. HMAC key in extended slot (plain, only allowed before IN_FIELD)
 *  3. reset -> HSM learns BOOT_MAC
 *  4. lock lifecycle to IN_FIELD, reset
 */
Eol_ResultType Eol_ProvisionEcu(const uint8 uid[15], const Backend_KeySetType *keys);

#endif

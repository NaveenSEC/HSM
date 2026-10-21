/**
 * @file    Hsm_She.h
 * @brief   SHE key derivation and memory update protocol (M1..M5).
 *
 * Implements chapters "Key derivation function" (Miyaguchi-Preneel based
 * KDF) and "Memory update protocol" of the SHE Functional Specification.
 * The generator functions are also used by the back-end/provisioning tool.
 */
#ifndef HSM_SHE_H
#define HSM_SHE_H

#include "Hsm_Types.h"

#define HSM_SHE_M1_SIZE  16u
#define HSM_SHE_M2_SIZE  32u
#define HSM_SHE_M3_SIZE  16u
#define HSM_SHE_M4_SIZE  32u
#define HSM_SHE_M5_SIZE  16u

extern const uint8 Hsm_She_KeyUpdateEncC[16];
extern const uint8 Hsm_She_KeyUpdateMacC[16];
extern const uint8 Hsm_She_DebugKeyC[16];
extern const uint8 Hsm_She_PrngKeyC[16];
extern const uint8 Hsm_She_PrngSeedKeyC[16];
extern const uint8 Hsm_She_DefaultKey[16];

typedef struct
{
    uint8 m1[HSM_SHE_M1_SIZE];
    uint8 m2[HSM_SHE_M2_SIZE];
    uint8 m3[HSM_SHE_M3_SIZE];
    uint8 m4[HSM_SHE_M4_SIZE];
    uint8 m5[HSM_SHE_M5_SIZE];
} Hsm_SheUpdateMsgType;

/** Miyaguchi-Preneel compression over a multiple of 16 bytes */
void Hsm_SheMpCompress(const uint8 *in, uint32 len, uint8 out[16]);

/** KDF(K, C) = MP(K || C) */
void Hsm_SheKdf(const uint8 key[16], const uint8 c[16], uint8 out[16]);

/**
 * @brief Back-end side: build M1..M5 for a key update.
 * @param uid     15 byte UID of the target ECU (all zero = wildcard)
 * @param keyId   target slot id
 * @param authId  slot id of the authorizing key
 * @param authKey value of the authorizing key
 * @param newKey  new key value
 * @param counter new 28-bit counter value
 * @param flags   HSM_FLAG_xxx protection flags
 */
void Hsm_SheGenerateUpdate(const uint8 uid[15], Hsm_KeyIdType keyId, Hsm_KeyIdType authId,
                           const uint8 authKey[16], const uint8 newKey[16],
                           uint32 counter, uint8 flags, Hsm_SheUpdateMsgType *msg);

/** HSM side: process CMD_LOAD_KEY. Outputs M4 / M5 on success. */
Hsm_ErrorType Hsm_SheLoadKey(const uint8 m1[16], const uint8 m2[32], const uint8 m3[16],
                             uint8 m4[32], uint8 m5[16]);

/** HSM side: CMD_EXPORT_RAM_KEY. Produces M1..M5 protected by SECRET_KEY. */
Hsm_ErrorType Hsm_SheExportRamKey(Hsm_SheUpdateMsgType *msg);

#endif /* HSM_SHE_H */

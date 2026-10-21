/**
 * @file    Hsm_KeyStore.h
 * @brief   Protected key storage of the HSM (SHE NVM key slots + extensions).
 *
 * The key store lives in HSM-private data flash which the host CPU cannot
 * access. In the simulation it is a static structure that survives a
 * simulated reset (Hsm_Reset) but not a "factory erase".
 */
#ifndef HSM_KEYSTORE_H
#define HSM_KEYSTORE_H

#include "Hsm_Types.h"

typedef struct
{
    uint8   key[HSM_MAX_KEY_LEN];
    uint8   keyLen;
    uint8   flags;          /* HSM_FLAG_xxx                       */
    uint32  counter;        /* 28 bit SHE counter                  */
    boolean valid;          /* slot contains a key                 */
    boolean plain;          /* RAM_KEY loaded in plain -> exportable */
} Hsm_KeySlotType;

typedef struct
{
    uint32            magic;
    uint8             uid[15];
    Hsm_KeySlotType   slot[HSM_NUM_KEY_SLOTS];
    uint32            monotonicCounter[HSM_NUM_COUNTERS];
    Hsm_LifecycleType lifecycle;
    uint8             prngSeed[16];   /* SHE PRNG_SEED, persisted        */
} Hsm_NvmType;

void            Hsm_KeyStoreFactoryInit(const uint8 uid[15]);
void            Hsm_KeyStoreResetVolatile(void);

Hsm_NvmType    *Hsm_KeyStoreNvm(void);
Hsm_KeySlotType*Hsm_KeyStoreSlot(Hsm_KeyIdType id);
boolean         Hsm_KeyStoreIsValidId(Hsm_KeyIdType id);
boolean         Hsm_KeyStoreIsSheSlot(Hsm_KeyIdType id);

/**
 * @brief Check whether a key may be used for a given operation.
 * @param forMac TRUE: CMAC operation, FALSE: cipher operation
 */
Hsm_ErrorType   Hsm_KeyStoreCheckUsage(Hsm_KeyIdType id, boolean forMac,
                                       boolean bootOk, boolean debuggerAttached);

void            Hsm_KeyStoreWrite(Hsm_KeyIdType id, const uint8 *key, uint8 len,
                                  uint8 flags, uint32 counter, boolean plain);
void            Hsm_KeyStoreErase(Hsm_KeyIdType id);

#endif /* HSM_KEYSTORE_H */

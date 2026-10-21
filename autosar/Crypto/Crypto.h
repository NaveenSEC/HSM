/**
 * @file    Crypto.h
 * @brief   Crypto Driver for the HSM (AUTOSAR_SWS_CryptoDriver).
 *
 * The driver forwards jobs to the HSM via the mailbox interface. Each Crypto
 * Driver Object owns a job queue (asynchronous jobs) and an HSM streaming
 * context (START/UPDATE/FINISH).
 */
#ifndef CRYPTO_H
#define CRYPTO_H

#include "Crypto_GeneralTypes.h"
#include "Crypto_Cfg.h"
#include "Hsm_Types.h"

#define CRYPTO_MODULE_ID      114u
#define CRYPTO_VENDOR_ID      0xFFFFu
#define CRYPTO_SW_MAJOR_VERSION 1u
#define CRYPTO_SW_MINOR_VERSION 0u
#define CRYPTO_SW_PATCH_VERSION 0u

/* API service ids */
#define CRYPTO_SID_INIT              0x00u
#define CRYPTO_SID_GETVERSIONINFO    0x01u
#define CRYPTO_SID_PROCESSJOB        0x03u
#define CRYPTO_SID_KEYELEMENTSET     0x04u
#define CRYPTO_SID_KEYSETVALID       0x05u
#define CRYPTO_SID_KEYELEMENTGET     0x06u
#define CRYPTO_SID_MAINFUNCTION      0x0Cu
#define CRYPTO_SID_RANDOMSEED        0x0Du
#define CRYPTO_SID_CANCELJOB         0x0Eu

/* DET error codes */
#define CRYPTO_E_UNINIT              0x00u
#define CRYPTO_E_INIT_FAILED         0x01u
#define CRYPTO_E_PARAM_POINTER       0x02u
#define CRYPTO_E_PARAM_HANDLE        0x04u
#define CRYPTO_E_PARAM_VALUE         0x05u

typedef struct
{
    Hsm_KeyIdType hsmKeyId;
} Crypto_KeyConfigType;

extern const Crypto_KeyConfigType Crypto_KeyConfig[CRYPTO_NUM_KEYS];

void           Crypto_Init(const void *configPtr);
void           Crypto_GetVersionInfo(Std_VersionInfoType *versioninfo);
Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType *job);
Std_ReturnType Crypto_CancelJob(uint32 objectId, Crypto_JobType *job);
Std_ReturnType Crypto_KeyElementSet(uint32 cryptoKeyId, uint32 keyElementId,
                                    const uint8 *keyPtr, uint32 keyLength);
Std_ReturnType Crypto_KeySetValid(uint32 cryptoKeyId);
Std_ReturnType Crypto_KeyElementGet(uint32 cryptoKeyId, uint32 keyElementId,
                                    uint8 *resultPtr, uint32 *resultLengthPtr);
Std_ReturnType Crypto_RandomSeed(uint32 cryptoKeyId, const uint8 *seedPtr, uint32 seedLength);
void           Crypto_MainFunction(void);

#endif /* CRYPTO_H */

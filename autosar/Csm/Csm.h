/**
 * @file    Csm.h
 * @brief   Crypto Service Manager (AUTOSAR_SWS_CryptoServiceManager, R4.4 API).
 */
#ifndef CSM_H
#define CSM_H

#include "Crypto_GeneralTypes.h"
#include "Csm_Cfg.h"

#define CSM_MODULE_ID              110u
#define CSM_INSTANCE_ID            0u
#define CSM_VENDOR_ID              0xFFFFu
#define CSM_SW_MAJOR_VERSION       1u
#define CSM_SW_MINOR_VERSION       0u
#define CSM_SW_PATCH_VERSION       0u

/* API ids */
#define CSM_SID_INIT               0x00u
#define CSM_SID_GETVERSIONINFO     0x3Bu
#define CSM_SID_HASH               0x5Du
#define CSM_SID_ENCRYPT            0x5Eu
#define CSM_SID_DECRYPT            0x5Fu
#define CSM_SID_MACGENERATE        0x60u
#define CSM_SID_MACVERIFY          0x61u
#define CSM_SID_KEYSETVALID        0x67u
#define CSM_SID_KEYELEMENTGET      0x68u
#define CSM_SID_CANCELJOB          0x6Fu
#define CSM_SID_CBKNOTIFICATION    0x70u
#define CSM_SID_MAINFUNCTION       0x71u
#define CSM_SID_RANDOMGENERATE     0x72u
#define CSM_SID_KEYELEMENTSET      0x78u
#define CSM_SID_RANDOMSEED         0x69u

/* DET errors */
#define CSM_E_PARAM_POINTER        0x01u
#define CSM_E_SMALL_BUFFER         0x03u
#define CSM_E_PARAM_HANDLE         0x04u
#define CSM_E_UNINIT               0x05u
#define CSM_E_INIT_FAILED          0x07u
#define CSM_E_PROCESSING_MODE      0x08u
#define CSM_E_SERVICE_TYPE         0x09u

typedef void (*Csm_CallbackType)(uint32 jobId, Std_ReturnType result);

typedef struct
{
    uint32                          csmKeyId;
    uint32                          queueRef;      /* CryIf channel          */
    const Crypto_PrimitiveInfoType *primitive;
    Crypto_ProcessingType           processing;
    uint32                          priority;
    Csm_CallbackType                callback;      /* async notification     */
} Csm_JobConfigType;

extern const Csm_JobConfigType Csm_JobConfig[CSM_NUM_JOBS];

void           Csm_Init(const void *configPtr);
void           Csm_GetVersionInfo(Std_VersionInfoType *versioninfo);
void           Csm_MainFunction(void);

Std_ReturnType Csm_Hash(uint32 jobId, Crypto_OperationModeType mode,
                        const uint8 *dataPtr, uint32 dataLength,
                        uint8 *resultPtr, uint32 *resultLengthPtr);
Std_ReturnType Csm_MacGenerate(uint32 jobId, Crypto_OperationModeType mode,
                               const uint8 *dataPtr, uint32 dataLength,
                               uint8 *macPtr, uint32 *macLengthPtr);
Std_ReturnType Csm_MacVerify(uint32 jobId, Crypto_OperationModeType mode,
                             const uint8 *dataPtr, uint32 dataLength,
                             const uint8 *macPtr, uint32 macLength,
                             Crypto_VerifyResultType *verifyPtr);
Std_ReturnType Csm_Encrypt(uint32 jobId, Crypto_OperationModeType mode,
                           const uint8 *dataPtr, uint32 dataLength,
                           uint8 *resultPtr, uint32 *resultLengthPtr);
Std_ReturnType Csm_Decrypt(uint32 jobId, Crypto_OperationModeType mode,
                           const uint8 *dataPtr, uint32 dataLength,
                           uint8 *resultPtr, uint32 *resultLengthPtr);
Std_ReturnType Csm_RandomGenerate(uint32 jobId, uint8 *resultPtr, uint32 *resultLengthPtr);

Std_ReturnType Csm_KeyElementSet(uint32 keyId, uint32 keyElementId,
                                 const uint8 *keyPtr, uint32 keyLength);
Std_ReturnType Csm_KeySetValid(uint32 keyId);
Std_ReturnType Csm_KeyElementGet(uint32 keyId, uint32 keyElementId,
                                 uint8 *keyPtr, uint32 *keyLengthPtr);
Std_ReturnType Csm_RandomSeed(uint32 keyId, const uint8 *seedPtr, uint32 seedLength);
Std_ReturnType Csm_CancelJob(uint32 jobId, Crypto_OperationModeType mode);

#endif

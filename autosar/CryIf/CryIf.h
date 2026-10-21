/**
 * @file    CryIf.h
 * @brief   Crypto Interface (AUTOSAR_SWS_CryptoInterface).
 */
#ifndef CRYIF_H
#define CRYIF_H

#include "Crypto_GeneralTypes.h"
#include "CryIf_Cfg.h"

#define CRYIF_MODULE_ID           112u
#define CRYIF_INSTANCE_ID         0u

#define CRYIF_SID_INIT            0x00u
#define CRYIF_SID_PROCESSJOB      0x03u
#define CRYIF_SID_CANCELJOB       0x0Eu
#define CRYIF_SID_KEYELEMENTSET   0x04u
#define CRYIF_SID_KEYSETVALID     0x05u
#define CRYIF_SID_KEYELEMENTGET   0x06u
#define CRYIF_SID_RANDOMSEED      0x07u
#define CRYIF_SID_CBKNOTIFICATION 0x0Du

#define CRYIF_E_UNINIT            0x00u
#define CRYIF_E_INIT_FAILED       0x01u
#define CRYIF_E_PARAM_POINTER     0x02u
#define CRYIF_E_PARAM_HANDLE      0x03u
#define CRYIF_E_PARAM_VALUE       0x04u

typedef struct
{
    uint32 driverObjectId;
} CryIf_ChannelConfigType;

typedef struct
{
    uint32 cryptoKeyId;
} CryIf_KeyConfigType;

extern const CryIf_ChannelConfigType CryIf_ChannelConfig[CRYIF_NUM_CHANNELS];
extern const CryIf_KeyConfigType     CryIf_KeyConfig[CRYIF_NUM_KEYS];

void           CryIf_Init(const void *configPtr);
Std_ReturnType CryIf_ProcessJob(uint32 channelId, Crypto_JobType *job);
Std_ReturnType CryIf_CancelJob(uint32 channelId, Crypto_JobType *job);
Std_ReturnType CryIf_KeyElementSet(uint32 cryIfKeyId, uint32 keyElementId,
                                   const uint8 *keyPtr, uint32 keyLength);
Std_ReturnType CryIf_KeySetValid(uint32 cryIfKeyId);
Std_ReturnType CryIf_KeyElementGet(uint32 cryIfKeyId, uint32 keyElementId,
                                   uint8 *resultPtr, uint32 *resultLengthPtr);
Std_ReturnType CryIf_RandomSeed(uint32 cryIfKeyId, const uint8 *seedPtr, uint32 seedLength);

#endif

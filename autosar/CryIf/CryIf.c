/**
 * @file    CryIf.c
 * @brief   Crypto Interface: routes CSM jobs/keys to the crypto driver.
 */
#include "CryIf.h"
#include "CryIf_Cbk.h"
#include "Crypto.h"
#include "Csm_Cbk.h"
#include "Det.h"

#if (CRYIF_DEV_ERROR_DETECT == STD_ON)
#define CRYIF_DET(api, err) (void)Det_ReportError(CRYIF_MODULE_ID, CRYIF_INSTANCE_ID, (api), (err))
#else
#define CRYIF_DET(api, err)
#endif

static boolean CryIf_Initialized = FALSE;

void CryIf_Init(const void *configPtr)
{
    (void)configPtr;
    CryIf_Initialized = TRUE;
}

Std_ReturnType CryIf_ProcessJob(uint32 channelId, Crypto_JobType *job)
{
    if (CryIf_Initialized == FALSE)
    {
        CRYIF_DET(CRYIF_SID_PROCESSJOB, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }
    if (channelId >= CRYIF_NUM_CHANNELS)
    {
        CRYIF_DET(CRYIF_SID_PROCESSJOB, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if ((job == NULL_PTR) || (job->jobPrimitiveInfo == NULL_PTR))
    {
        CRYIF_DET(CRYIF_SID_PROCESSJOB, CRYIF_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    /* translate CryIf key id to crypto key id */
    if (job->jobPrimitiveInfo->cryIfKeyId >= CRYIF_NUM_KEYS)
    {
        CRYIF_DET(CRYIF_SID_PROCESSJOB, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    job->cryptoKeyId = CryIf_KeyConfig[job->jobPrimitiveInfo->cryIfKeyId].cryptoKeyId;
    return Crypto_ProcessJob(CryIf_ChannelConfig[channelId].driverObjectId, job);
}

Std_ReturnType CryIf_CancelJob(uint32 channelId, Crypto_JobType *job)
{
    if (CryIf_Initialized == FALSE)
    {
        CRYIF_DET(CRYIF_SID_CANCELJOB, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }
    if (channelId >= CRYIF_NUM_CHANNELS)
    {
        CRYIF_DET(CRYIF_SID_CANCELJOB, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    return Crypto_CancelJob(CryIf_ChannelConfig[channelId].driverObjectId, job);
}

static Std_ReturnType checkKey(uint8 api, uint32 cryIfKeyId)
{
    if (CryIf_Initialized == FALSE)
    {
        CRYIF_DET(api, CRYIF_E_UNINIT);
        return E_NOT_OK;
    }
    if (cryIfKeyId >= CRYIF_NUM_KEYS)
    {
        CRYIF_DET(api, CRYIF_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    return E_OK;
}

Std_ReturnType CryIf_KeyElementSet(uint32 cryIfKeyId, uint32 keyElementId,
                                   const uint8 *keyPtr, uint32 keyLength)
{
    if (checkKey(CRYIF_SID_KEYELEMENTSET, cryIfKeyId) != E_OK)
    {
        return E_NOT_OK;
    }
    return Crypto_KeyElementSet(CryIf_KeyConfig[cryIfKeyId].cryptoKeyId, keyElementId, keyPtr, keyLength);
}

Std_ReturnType CryIf_KeySetValid(uint32 cryIfKeyId)
{
    if (checkKey(CRYIF_SID_KEYSETVALID, cryIfKeyId) != E_OK)
    {
        return E_NOT_OK;
    }
    return Crypto_KeySetValid(CryIf_KeyConfig[cryIfKeyId].cryptoKeyId);
}

Std_ReturnType CryIf_KeyElementGet(uint32 cryIfKeyId, uint32 keyElementId,
                                   uint8 *resultPtr, uint32 *resultLengthPtr)
{
    if (checkKey(CRYIF_SID_KEYELEMENTGET, cryIfKeyId) != E_OK)
    {
        return E_NOT_OK;
    }
    return Crypto_KeyElementGet(CryIf_KeyConfig[cryIfKeyId].cryptoKeyId, keyElementId,
                                resultPtr, resultLengthPtr);
}

Std_ReturnType CryIf_RandomSeed(uint32 cryIfKeyId, const uint8 *seedPtr, uint32 seedLength)
{
    if (checkKey(CRYIF_SID_RANDOMSEED, cryIfKeyId) != E_OK)
    {
        return E_NOT_OK;
    }
    return Crypto_RandomSeed(CryIf_KeyConfig[cryIfKeyId].cryptoKeyId, seedPtr, seedLength);
}

void CryIf_CallbackNotification(Crypto_JobType *job, Std_ReturnType result)
{
    if (CryIf_Initialized == FALSE)
    {
        CRYIF_DET(CRYIF_SID_CBKNOTIFICATION, CRYIF_E_UNINIT);
        return;
    }
    if (job == NULL_PTR)
    {
        CRYIF_DET(CRYIF_SID_CBKNOTIFICATION, CRYIF_E_PARAM_POINTER);
        return;
    }
    Csm_CallbackNotification(job, result);
}

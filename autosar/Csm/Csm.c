/**
 * @file    Csm.c
 * @brief   Crypto Service Manager implementation.
 */
#include "Csm.h"
#include "Csm_Cbk.h"
#include "CryIf.h"
#include "Det.h"

#if (CSM_DEV_ERROR_DETECT == STD_ON)
#define CSM_DET(api, err) (void)Det_ReportError(CSM_MODULE_ID, CSM_INSTANCE_ID, (api), (err))
#else
#define CSM_DET(api, err)
#endif

static boolean                      Csm_Initialized = FALSE;
static Crypto_JobType               Csm_Jobs[CSM_NUM_JOBS];
static Crypto_JobPrimitiveInfoType  Csm_JobPrimInfo[CSM_NUM_JOBS];
static Crypto_JobInfoType           Csm_JobInfo[CSM_NUM_JOBS];
static uint32                       Csm_Queue[CSM_QUEUE_SIZE];
static uint8                        Csm_QueueCount;
static boolean                      Csm_JobQueued[CSM_NUM_JOBS];

/* ------------------------------------------------------------------------ */
static void clearIo(Crypto_JobPrimitiveInputOutputType *io)
{
    io->inputPtr = NULL_PTR;
    io->inputLength = 0u;
    io->secondaryInputPtr = NULL_PTR;
    io->secondaryInputLength = 0u;
    io->tertiaryInputPtr = NULL_PTR;
    io->tertiaryInputLength = 0u;
    io->outputPtr = NULL_PTR;
    io->outputLengthPtr = NULL_PTR;
    io->secondaryOutputPtr = NULL_PTR;
    io->secondaryOutputLengthPtr = NULL_PTR;
    io->verifyPtr = NULL_PTR;
    io->mode = 0u;
}

static Std_ReturnType checkJob(uint8 api, uint32 jobId, Crypto_ServiceInfoType service)
{
    if (Csm_Initialized == FALSE)
    {
        CSM_DET(api, CSM_E_UNINIT);
        return E_NOT_OK;
    }
    if (jobId >= CSM_NUM_JOBS)
    {
        CSM_DET(api, CSM_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if (Csm_JobConfig[jobId].primitive->service != service)
    {
        CSM_DET(api, CSM_E_SERVICE_TYPE);
        return E_NOT_OK;
    }
    if (Csm_JobQueued[jobId] == TRUE)
    {
        return CRYPTO_E_BUSY;
    }
    return E_OK;
}

static Std_ReturnType enqueue(uint32 jobId)
{
    uint32 prio = Csm_JobConfig[jobId].priority;
    uint8 pos;

    if (Csm_QueueCount >= CSM_QUEUE_SIZE)
    {
        return CRYPTO_E_QUEUE_FULL;
    }
    pos = Csm_QueueCount;
    while ((pos > 0u) && (Csm_JobConfig[Csm_Queue[pos - 1u]].priority < prio))
    {
        Csm_Queue[pos] = Csm_Queue[pos - 1u];
        pos--;
    }
    Csm_Queue[pos] = jobId;
    Csm_QueueCount++;
    Csm_JobQueued[jobId] = TRUE;
    return E_OK;
}

static Std_ReturnType dispatch(uint32 jobId)
{
    const Csm_JobConfigType *cfg = &Csm_JobConfig[jobId];

    if (cfg->processing == CRYPTO_PROCESSING_ASYNC)
    {
        /* asynchronous jobs are queued and dispatched in
         * Csm_MainFunction; the result is reported by callback */
        return enqueue(jobId);
    }
    return CryIf_ProcessJob(cfg->queueRef, &Csm_Jobs[jobId]);
}

/* ------------------------------------------------------------------------ */
void Csm_Init(const void *configPtr)
{
    uint32 i;
    (void)configPtr;
    for (i = 0u; i < CSM_NUM_JOBS; i++)
    {
        Csm_JobInfo[i].jobId = i;
        Csm_JobInfo[i].jobPriority = Csm_JobConfig[i].priority;
        Csm_JobPrimInfo[i].callbackId = i;
        Csm_JobPrimInfo[i].primitiveInfo = Csm_JobConfig[i].primitive;
        Csm_JobPrimInfo[i].cryIfKeyId = Csm_JobConfig[i].csmKeyId;
        Csm_JobPrimInfo[i].processingType = Csm_JobConfig[i].processing;
        Csm_JobPrimInfo[i].callbackUpdateNotification = FALSE;
        Csm_Jobs[i].jobId = i;
        Csm_Jobs[i].jobState = CRYPTO_JOBSTATE_IDLE;
        Csm_Jobs[i].jobPrimitiveInfo = &Csm_JobPrimInfo[i];
        Csm_Jobs[i].jobInfo = &Csm_JobInfo[i];
        Csm_Jobs[i].cryptoKeyId = 0u;
        clearIo(&Csm_Jobs[i].jobPrimitiveInputOutput);
        Csm_JobQueued[i] = FALSE;
    }
    Csm_QueueCount = 0u;
    Csm_Initialized = TRUE;
}

void Csm_GetVersionInfo(Std_VersionInfoType *versioninfo)
{
    if (versioninfo == NULL_PTR)
    {
        CSM_DET(CSM_SID_GETVERSIONINFO, CSM_E_PARAM_POINTER);
        return;
    }
    versioninfo->vendorID = CSM_VENDOR_ID;
    versioninfo->moduleID = CSM_MODULE_ID;
    versioninfo->sw_major_version = CSM_SW_MAJOR_VERSION;
    versioninfo->sw_minor_version = CSM_SW_MINOR_VERSION;
    versioninfo->sw_patch_version = CSM_SW_PATCH_VERSION;
}

void Csm_MainFunction(void)
{
    uint8 i = 0u;
    if (Csm_Initialized == FALSE)
    {
        return;
    }
    /* Pass queued jobs to the CryIf in priority order */
    while (i < Csm_QueueCount)
    {
        uint32 jobId = Csm_Queue[i];
        Std_ReturnType r = CryIf_ProcessJob(Csm_JobConfig[jobId].queueRef, &Csm_Jobs[jobId]);
        if (r == CRYPTO_E_BUSY)
        {
            i++;   /* keep in queue, retry next cycle */
        }
        else
        {
            uint8 j;
            for (j = i; (j + 1u) < Csm_QueueCount; j++)
            {
                Csm_Queue[j] = Csm_Queue[j + 1u];
            }
            Csm_QueueCount--;
            if (r != E_OK)
            {
                /* rejected by the lower layer: report immediately */
                Csm_JobQueued[jobId] = FALSE;
                if (Csm_JobConfig[jobId].callback != NULL_PTR)
                {
                    Csm_JobConfig[jobId].callback(jobId, r);
                }
            }
        }
    }
}

void Csm_CallbackNotification(Crypto_JobType *job, Std_ReturnType result)
{
    uint32 jobId;
    if (Csm_Initialized == FALSE)
    {
        CSM_DET(CSM_SID_CBKNOTIFICATION, CSM_E_UNINIT);
        return;
    }
    if ((job == NULL_PTR) || (job->jobId >= CSM_NUM_JOBS))
    {
        CSM_DET(CSM_SID_CBKNOTIFICATION, CSM_E_PARAM_POINTER);
        return;
    }
    jobId = job->jobId;
    Csm_JobQueued[jobId] = FALSE;
    if (Csm_JobConfig[jobId].callback != NULL_PTR)
    {
        Csm_JobConfig[jobId].callback(jobId, result);
    }
}

/* ------------------------------------------------------------------------ */
Std_ReturnType Csm_Hash(uint32 jobId, Crypto_OperationModeType mode,
                        const uint8 *dataPtr, uint32 dataLength,
                        uint8 *resultPtr, uint32 *resultLengthPtr)
{
    Std_ReturnType r = checkJob(CSM_SID_HASH, jobId, CRYPTO_HASH);
    Crypto_JobPrimitiveInputOutputType *io;
    if (r != E_OK)
    {
        return r;
    }
    if ((((mode & CRYPTO_OPERATIONMODE_UPDATE) != 0u) && (dataPtr == NULL_PTR) && (dataLength != 0u)) ||
        (((mode & CRYPTO_OPERATIONMODE_FINISH) != 0u) && ((resultPtr == NULL_PTR) || (resultLengthPtr == NULL_PTR))))
    {
        CSM_DET(CSM_SID_HASH, CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    io = &Csm_Jobs[jobId].jobPrimitiveInputOutput;
    clearIo(io);
    io->mode = mode;
    io->inputPtr = dataPtr;
    io->inputLength = dataLength;
    io->outputPtr = resultPtr;
    io->outputLengthPtr = resultLengthPtr;
    return dispatch(jobId);
}

Std_ReturnType Csm_MacGenerate(uint32 jobId, Crypto_OperationModeType mode,
                               const uint8 *dataPtr, uint32 dataLength,
                               uint8 *macPtr, uint32 *macLengthPtr)
{
    Std_ReturnType r = checkJob(CSM_SID_MACGENERATE, jobId, CRYPTO_MACGENERATE);
    Crypto_JobPrimitiveInputOutputType *io;
    if (r != E_OK)
    {
        return r;
    }
    if ((((mode & CRYPTO_OPERATIONMODE_UPDATE) != 0u) && (dataPtr == NULL_PTR) && (dataLength != 0u)) ||
        (((mode & CRYPTO_OPERATIONMODE_FINISH) != 0u) && ((macPtr == NULL_PTR) || (macLengthPtr == NULL_PTR))))
    {
        CSM_DET(CSM_SID_MACGENERATE, CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    io = &Csm_Jobs[jobId].jobPrimitiveInputOutput;
    clearIo(io);
    io->mode = mode;
    io->inputPtr = dataPtr;
    io->inputLength = dataLength;
    io->outputPtr = macPtr;
    io->outputLengthPtr = macLengthPtr;
    return dispatch(jobId);
}

Std_ReturnType Csm_MacVerify(uint32 jobId, Crypto_OperationModeType mode,
                             const uint8 *dataPtr, uint32 dataLength,
                             const uint8 *macPtr, uint32 macLength,
                             Crypto_VerifyResultType *verifyPtr)
{
    Std_ReturnType r = checkJob(CSM_SID_MACVERIFY, jobId, CRYPTO_MACVERIFY);
    Crypto_JobPrimitiveInputOutputType *io;
    if (r != E_OK)
    {
        return r;
    }
    if ((((mode & CRYPTO_OPERATIONMODE_UPDATE) != 0u) && (dataPtr == NULL_PTR) && (dataLength != 0u)) ||
        (((mode & CRYPTO_OPERATIONMODE_FINISH) != 0u) && ((macPtr == NULL_PTR) || (verifyPtr == NULL_PTR))))
    {
        CSM_DET(CSM_SID_MACVERIFY, CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    io = &Csm_Jobs[jobId].jobPrimitiveInputOutput;
    clearIo(io);
    io->mode = mode;
    io->inputPtr = dataPtr;
    io->inputLength = dataLength;
    io->secondaryInputPtr = macPtr;
    io->secondaryInputLength = macLength;   /* length in bits */
    io->verifyPtr = verifyPtr;
    return dispatch(jobId);
}

static Std_ReturnType cipher(uint8 api, Crypto_ServiceInfoType svc, uint32 jobId,
                             Crypto_OperationModeType mode, const uint8 *dataPtr, uint32 dataLength,
                             uint8 *resultPtr, uint32 *resultLengthPtr)
{
    Std_ReturnType r = checkJob(api, jobId, svc);
    Crypto_JobPrimitiveInputOutputType *io;
    if (r != E_OK)
    {
        return r;
    }
    if ((dataPtr == NULL_PTR) || (resultPtr == NULL_PTR) || (resultLengthPtr == NULL_PTR))
    {
        CSM_DET(api, CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    io = &Csm_Jobs[jobId].jobPrimitiveInputOutput;
    clearIo(io);
    io->mode = mode;
    io->inputPtr = dataPtr;
    io->inputLength = dataLength;
    io->outputPtr = resultPtr;
    io->outputLengthPtr = resultLengthPtr;
    return dispatch(jobId);
}

Std_ReturnType Csm_Encrypt(uint32 jobId, Crypto_OperationModeType mode,
                           const uint8 *dataPtr, uint32 dataLength,
                           uint8 *resultPtr, uint32 *resultLengthPtr)
{
    return cipher(CSM_SID_ENCRYPT, CRYPTO_ENCRYPT, jobId, mode, dataPtr, dataLength, resultPtr, resultLengthPtr);
}

Std_ReturnType Csm_Decrypt(uint32 jobId, Crypto_OperationModeType mode,
                           const uint8 *dataPtr, uint32 dataLength,
                           uint8 *resultPtr, uint32 *resultLengthPtr)
{
    return cipher(CSM_SID_DECRYPT, CRYPTO_DECRYPT, jobId, mode, dataPtr, dataLength, resultPtr, resultLengthPtr);
}

Std_ReturnType Csm_RandomGenerate(uint32 jobId, uint8 *resultPtr, uint32 *resultLengthPtr)
{
    Std_ReturnType r = checkJob(CSM_SID_RANDOMGENERATE, jobId, CRYPTO_RANDOMGENERATE);
    Crypto_JobPrimitiveInputOutputType *io;
    if (r != E_OK)
    {
        return r;
    }
    if ((resultPtr == NULL_PTR) || (resultLengthPtr == NULL_PTR))
    {
        CSM_DET(CSM_SID_RANDOMGENERATE, CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    io = &Csm_Jobs[jobId].jobPrimitiveInputOutput;
    clearIo(io);
    io->mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    io->outputPtr = resultPtr;
    io->outputLengthPtr = resultLengthPtr;
    return dispatch(jobId);
}

/* ------------------------------------------------------------------------ */
static Std_ReturnType checkKey(uint8 api, uint32 keyId)
{
    if (Csm_Initialized == FALSE)
    {
        CSM_DET(api, CSM_E_UNINIT);
        return E_NOT_OK;
    }
    if (keyId >= CSM_NUM_KEYS)
    {
        CSM_DET(api, CSM_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    return E_OK;
}

Std_ReturnType Csm_KeyElementSet(uint32 keyId, uint32 keyElementId,
                                 const uint8 *keyPtr, uint32 keyLength)
{
    if (checkKey(CSM_SID_KEYELEMENTSET, keyId) != E_OK)
    {
        return E_NOT_OK;
    }
    if (keyPtr == NULL_PTR)
    {
        CSM_DET(CSM_SID_KEYELEMENTSET, CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    return CryIf_KeyElementSet(keyId, keyElementId, keyPtr, keyLength);
}

Std_ReturnType Csm_KeySetValid(uint32 keyId)
{
    if (checkKey(CSM_SID_KEYSETVALID, keyId) != E_OK)
    {
        return E_NOT_OK;
    }
    return CryIf_KeySetValid(keyId);
}

Std_ReturnType Csm_KeyElementGet(uint32 keyId, uint32 keyElementId,
                                 uint8 *keyPtr, uint32 *keyLengthPtr)
{
    if (checkKey(CSM_SID_KEYELEMENTGET, keyId) != E_OK)
    {
        return E_NOT_OK;
    }
    if ((keyPtr == NULL_PTR) || (keyLengthPtr == NULL_PTR))
    {
        CSM_DET(CSM_SID_KEYELEMENTGET, CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    return CryIf_KeyElementGet(keyId, keyElementId, keyPtr, keyLengthPtr);
}

Std_ReturnType Csm_RandomSeed(uint32 keyId, const uint8 *seedPtr, uint32 seedLength)
{
    if (checkKey(CSM_SID_RANDOMSEED, keyId) != E_OK)
    {
        return E_NOT_OK;
    }
    if (seedPtr == NULL_PTR)
    {
        CSM_DET(CSM_SID_RANDOMSEED, CSM_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    return CryIf_RandomSeed(keyId, seedPtr, seedLength);
}

Std_ReturnType Csm_CancelJob(uint32 jobId, Crypto_OperationModeType mode)
{
    uint8 i;
    (void)mode;
    if (Csm_Initialized == FALSE)
    {
        CSM_DET(CSM_SID_CANCELJOB, CSM_E_UNINIT);
        return E_NOT_OK;
    }
    if (jobId >= CSM_NUM_JOBS)
    {
        CSM_DET(CSM_SID_CANCELJOB, CSM_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    /* remove from CSM queue */
    for (i = 0u; i < Csm_QueueCount; i++)
    {
        if (Csm_Queue[i] == jobId)
        {
            uint8 j;
            for (j = i; (j + 1u) < Csm_QueueCount; j++)
            {
                Csm_Queue[j] = Csm_Queue[j + 1u];
            }
            Csm_QueueCount--;
            break;
        }
    }
    (void)CryIf_CancelJob(Csm_JobConfig[jobId].queueRef, &Csm_Jobs[jobId]);
    if ((Csm_JobQueued[jobId] == TRUE) && (Csm_JobConfig[jobId].callback != NULL_PTR))
    {
        Csm_JobQueued[jobId] = FALSE;
        Csm_JobConfig[jobId].callback(jobId, CRYPTO_E_JOB_CANCELED);
    }
    Csm_JobQueued[jobId] = FALSE;
    return E_OK;
}

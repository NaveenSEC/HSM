/**
 * @file    Crypto.c
 * @brief   Crypto Driver implementation on top of the HSM mailbox.
 */
#include "Crypto.h"
#include "CryIf_Cbk.h"
#include "Det.h"
#include "Hsm.h"

#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
#define CRYPTO_DET(api, err) (void)Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, (api), (err))
#else
#define CRYPTO_DET(api, err)
#endif

typedef struct
{
    Crypto_JobType *queue[CRYPTO_QUEUE_SIZE];
    uint8           count;
    Crypto_JobType *activeStream;     /* job owning the HSM context */
} Crypto_DriverObjectType;

typedef struct
{
    uint8   m123[64];
    boolean m123Staged;
    uint8   plain[HSM_MAX_KEY_LEN];
    uint8   plainLen;
    boolean plainStaged;
    uint8   m45[48];
    boolean proofValid;
    uint8   iv[16];
    boolean ivSet;
} Crypto_KeyRuntimeType;

static boolean                 Crypto_Initialized = FALSE;
static Crypto_DriverObjectType Crypto_Obj[CRYPTO_NUM_DRIVER_OBJECTS];
static Crypto_KeyRuntimeType   Crypto_Key[CRYPTO_NUM_KEYS];

/* ------------------------------------------------------------------------ */
static void memCopy(uint8 *d, const uint8 *s, uint32 n)
{
    uint32 i;
    for (i = 0u; i < n; i++)
    {
        d[i] = s[i];
    }
}

static void memClear(void *p, uint32 n)
{
    volatile uint8 *v = (volatile uint8 *)p;
    while (n-- > 0u)
    {
        *v++ = 0u;
    }
}

static Std_ReturnType mapErc(Hsm_ErrorType erc)
{
    switch (erc)
    {
        case HSM_ERC_NO_ERROR:            return E_OK;
        case HSM_ERC_BUSY:                return CRYPTO_E_BUSY;
        case HSM_ERC_KEY_EMPTY:           return CRYPTO_E_KEY_EMPTY;
        case HSM_ERC_KEY_NOT_AVAILABLE:   return CRYPTO_E_KEY_NOT_AVAILABLE;
        case HSM_ERC_KEY_INVALID:         return CRYPTO_E_KEY_NOT_VALID;
        case HSM_ERC_SMALL_BUFFER:        return CRYPTO_E_SMALL_BUFFER;
        case HSM_ERC_RNG_SEED:            return CRYPTO_E_ENTROPY_EXHAUSTED;
        case HSM_ERC_KEY_WRITE_PROTECTED:
        case HSM_ERC_KEY_UPDATE_ERROR:
        case HSM_ERC_ACCESS_DENIED:       return CRYPTO_E_KEY_WRITE_FAIL;
        default:                          return E_NOT_OK;
    }
}

/**
 * @brief Post a request to the HSM mailbox and wait for completion.
 *        On the target the wait is a poll on the HSM status / IRQ; in the
 *        simulation the HSM core is stepped while waiting.
 */
static Std_ReturnType hsmCall(Hsm_RequestType *req)
{
    Hsm_IpcHandleType h = Hsm_IpcSubmit(req);
    uint32 loops = 0u;

    if (h == HSM_IPC_INVALID_HANDLE)
    {
        return CRYPTO_E_BUSY;
    }
    while ((Hsm_IpcGetState(h) != HSM_IPC_DONE) && (loops < CRYPTO_HSM_TIMEOUT_LOOPS))
    {
        Hsm_MainFunction();
        loops++;
    }
    if (Hsm_IpcGetState(h) != HSM_IPC_DONE)
    {
        return E_NOT_OK;
    }
    return mapErc(Hsm_IpcRelease(h));
}

static Std_ReturnType hsmKey(uint32 cryptoKeyId, Hsm_KeyIdType *hsmId)
{
    if (cryptoKeyId >= CRYPTO_NUM_KEYS)
    {
        return E_NOT_OK;
    }
    *hsmId = Crypto_KeyConfig[cryptoKeyId].hsmKeyId;
    return E_OK;
}

static void setVerify(Crypto_JobType *job, boolean ok)
{
    if (job->jobPrimitiveInputOutput.verifyPtr != NULL_PTR)
    {
        *job->jobPrimitiveInputOutput.verifyPtr = (ok == TRUE) ? CRYPTO_E_VER_OK : CRYPTO_E_VER_NOT_OK;
    }
}

/* ------------------------------------------------------------------------ */
/* Primitive execution                                                      */
/* ------------------------------------------------------------------------ */
static Std_ReturnType execMac(uint32 objectId, Crypto_JobType *job, Hsm_KeyIdType key)
{
    Crypto_JobPrimitiveInputOutputType *io = &job->jobPrimitiveInputOutput;
    const Crypto_PrimitiveInfoType *pi = job->jobPrimitiveInfo->primitiveInfo;
    boolean verify = (pi->service == CRYPTO_MACVERIFY) ? TRUE : FALSE;
    Hsm_RequestType req;
    Std_ReturnType ret = E_OK;

    memClear(&req, sizeof(req));
    req.keyId = key;
    req.contextId = (uint8)objectId;

    if (pi->algorithm.mode == CRYPTO_ALGOMODE_HMAC)
    {
        /* HMAC: single call only */
        if (io->mode != CRYPTO_OPERATIONMODE_SINGLECALL)
        {
            return E_NOT_OK;
        }
        req.cmd = (verify == TRUE) ? HSM_CMD_HMAC_VERIFY : HSM_CMD_HMAC_GENERATE;
        req.in1 = io->inputPtr;
        req.in1Len = io->inputLength;
        req.in2 = io->secondaryInputPtr;
        req.in2Len = io->secondaryInputLength;
        req.out1 = io->outputPtr;
        req.out1Len = io->outputLengthPtr;
        ret = hsmCall(&req);
        if ((ret == E_OK) && (verify == TRUE))
        {
            setVerify(job, req.verifyResult);
        }
        return ret;
    }

    if (io->mode == CRYPTO_OPERATIONMODE_SINGLECALL)
    {
        req.cmd = (verify == TRUE) ? HSM_CMD_VERIFY_MAC : HSM_CMD_GENERATE_MAC;
        req.in1 = io->inputPtr;
        req.in1Len = io->inputLength;
        req.in2 = io->secondaryInputPtr;
        req.in2Len = io->secondaryInputLength;   /* MAC length in bits */
        req.out1 = io->outputPtr;
        req.out1Len = io->outputLengthPtr;
        ret = hsmCall(&req);
        if ((ret == E_OK) && (verify == TRUE))
        {
            setVerify(job, req.verifyResult);
        }
        return ret;
    }

    if ((io->mode & CRYPTO_OPERATIONMODE_START) != 0u)
    {
        req.cmd = HSM_CMD_MAC_START;
        ret = hsmCall(&req);
    }
    if ((ret == E_OK) && ((io->mode & CRYPTO_OPERATIONMODE_UPDATE) != 0u))
    {
        req.cmd = HSM_CMD_MAC_UPDATE;
        req.in1 = io->inputPtr;
        req.in1Len = io->inputLength;
        ret = hsmCall(&req);
    }
    if ((ret == E_OK) && ((io->mode & CRYPTO_OPERATIONMODE_FINISH) != 0u))
    {
        req.cmd = HSM_CMD_MAC_FINISH;
        req.in1 = NULL_PTR;
        req.in1Len = 0u;
        if (verify == TRUE)
        {
            req.in2 = io->secondaryInputPtr;
            req.in2Len = io->secondaryInputLength;
        }
        else
        {
            req.out1 = io->outputPtr;
            req.out1Len = io->outputLengthPtr;
        }
        ret = hsmCall(&req);
        if ((ret == E_OK) && (verify == TRUE))
        {
            setVerify(job, req.verifyResult);
        }
    }
    return ret;
}

static Std_ReturnType execHash(uint32 objectId, Crypto_JobType *job)
{
    Crypto_JobPrimitiveInputOutputType *io = &job->jobPrimitiveInputOutput;
    Hsm_RequestType req;
    Std_ReturnType ret = E_OK;

    memClear(&req, sizeof(req));
    req.contextId = (uint8)objectId;
    if (io->mode == CRYPTO_OPERATIONMODE_SINGLECALL)
    {
        req.cmd = HSM_CMD_HASH_SHA256;
        req.in1 = io->inputPtr;
        req.in1Len = io->inputLength;
        req.out1 = io->outputPtr;
        req.out1Len = io->outputLengthPtr;
        return hsmCall(&req);
    }
    if ((io->mode & CRYPTO_OPERATIONMODE_START) != 0u)
    {
        req.cmd = HSM_CMD_HASH_START;
        ret = hsmCall(&req);
    }
    if ((ret == E_OK) && ((io->mode & CRYPTO_OPERATIONMODE_UPDATE) != 0u))
    {
        req.cmd = HSM_CMD_HASH_UPDATE;
        req.in1 = io->inputPtr;
        req.in1Len = io->inputLength;
        ret = hsmCall(&req);
    }
    if ((ret == E_OK) && ((io->mode & CRYPTO_OPERATIONMODE_FINISH) != 0u))
    {
        req.cmd = HSM_CMD_HASH_FINISH;
        req.in1 = NULL_PTR;
        req.in1Len = 0u;
        req.out1 = io->outputPtr;
        req.out1Len = io->outputLengthPtr;
        ret = hsmCall(&req);
    }
    return ret;
}

static Std_ReturnType execCipher(Crypto_JobType *job, Hsm_KeyIdType key)
{
    Crypto_JobPrimitiveInputOutputType *io = &job->jobPrimitiveInputOutput;
    const Crypto_PrimitiveInfoType *pi = job->jobPrimitiveInfo->primitiveInfo;
    boolean enc = (pi->service == CRYPTO_ENCRYPT) ? TRUE : FALSE;
    Hsm_RequestType req;

    if (io->mode != CRYPTO_OPERATIONMODE_SINGLECALL)
    {
        return E_NOT_OK;   /* streaming cipher not supported by the HSM */
    }
    memClear(&req, sizeof(req));
    req.keyId = key;
    req.in1 = io->inputPtr;
    req.in1Len = io->inputLength;
    req.out1 = io->outputPtr;
    req.out1Len = io->outputLengthPtr;
    if (pi->algorithm.mode == CRYPTO_ALGOMODE_CBC)
    {
        const Crypto_KeyRuntimeType *k = &Crypto_Key[job->cryptoKeyId];
        if (k->ivSet == FALSE)
        {
            return CRYPTO_E_KEY_NOT_VALID;
        }
        req.in2 = k->iv;
        req.in2Len = 16u;
        req.cmd = (enc == TRUE) ? HSM_CMD_ENC_CBC : HSM_CMD_DEC_CBC;
    }
    else if (pi->algorithm.mode == CRYPTO_ALGOMODE_ECB)
    {
        req.cmd = (enc == TRUE) ? HSM_CMD_ENC_ECB : HSM_CMD_DEC_ECB;
    }
    else
    {
        return E_NOT_OK;
    }
    return hsmCall(&req);
}

static Std_ReturnType execRandom(Crypto_JobType *job)
{
    Crypto_JobPrimitiveInputOutputType *io = &job->jobPrimitiveInputOutput;
    Hsm_RequestType req;
    memClear(&req, sizeof(req));
    req.cmd = HSM_CMD_RND;
    req.out1 = io->outputPtr;
    req.out1Len = io->outputLengthPtr;
    return hsmCall(&req);
}

static Std_ReturnType executeJob(uint32 objectId, Crypto_JobType *job)
{
    const Crypto_PrimitiveInfoType *pi = job->jobPrimitiveInfo->primitiveInfo;
    Crypto_DriverObjectType *obj = &Crypto_Obj[objectId];
    Crypto_OperationModeType mode = job->jobPrimitiveInputOutput.mode;
    Hsm_KeyIdType key = 0u;
    Std_ReturnType ret;

    /* UPDATE/FINISH without START */
    if (((mode & CRYPTO_OPERATIONMODE_START) == 0u) && (job->jobState != CRYPTO_JOBSTATE_ACTIVE))
    {
        return E_NOT_OK;
    }
    /* driver object busy with another streaming job */
    if ((obj->activeStream != NULL_PTR) && (obj->activeStream != job))
    {
        return CRYPTO_E_BUSY;
    }
    if ((pi->service != CRYPTO_HASH) && (pi->service != CRYPTO_RANDOMGENERATE))
    {
        if (hsmKey(job->cryptoKeyId, &key) != E_OK)
        {
            return E_NOT_OK;
        }
    }

    switch (pi->service)
    {
        case CRYPTO_MACGENERATE:
        case CRYPTO_MACVERIFY:       ret = execMac(objectId, job, key); break;
        case CRYPTO_HASH:            ret = execHash(objectId, job); break;
        case CRYPTO_ENCRYPT:
        case CRYPTO_DECRYPT:         ret = execCipher(job, key); break;
        case CRYPTO_RANDOMGENERATE:  ret = execRandom(job); break;
        default:                     ret = E_NOT_OK; break;
    }

    if ((ret == E_OK) && ((mode & CRYPTO_OPERATIONMODE_FINISH) == 0u))
    {
        job->jobState = CRYPTO_JOBSTATE_ACTIVE;
        obj->activeStream = job;
    }
    else
    {
        job->jobState = CRYPTO_JOBSTATE_IDLE;
        if (obj->activeStream == job)
        {
            obj->activeStream = NULL_PTR;
        }
    }
    return ret;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */
void Crypto_Init(const void *configPtr)
{
    (void)configPtr;
    memClear(Crypto_Obj, sizeof(Crypto_Obj));
    memClear(Crypto_Key, sizeof(Crypto_Key));
    Crypto_Initialized = TRUE;
}

void Crypto_GetVersionInfo(Std_VersionInfoType *versioninfo)
{
    if (versioninfo == NULL_PTR)
    {
        CRYPTO_DET(CRYPTO_SID_GETVERSIONINFO, CRYPTO_E_PARAM_POINTER);
        return;
    }
    versioninfo->vendorID = CRYPTO_VENDOR_ID;
    versioninfo->moduleID = CRYPTO_MODULE_ID;
    versioninfo->sw_major_version = CRYPTO_SW_MAJOR_VERSION;
    versioninfo->sw_minor_version = CRYPTO_SW_MINOR_VERSION;
    versioninfo->sw_patch_version = CRYPTO_SW_PATCH_VERSION;
}

Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType *job)
{
    Crypto_DriverObjectType *obj;

    if (Crypto_Initialized == FALSE)
    {
        CRYPTO_DET(CRYPTO_SID_PROCESSJOB, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
    if (objectId >= CRYPTO_NUM_DRIVER_OBJECTS)
    {
        CRYPTO_DET(CRYPTO_SID_PROCESSJOB, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if ((job == NULL_PTR) || (job->jobPrimitiveInfo == NULL_PTR) ||
        (job->jobPrimitiveInfo->primitiveInfo == NULL_PTR))
    {
        CRYPTO_DET(CRYPTO_SID_PROCESSJOB, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    if (job->jobPrimitiveInputOutput.mode == 0u)
    {
        CRYPTO_DET(CRYPTO_SID_PROCESSJOB, CRYPTO_E_PARAM_VALUE);
        return E_NOT_OK;
    }

    if (job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_SYNC)
    {
        return executeJob(objectId, job);
    }

    /* asynchronous: insert into the priority queue of the driver object */
    obj = &Crypto_Obj[objectId];
    if (obj->count >= CRYPTO_QUEUE_SIZE)
    {
        return CRYPTO_E_BUSY;
    }
    {
        uint32 prio = (job->jobInfo != NULL_PTR) ? job->jobInfo->jobPriority : 0u;
        uint8 pos = obj->count;
        while ((pos > 0u) && (((obj->queue[pos - 1u]->jobInfo != NULL_PTR) ?
                               obj->queue[pos - 1u]->jobInfo->jobPriority : 0u) < prio))
        {
            obj->queue[pos] = obj->queue[pos - 1u];
            pos--;
        }
        obj->queue[pos] = job;
        obj->count++;
    }
    return E_OK;
}

Std_ReturnType Crypto_CancelJob(uint32 objectId, Crypto_JobType *job)
{
    Crypto_DriverObjectType *obj;
    uint8 i;

    if (Crypto_Initialized == FALSE)
    {
        CRYPTO_DET(CRYPTO_SID_CANCELJOB, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
    if ((objectId >= CRYPTO_NUM_DRIVER_OBJECTS) || (job == NULL_PTR))
    {
        CRYPTO_DET(CRYPTO_SID_CANCELJOB, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    obj = &Crypto_Obj[objectId];
    for (i = 0u; i < obj->count; i++)
    {
        if (obj->queue[i] == job)
        {
            uint8 j;
            for (j = i; (j + 1u) < obj->count; j++)
            {
                obj->queue[j] = obj->queue[j + 1u];
            }
            obj->count--;
            break;
        }
    }
    if (obj->activeStream == job)
    {
        Hsm_RequestType req;
        memClear(&req, sizeof(req));
        req.cmd = HSM_CMD_CANCEL;
        (void)hsmCall(&req);
        obj->activeStream = NULL_PTR;
    }
    job->jobState = CRYPTO_JOBSTATE_IDLE;
    return E_OK;
}

void Crypto_MainFunction(void)
{
    uint32 o;
    if (Crypto_Initialized == FALSE)
    {
        return;
    }
    for (o = 0u; o < CRYPTO_NUM_DRIVER_OBJECTS; o++)
    {
        Crypto_DriverObjectType *obj = &Crypto_Obj[o];
        if (obj->count > 0u)
        {
            Crypto_JobType *job = obj->queue[0];
            Std_ReturnType ret;
            uint8 j;
            for (j = 0u; (j + 1u) < obj->count; j++)
            {
                obj->queue[j] = obj->queue[j + 1u];
            }
            obj->count--;
            ret = executeJob(o, job);
            CryIf_CallbackNotification(job, ret);
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Key management                                                           */
/* ------------------------------------------------------------------------ */
Std_ReturnType Crypto_KeyElementSet(uint32 cryptoKeyId, uint32 keyElementId,
                                    const uint8 *keyPtr, uint32 keyLength)
{
    Crypto_KeyRuntimeType *k;

    if (Crypto_Initialized == FALSE)
    {
        CRYPTO_DET(CRYPTO_SID_KEYELEMENTSET, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
    if (cryptoKeyId >= CRYPTO_NUM_KEYS)
    {
        CRYPTO_DET(CRYPTO_SID_KEYELEMENTSET, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if ((keyPtr == NULL_PTR) || (keyLength == 0u))
    {
        CRYPTO_DET(CRYPTO_SID_KEYELEMENTSET, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    k = &Crypto_Key[cryptoKeyId];
    switch (keyElementId)
    {
        case CRYPTO_KE_CUSTOM_SHE_M1M2M3:
            if (keyLength != 64u)
            {
                return CRYPTO_E_KEY_SIZE_MISMATCH;
            }
            memCopy(k->m123, keyPtr, 64u);
            k->m123Staged = TRUE;
            return E_OK;

        case CRYPTO_KE_MAC_KEY:   /* == CRYPTO_KE_CIPHER_KEY */
            if (keyLength > HSM_MAX_KEY_LEN)
            {
                return CRYPTO_E_KEY_SIZE_MISMATCH;
            }
            memCopy(k->plain, keyPtr, keyLength);
            k->plainLen = (uint8)keyLength;
            k->plainStaged = TRUE;
            return E_OK;

        case CRYPTO_KE_CIPHER_IV:
            if (keyLength != 16u)
            {
                return CRYPTO_E_KEY_SIZE_MISMATCH;
            }
            memCopy(k->iv, keyPtr, 16u);
            k->ivSet = TRUE;
            return E_OK;

        default:
            return CRYPTO_E_KEY_WRITE_FAIL;
    }
}

Std_ReturnType Crypto_KeySetValid(uint32 cryptoKeyId)
{
    Crypto_KeyRuntimeType *k;
    Hsm_RequestType req;
    Hsm_KeyIdType hsmId;
    Std_ReturnType ret = E_OK;

    if (Crypto_Initialized == FALSE)
    {
        CRYPTO_DET(CRYPTO_SID_KEYSETVALID, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
    if (hsmKey(cryptoKeyId, &hsmId) != E_OK)
    {
        CRYPTO_DET(CRYPTO_SID_KEYSETVALID, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    k = &Crypto_Key[cryptoKeyId];

    if (k->m123Staged == TRUE)
    {
        uint32 l4 = 32u, l5 = 16u;
        memClear(&req, sizeof(req));
        req.cmd = HSM_CMD_LOAD_KEY;
        req.in1 = &k->m123[0];  req.in1Len = 16u;
        req.in2 = &k->m123[16]; req.in2Len = 32u;
        req.in3 = &k->m123[48]; req.in3Len = 16u;
        req.out1 = &k->m45[0];  req.out1Len = &l4;
        req.out2 = &k->m45[32]; req.out2Len = &l5;
        /* the slot addressed by M1 must be the one configured for this key */
        if ((k->m123[15] >> 4) != hsmId)
        {
            ret = CRYPTO_E_KEY_NOT_VALID;
        }
        else
        {
            ret = hsmCall(&req);
        }
        k->proofValid = (ret == E_OK) ? TRUE : FALSE;
        k->m123Staged = FALSE;
        memClear(k->m123, sizeof(k->m123));
    }
    else if (k->plainStaged == TRUE)
    {
        memClear(&req, sizeof(req));
        if (hsmId == HSM_RAM_KEY)
        {
            req.cmd = HSM_CMD_LOAD_PLAIN_KEY;
        }
        else
        {
            req.cmd = HSM_CMD_LOAD_PLAIN_KEY_EXT;
            req.keyId = hsmId;
            req.value = HSM_FLAG_KEY_USAGE;   /* provisioning default: MAC key */
            if (cryptoKeyId == CRYPTO_KEY_APP_CIPHER)
            {
                req.value = 0u;
            }
        }
        req.in1 = k->plain;
        req.in1Len = k->plainLen;
        ret = hsmCall(&req);
        k->plainStaged = FALSE;
        memClear(k->plain, sizeof(k->plain));
    }
    else
    {
        /* nothing staged: key is valid if the HSM slot holds a key */
        memClear(&req, sizeof(req));
        req.cmd = HSM_CMD_KEY_STATUS;
        req.keyId = hsmId;
        ret = hsmCall(&req);
        if ((ret == E_OK) && ((req.value & 0x100u) == 0u))
        {
            ret = CRYPTO_E_KEY_EMPTY;
        }
    }
    return ret;
}

Std_ReturnType Crypto_KeyElementGet(uint32 cryptoKeyId, uint32 keyElementId,
                                    uint8 *resultPtr, uint32 *resultLengthPtr)
{
    Crypto_KeyRuntimeType *k;
    Hsm_KeyIdType hsmId;

    if (Crypto_Initialized == FALSE)
    {
        CRYPTO_DET(CRYPTO_SID_KEYELEMENTGET, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
    if (hsmKey(cryptoKeyId, &hsmId) != E_OK)
    {
        CRYPTO_DET(CRYPTO_SID_KEYELEMENTGET, CRYPTO_E_PARAM_HANDLE);
        return E_NOT_OK;
    }
    if ((resultPtr == NULL_PTR) || (resultLengthPtr == NULL_PTR))
    {
        CRYPTO_DET(CRYPTO_SID_KEYELEMENTGET, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    k = &Crypto_Key[cryptoKeyId];
    switch (keyElementId)
    {
        case CRYPTO_KE_CUSTOM_SHE_M4M5:
            if (k->proofValid == FALSE)
            {
                return CRYPTO_E_KEY_NOT_AVAILABLE;
            }
            if (*resultLengthPtr < 48u)
            {
                return CRYPTO_E_SMALL_BUFFER;
            }
            memCopy(resultPtr, k->m45, 48u);
            *resultLengthPtr = 48u;
            return E_OK;

        case CRYPTO_KE_CUSTOM_SHE_COUNTER:
        {
            Hsm_RequestType req;
            Std_ReturnType ret;
            if (*resultLengthPtr < 4u)
            {
                return CRYPTO_E_SMALL_BUFFER;
            }
            memClear(&req, sizeof(req));
            req.cmd = HSM_CMD_KEY_STATUS;
            req.keyId = hsmId;
            ret = hsmCall(&req);
            if (ret == E_OK)
            {
                uint32 c = req.value >> 12;
                resultPtr[0] = (uint8)(c >> 24);
                resultPtr[1] = (uint8)(c >> 16);
                resultPtr[2] = (uint8)(c >> 8);
                resultPtr[3] = (uint8)c;
                *resultLengthPtr = 4u;
            }
            return ret;
        }

        case CRYPTO_KE_CIPHER_IV:
            if (k->ivSet == FALSE)
            {
                return CRYPTO_E_KEY_NOT_AVAILABLE;
            }
            if (*resultLengthPtr < 16u)
            {
                return CRYPTO_E_SMALL_BUFFER;
            }
            memCopy(resultPtr, k->iv, 16u);
            *resultLengthPtr = 16u;
            return E_OK;

        default:
            /* secret key material never leaves the HSM */
            return CRYPTO_E_KEY_READ_FAIL;
    }
}

Std_ReturnType Crypto_RandomSeed(uint32 cryptoKeyId, const uint8 *seedPtr, uint32 seedLength)
{
    Hsm_RequestType req;
    (void)cryptoKeyId;
    if (Crypto_Initialized == FALSE)
    {
        CRYPTO_DET(CRYPTO_SID_RANDOMSEED, CRYPTO_E_UNINIT);
        return E_NOT_OK;
    }
    if ((seedPtr == NULL_PTR) || (seedLength == 0u))
    {
        CRYPTO_DET(CRYPTO_SID_RANDOMSEED, CRYPTO_E_PARAM_POINTER);
        return E_NOT_OK;
    }
    memClear(&req, sizeof(req));
    req.cmd = HSM_CMD_EXTEND_SEED;
    req.in1 = seedPtr;
    req.in1Len = seedLength;
    return hsmCall(&req);
}

/* ------------------------------------------------------------------------ */
/* Vendor specific extensions                                               */
/* ------------------------------------------------------------------------ */
#include "Crypto_HsmExt.h"

Std_ReturnType Crypto_Hsm_GetStatus(uint8 *sreg, Hsm_ErrorType *bootResult)
{
    Hsm_RequestType req;
    Std_ReturnType ret;
    if (sreg == NULL_PTR)
    {
        return E_NOT_OK;
    }
    memClear(&req, sizeof(req));
    req.cmd = HSM_CMD_GET_STATUS;
    ret = hsmCall(&req);
    *sreg = (uint8)req.value;
    if (bootResult != NULL_PTR)
    {
        *bootResult = (Hsm_ErrorType)(req.value >> 8);
    }
    return ret;
}

Std_ReturnType Crypto_Hsm_BootFailure(void)
{
    Hsm_RequestType req;
    memClear(&req, sizeof(req));
    req.cmd = HSM_CMD_BOOT_FAILURE;
    return hsmCall(&req);
}

Std_ReturnType Crypto_Hsm_BootOk(void)
{
    Hsm_RequestType req;
    memClear(&req, sizeof(req));
    req.cmd = HSM_CMD_BOOT_OK;
    return hsmCall(&req);
}

Std_ReturnType Crypto_Hsm_CounterRead(uint8 counterId, uint32 *value)
{
    Hsm_RequestType req;
    Std_ReturnType ret;
    if (value == NULL_PTR)
    {
        return E_NOT_OK;
    }
    memClear(&req, sizeof(req));
    req.cmd = HSM_CMD_COUNTER_READ;
    req.contextId = counterId;
    ret = hsmCall(&req);
    *value = req.value;
    return ret;
}

Std_ReturnType Crypto_Hsm_CounterIncrement(uint8 counterId, uint32 newValue)
{
    Hsm_RequestType req;
    memClear(&req, sizeof(req));
    req.cmd = HSM_CMD_COUNTER_INCREMENT;
    req.contextId = counterId;
    req.value = newValue;
    return hsmCall(&req);
}

Std_ReturnType Crypto_Hsm_SetLifecycle(Hsm_LifecycleType lc)
{
    Hsm_RequestType req;
    memClear(&req, sizeof(req));
    req.cmd = HSM_CMD_SET_LIFECYCLE;
    req.value = (uint32)lc;
    return hsmCall(&req);
}

Std_ReturnType Crypto_Hsm_GetId(const uint8 challenge[16], uint8 out[32])
{
    Hsm_RequestType req;
    uint32 l = 32u;
    memClear(&req, sizeof(req));
    req.cmd = HSM_CMD_GET_ID;
    req.in1 = challenge;
    req.in1Len = 16u;
    req.out1 = out;
    req.out1Len = &l;
    return hsmCall(&req);
}

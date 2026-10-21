/**
 * @file    Hsm.c
 * @brief   HSM firmware: command dispatcher, secure boot, RNG, IPC mailbox.
 */
#include "Hsm.h"
#include "Hsm_KeyStore.h"
#include "Hsm_She.h"
#include "hsm_aes.h"
#include "hsm_cmac.h"
#include "hsm_sha256.h"
#include "hsm_drbg.h"

/* ======================================================================== */
/* Internal state                                                           */
/* ======================================================================== */
typedef enum
{
    HSM_CTX_IDLE = 0,
    HSM_CTX_CMAC,
    HSM_CTX_SHA256
} Hsm_CtxKindType;

typedef struct
{
    Hsm_CtxKindType kind;
    Hsm_KeyIdType   keyId;
    union
    {
        Hsm_CmacCtxType   cmac;
        Hsm_Sha256CtxType sha;
    } u;
} Hsm_StreamCtxType;

typedef struct
{
    Hsm_RequestType *req;
    Hsm_IpcStateType state;
    Hsm_ErrorType    erc;
} Hsm_MailboxType;

static const Hsm_PlatformConfigType *Hsm_Platform = NULL_PTR;
static uint8             Hsm_Sreg;
static Hsm_ErrorType     Hsm_BootResult;
static Hsm_DrbgCtxType   Hsm_Drbg;
static Hsm_StreamCtxType Hsm_Ctx[HSM_NUM_CONTEXTS];
static Hsm_MailboxType   Hsm_Mailbox[HSM_IPC_QUEUE_LEN];
static uint8             Hsm_MailboxNext;
static uint8             Hsm_DebugChallenge[16];
static boolean           Hsm_DebugChallengeValid;
static boolean           Hsm_DebuggerAttached;

#define BOOT_OK()   (((Hsm_Sreg & HSM_SREG_BOOT_OK) != 0u) ? TRUE : FALSE)

/* ======================================================================== */
/* Helpers                                                                  */
/* ======================================================================== */
static void copyBytes(uint8 *dst, const uint8 *src, uint32 len)
{
    uint32 i;
    for (i = 0u; i < len; i++)
    {
        dst[i] = src[i];
    }
}

static Hsm_ErrorType checkOut(const Hsm_RequestType *req, uint32 needed)
{
    if ((req->out1 == NULL_PTR) || (req->out1Len == NULL_PTR))
    {
        return HSM_ERC_PARAM;
    }
    if (*req->out1Len < needed)
    {
        return HSM_ERC_SMALL_BUFFER;
    }
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType keyFor(Hsm_KeyIdType id, boolean forMac, const uint8 **key)
{
    Hsm_ErrorType erc = Hsm_KeyStoreCheckUsage(id, forMac, BOOT_OK(), Hsm_DebuggerAttached);
    if (erc == HSM_ERC_NO_ERROR)
    {
        const Hsm_KeySlotType *s = Hsm_KeyStoreSlot(id);
        if ((Hsm_KeyStoreIsSheSlot(id) == TRUE) && (s->keyLen != 16u))
        {
            return HSM_ERC_KEY_INVALID;
        }
        *key = s->key;
    }
    return erc;
}

/* ======================================================================== */
/* Secure boot (SHE CMD_SECURE_BOOT executed autonomously after reset)      */
/* ======================================================================== */
static void lockBootProtectedKeys(void)
{
    Hsm_Sreg &= (uint8)~HSM_SREG_BOOT_OK;
}

static Hsm_ErrorType secureBoot(void)
{
    const Hsm_KeySlotType *bootKey = Hsm_KeyStoreSlot(HSM_KEY_BOOT_MAC_KEY);
    const Hsm_KeySlotType *bootMac = Hsm_KeyStoreSlot(HSM_KEY_BOOT_MAC);
    Hsm_CmacCtxType cmac;
    const uint8 *img;
    uint32 size = 0u;
    uint8 hdr[16] = { 0u };
    uint8 mac[16];
    uint32 bits;

    Hsm_Sreg |= HSM_SREG_BOOT_INIT;

    if ((Hsm_Platform == NULL_PTR) || (Hsm_Platform->getBootImage == NULL_PTR) ||
        (bootKey->valid == FALSE))
    {
        /* No BOOT_MAC_KEY: secure boot not configured */
        Hsm_Sreg |= HSM_SREG_BOOT_FINISHED;
        Hsm_Sreg &= (uint8)~HSM_SREG_BOOT_INIT;
        return HSM_ERC_NO_SECURE_BOOT;
    }

    Hsm_Sreg |= HSM_SREG_SECURE_BOOT;
    img = Hsm_Platform->getBootImage(&size);
    bits = size * 8u;
    hdr[12] = (uint8)(bits >> 24);
    hdr[13] = (uint8)(bits >> 16);
    hdr[14] = (uint8)(bits >> 8);
    hdr[15] = (uint8)(bits);

    /* BOOT_MAC = CMAC(BOOT_MAC_KEY, 0^96 | SIZE(32) | BOOTLOADER) */
    Hsm_CmacStart(&cmac, bootKey->key);
    Hsm_CmacUpdate(&cmac, hdr, 16u);
    Hsm_CmacUpdate(&cmac, img, size);
    Hsm_CmacFinish(&cmac, mac);

    Hsm_Sreg |= HSM_SREG_BOOT_FINISHED;
    Hsm_Sreg &= (uint8)~(HSM_SREG_BOOT_INIT | HSM_SREG_SECURE_BOOT);

    if (bootMac->valid == FALSE)
    {
        /* Autonomous bootstrap: learn BOOT_MAC on first boot (not in field) */
        if (Hsm_KeyStoreNvm()->lifecycle == HSM_LC_IN_FIELD)
        {
            lockBootProtectedKeys();
            return HSM_ERC_NO_SECURE_BOOT;
        }
        Hsm_KeyStoreWrite(HSM_KEY_BOOT_MAC, mac, 16u, 0u, 0u, FALSE);
        Hsm_Sreg |= HSM_SREG_BOOT_OK;
        return HSM_ERC_NO_ERROR;
    }

    if (Hsm_ConstTimeEqual(mac, bootMac->key, 16u) == TRUE)
    {
        Hsm_Sreg |= HSM_SREG_BOOT_OK;
        Hsm_SecureZero(mac, sizeof(mac));
        return HSM_ERC_NO_ERROR;
    }
    lockBootProtectedKeys();
    Hsm_SecureZero(mac, sizeof(mac));
    return HSM_ERC_VERIFY_FAILED;
}

/* ======================================================================== */
/* RNG                                                                      */
/* ======================================================================== */
static Hsm_ErrorType rngInit(void)
{
    uint8 seed[HSM_DRBG_SEEDLEN];
    uint8 i;
    Hsm_NvmType *nvm = Hsm_KeyStoreNvm();

    if ((Hsm_Platform == NULL_PTR) || (Hsm_Platform->getEntropy == NULL_PTR) ||
        (Hsm_Platform->getEntropy(seed, HSM_DRBG_SEEDLEN) != E_OK))
    {
        return HSM_ERC_RNG_SEED;
    }
    /* mix persisted PRNG seed so that state evolves across resets */
    for (i = 0u; i < 16u; i++)
    {
        seed[16u + i] ^= nvm->prngSeed[i];
    }
    (void)Hsm_DrbgInstantiate(&Hsm_Drbg, seed);
    (void)Hsm_DrbgGenerate(&Hsm_Drbg, nvm->prngSeed, 16u);
    Hsm_SecureZero(seed, sizeof(seed));
    Hsm_Sreg |= HSM_SREG_RND_INIT;
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType rngGenerate(uint8 *out, uint32 len)
{
    Std_ReturnType r;
    if ((Hsm_Sreg & HSM_SREG_RND_INIT) == 0u)
    {
        return HSM_ERC_RNG_SEED;
    }
    r = Hsm_DrbgGenerate(&Hsm_Drbg, out, len);
    if (r == HSM_DRBG_E_RESEED_REQUIRED)
    {
        if (rngInit() != HSM_ERC_NO_ERROR)
        {
            return HSM_ERC_RNG_SEED;
        }
        r = Hsm_DrbgGenerate(&Hsm_Drbg, out, len);
    }
    return (r == E_OK) ? HSM_ERC_NO_ERROR : HSM_ERC_GENERAL_ERROR;
}

/* ======================================================================== */
/* Command handlers                                                         */
/* ======================================================================== */
static Hsm_ErrorType cmdCipher(Hsm_RequestType *req)
{
    const uint8 *key = NULL_PTR;
    Hsm_ErrorType erc;
    Std_ReturnType r = E_NOT_OK;

    if ((req->in1 == NULL_PTR) || ((req->in1Len % 16u) != 0u) || (req->in1Len == 0u))
    {
        return HSM_ERC_PARAM;
    }
    erc = checkOut(req, req->in1Len);
    if (erc != HSM_ERC_NO_ERROR)
    {
        return erc;
    }
    erc = keyFor(req->keyId, FALSE, &key);
    if (erc != HSM_ERC_NO_ERROR)
    {
        return erc;
    }
    if (((req->cmd == HSM_CMD_ENC_CBC) || (req->cmd == HSM_CMD_DEC_CBC)) &&
        ((req->in2 == NULL_PTR) || (req->in2Len != 16u)))
    {
        return HSM_ERC_PARAM;
    }
    switch (req->cmd)
    {
        case HSM_CMD_ENC_ECB: r = Hsm_AesEcbEncrypt(key, req->in1, req->in1Len, req->out1); break;
        case HSM_CMD_DEC_ECB: r = Hsm_AesEcbDecrypt(key, req->in1, req->in1Len, req->out1); break;
        case HSM_CMD_ENC_CBC: r = Hsm_AesCbcEncrypt(key, req->in2, req->in1, req->in1Len, req->out1); break;
        case HSM_CMD_DEC_CBC: r = Hsm_AesCbcDecrypt(key, req->in2, req->in1, req->in1Len, req->out1); break;
        default: break;
    }
    *req->out1Len = req->in1Len;
    return (r == E_OK) ? HSM_ERC_NO_ERROR : HSM_ERC_GENERAL_ERROR;
}

static Hsm_ErrorType cmdGenerateMac(Hsm_RequestType *req)
{
    const uint8 *key = NULL_PTR;
    Hsm_ErrorType erc;
    uint8 mac[16];
    uint32 n;

    if ((req->in1 == NULL_PTR) && (req->in1Len != 0u))
    {
        return HSM_ERC_PARAM;
    }
    if ((req->out1 == NULL_PTR) || (req->out1Len == NULL_PTR) || (*req->out1Len == 0u))
    {
        return HSM_ERC_PARAM;
    }
    erc = keyFor(req->keyId, TRUE, &key);
    if (erc != HSM_ERC_NO_ERROR)
    {
        return erc;
    }
    Hsm_Cmac(key, req->in1, req->in1Len, mac);
    /* AUTOSAR allows truncation: output min(capacity, 16) bytes */
    n = (*req->out1Len < 16u) ? *req->out1Len : 16u;
    copyBytes(req->out1, mac, n);
    *req->out1Len = n;
    Hsm_SecureZero(mac, sizeof(mac));
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType cmdVerifyMac(Hsm_RequestType *req)
{
    const uint8 *key = NULL_PTR;
    Hsm_ErrorType erc;

    req->verifyResult = FALSE;
    if (((req->in1 == NULL_PTR) && (req->in1Len != 0u)) || (req->in2 == NULL_PTR) ||
        (req->in2Len == 0u) || (req->in2Len > 128u))
    {
        return HSM_ERC_PARAM;
    }
    erc = keyFor(req->keyId, TRUE, &key);
    if (erc != HSM_ERC_NO_ERROR)
    {
        return erc;
    }
    req->verifyResult = Hsm_CmacVerify(key, req->in1, req->in1Len, req->in2, req->in2Len);
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType cmdLoadKey(Hsm_RequestType *req)
{
    if ((req->in1 == NULL_PTR) || (req->in1Len != 16u) || (req->in2 == NULL_PTR) ||
        (req->in2Len != 32u) || (req->in3 == NULL_PTR) || (req->in3Len != 16u) ||
        (req->out1 == NULL_PTR) || (req->out1Len == NULL_PTR) || (*req->out1Len < 32u) ||
        (req->out2 == NULL_PTR) || (req->out2Len == NULL_PTR) || (*req->out2Len < 16u))
    {
        return HSM_ERC_PARAM;
    }
    {
        Hsm_ErrorType erc = Hsm_SheLoadKey(req->in1, req->in2, req->in3, req->out1, req->out2);
        if (erc == HSM_ERC_NO_ERROR)
        {
            *req->out1Len = 32u;
            *req->out2Len = 16u;
        }
        return erc;
    }
}

static Hsm_ErrorType cmdLoadPlainKey(Hsm_RequestType *req)
{
    /* SHE CMD_LOAD_PLAIN_KEY: only RAM_KEY, marked as plain (exportable) */
    if ((req->in1 == NULL_PTR) || (req->in1Len != 16u))
    {
        return HSM_ERC_PARAM;
    }
    Hsm_KeyStoreWrite(HSM_RAM_KEY, req->in1, 16u, 0u, 0u, TRUE);
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType cmdLoadPlainKeyExt(Hsm_RequestType *req)
{
    /* Provisioning interface: any slot, only outside IN_FIELD lifecycle    */
    Hsm_KeySlotType *s = Hsm_KeyStoreSlot(req->keyId);
    if (Hsm_KeyStoreNvm()->lifecycle == HSM_LC_IN_FIELD)
    {
        return HSM_ERC_ACCESS_DENIED;
    }
    if ((s == NULL_PTR) || (req->in1 == NULL_PTR) || (req->in1Len == 0u) ||
        (req->in1Len > HSM_MAX_KEY_LEN) ||
        ((Hsm_KeyStoreIsSheSlot(req->keyId) == TRUE) && (req->in1Len != 16u)))
    {
        return HSM_ERC_PARAM;
    }
    if ((s->valid == TRUE) && ((s->flags & HSM_FLAG_WRITE_PROTECTION) != 0u))
    {
        return HSM_ERC_KEY_WRITE_PROTECTED;
    }
    Hsm_KeyStoreWrite(req->keyId, req->in1, (uint8)req->in1Len, (uint8)req->value,
                      (s->valid == TRUE) ? s->counter : 0u, FALSE);
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType cmdExportRamKey(Hsm_RequestType *req)
{
    Hsm_SheUpdateMsgType msg;
    Hsm_ErrorType erc;

    /* out1: M1|M2|M3 (64 bytes), out2: M4|M5 (48 bytes) */
    if ((req->out1 == NULL_PTR) || (req->out1Len == NULL_PTR) || (*req->out1Len < 64u) ||
        (req->out2 == NULL_PTR) || (req->out2Len == NULL_PTR) || (*req->out2Len < 48u))
    {
        return HSM_ERC_PARAM;
    }
    erc = Hsm_SheExportRamKey(&msg);
    if (erc == HSM_ERC_NO_ERROR)
    {
        copyBytes(&req->out1[0], msg.m1, 16u);
        copyBytes(&req->out1[16], msg.m2, 32u);
        copyBytes(&req->out1[48], msg.m3, 16u);
        copyBytes(&req->out2[0], msg.m4, 32u);
        copyBytes(&req->out2[32], msg.m5, 16u);
        *req->out1Len = 64u;
        *req->out2Len = 48u;
    }
    Hsm_SecureZero(&msg, sizeof(msg));
    return erc;
}

static Hsm_ErrorType cmdExtendSeed(const Hsm_RequestType *req)
{
    uint8 seed[HSM_DRBG_SEEDLEN] = { 0u };
    uint32 i;

    if ((Hsm_Sreg & HSM_SREG_RND_INIT) == 0u)
    {
        return HSM_ERC_RNG_SEED;
    }
    if ((req->in1 == NULL_PTR) || (req->in1Len == 0u) || (req->in1Len > HSM_DRBG_SEEDLEN))
    {
        return HSM_ERC_PARAM;
    }
    for (i = 0u; i < req->in1Len; i++)
    {
        seed[i] = req->in1[i];
    }
    (void)Hsm_DrbgReseed(&Hsm_Drbg, seed);
    Hsm_SecureZero(seed, sizeof(seed));
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType cmdRnd(Hsm_RequestType *req)
{
    if ((req->out1 == NULL_PTR) || (req->out1Len == NULL_PTR) || (*req->out1Len == 0u))
    {
        return HSM_ERC_PARAM;
    }
    return rngGenerate(req->out1, *req->out1Len);
}

static Hsm_ErrorType cmdGetId(Hsm_RequestType *req)
{
    /* SHE CMD_GET_ID: out1 = UID(15) | SREG(1) | MAC(16) where
     * MAC = CMAC(MASTER_ECU_KEY, CHALLENGE | UID | SREG); in1 = challenge  */
    const Hsm_KeySlotType *mk = Hsm_KeyStoreSlot(HSM_KEY_MASTER_ECU_KEY);
    uint8 buf[32];
    uint8 i;
    Hsm_ErrorType erc = checkOut(req, 32u);

    if (erc != HSM_ERC_NO_ERROR)
    {
        return erc;
    }
    if ((req->in1 == NULL_PTR) || (req->in1Len != 16u))
    {
        return HSM_ERC_PARAM;
    }
    copyBytes(buf, req->in1, 16u);
    copyBytes(&buf[16], Hsm_KeyStoreNvm()->uid, 15u);
    buf[31] = Hsm_Sreg;
    copyBytes(req->out1, &buf[16], 16u);
    if (mk->valid == TRUE)
    {
        Hsm_Cmac(mk->key, buf, 32u, &req->out1[16]);
    }
    else
    {
        for (i = 0u; i < 16u; i++)
        {
            req->out1[16u + i] = 0u;
        }
    }
    *req->out1Len = 32u;
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType cmdDebugChallenge(Hsm_RequestType *req)
{
    Hsm_ErrorType erc = checkOut(req, 16u);
    if (erc != HSM_ERC_NO_ERROR)
    {
        return erc;
    }
    erc = rngGenerate(Hsm_DebugChallenge, 16u);
    if (erc == HSM_ERC_NO_ERROR)
    {
        copyBytes(req->out1, Hsm_DebugChallenge, 16u);
        *req->out1Len = 16u;
        Hsm_DebugChallengeValid = TRUE;
    }
    return erc;
}

static Hsm_ErrorType cmdDebugAuthorization(const Hsm_RequestType *req)
{
    const Hsm_KeySlotType *mk = Hsm_KeyStoreSlot(HSM_KEY_MASTER_ECU_KEY);
    uint8 k[16];
    uint8 buf[31];
    uint8 auth[16];
    boolean ok;
    Hsm_KeyIdType id;

    if (Hsm_DebugChallengeValid == FALSE)
    {
        return HSM_ERC_SEQUENCE_ERROR;
    }
    Hsm_DebugChallengeValid = FALSE;
    if ((req->in1 == NULL_PTR) || (req->in1Len != 16u))
    {
        return HSM_ERC_PARAM;
    }
    /* Not allowed while any key is write protected */
    for (id = 0u; id < HSM_NUM_SHE_SLOTS; id++)
    {
        const Hsm_KeySlotType *s = Hsm_KeyStoreSlot(id);
        if ((s->valid == TRUE) && ((s->flags & HSM_FLAG_WRITE_PROTECTION) != 0u))
        {
            return HSM_ERC_KEY_WRITE_PROTECTED;
        }
    }
    Hsm_SheKdf((mk->valid == TRUE) ? mk->key : Hsm_She_DefaultKey, Hsm_She_DebugKeyC, k);
    copyBytes(buf, Hsm_DebugChallenge, 16u);
    copyBytes(&buf[16], Hsm_KeyStoreNvm()->uid, 15u);
    Hsm_Cmac(k, buf, 31u, auth);
    ok = Hsm_ConstTimeEqual(auth, req->in1, 16u);
    Hsm_SecureZero(k, sizeof(k));
    if (ok == FALSE)
    {
        return HSM_ERC_NO_DEBUGGING;
    }
    /* Erase all keys except SECRET_KEY, unlock debug interface */
    for (id = 1u; id < HSM_NUM_KEY_SLOTS; id++)
    {
        Hsm_KeyStoreErase(id);
    }
    return HSM_ERC_NO_ERROR;
}

static Hsm_StreamCtxType *getCtx(uint8 id)
{
    return (id < HSM_NUM_CONTEXTS) ? &Hsm_Ctx[id] : NULL_PTR;
}

static Hsm_ErrorType cmdMacStream(Hsm_RequestType *req)
{
    Hsm_StreamCtxType *c = getCtx(req->contextId);
    const uint8 *key = NULL_PTR;
    Hsm_ErrorType erc;
    uint8 mac[16];

    if (c == NULL_PTR)
    {
        return HSM_ERC_PARAM;
    }
    switch (req->cmd)
    {
        case HSM_CMD_MAC_START:
            erc = keyFor(req->keyId, TRUE, &key);
            if (erc != HSM_ERC_NO_ERROR)
            {
                return erc;
            }
            Hsm_CmacStart(&c->u.cmac, key);
            c->kind = HSM_CTX_CMAC;
            c->keyId = req->keyId;
            return HSM_ERC_NO_ERROR;

        case HSM_CMD_MAC_UPDATE:
            if (c->kind != HSM_CTX_CMAC)
            {
                return HSM_ERC_SEQUENCE_ERROR;
            }
            if ((req->in1 == NULL_PTR) && (req->in1Len != 0u))
            {
                return HSM_ERC_PARAM;
            }
            Hsm_CmacUpdate(&c->u.cmac, req->in1, req->in1Len);
            return HSM_ERC_NO_ERROR;

        case HSM_CMD_MAC_FINISH:
            if (c->kind != HSM_CTX_CMAC)
            {
                return HSM_ERC_SEQUENCE_ERROR;
            }
            Hsm_CmacFinish(&c->u.cmac, mac);
            c->kind = HSM_CTX_IDLE;
            if (req->in2 != NULL_PTR)
            {
                /* verify mode: in2 = MAC, in2Len = MAC length in bits */
                req->verifyResult = ((req->in2Len > 0u) && (req->in2Len <= 128u)) ?
                                    Hsm_CompareBits(mac, req->in2, req->in2Len) : FALSE;
            }
            else
            {
                uint32 n;
                if ((req->out1 == NULL_PTR) || (req->out1Len == NULL_PTR))
                {
                    return HSM_ERC_PARAM;
                }
                n = (*req->out1Len < 16u) ? *req->out1Len : 16u;
                copyBytes(req->out1, mac, n);
                *req->out1Len = n;
            }
            Hsm_SecureZero(mac, sizeof(mac));
            return HSM_ERC_NO_ERROR;

        default:
            return HSM_ERC_PARAM;
    }
}

static Hsm_ErrorType cmdHash(Hsm_RequestType *req)
{
    Hsm_StreamCtxType *c;
    uint8 dig[32];
    Hsm_ErrorType erc;
    uint32 n;

    if (req->cmd == HSM_CMD_HASH_SHA256)
    {
        if ((req->in1 == NULL_PTR) && (req->in1Len != 0u))
        {
            return HSM_ERC_PARAM;
        }
        erc = checkOut(req, 1u);
        if (erc != HSM_ERC_NO_ERROR)
        {
            return erc;
        }
        Hsm_Sha256(req->in1, req->in1Len, dig);
        n = (*req->out1Len < 32u) ? *req->out1Len : 32u;
        copyBytes(req->out1, dig, n);
        *req->out1Len = n;
        return HSM_ERC_NO_ERROR;
    }
    c = getCtx(req->contextId);
    if (c == NULL_PTR)
    {
        return HSM_ERC_PARAM;
    }
    if (req->cmd == HSM_CMD_HASH_START)
    {
        Hsm_Sha256Start(&c->u.sha);
        c->kind = HSM_CTX_SHA256;
        return HSM_ERC_NO_ERROR;
    }
    if (c->kind != HSM_CTX_SHA256)
    {
        return HSM_ERC_SEQUENCE_ERROR;
    }
    if (req->cmd == HSM_CMD_HASH_UPDATE)
    {
        if ((req->in1 == NULL_PTR) && (req->in1Len != 0u))
        {
            return HSM_ERC_PARAM;
        }
        Hsm_Sha256Update(&c->u.sha, req->in1, req->in1Len);
        return HSM_ERC_NO_ERROR;
    }
    erc = checkOut(req, 1u);
    if (erc != HSM_ERC_NO_ERROR)
    {
        return erc;
    }
    Hsm_Sha256Finish(&c->u.sha, dig);
    c->kind = HSM_CTX_IDLE;
    n = (*req->out1Len < 32u) ? *req->out1Len : 32u;
    copyBytes(req->out1, dig, n);
    *req->out1Len = n;
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType cmdHmac(Hsm_RequestType *req)
{
    const Hsm_KeySlotType *s = Hsm_KeyStoreSlot(req->keyId);
    uint8 mac[32];
    Hsm_ErrorType erc;

    /* HMAC keys only live in extended slots */
    if ((s == NULL_PTR) || (Hsm_KeyStoreIsSheSlot(req->keyId) == TRUE))
    {
        return HSM_ERC_KEY_INVALID;
    }
    erc = Hsm_KeyStoreCheckUsage(req->keyId, TRUE, BOOT_OK(), Hsm_DebuggerAttached);
    if (erc != HSM_ERC_NO_ERROR)
    {
        return erc;
    }
    if ((req->in1 == NULL_PTR) && (req->in1Len != 0u))
    {
        return HSM_ERC_PARAM;
    }
    Hsm_HmacSha256(s->key, s->keyLen, req->in1, req->in1Len, mac);
    if (req->cmd == HSM_CMD_HMAC_GENERATE)
    {
        uint32 n;
        erc = checkOut(req, 1u);
        if (erc == HSM_ERC_NO_ERROR)
        {
            n = (*req->out1Len < 32u) ? *req->out1Len : 32u;
            copyBytes(req->out1, mac, n);
            *req->out1Len = n;
        }
    }
    else
    {
        if ((req->in2 == NULL_PTR) || (req->in2Len == 0u) || (req->in2Len > 256u))
        {
            erc = HSM_ERC_PARAM;
        }
        else
        {
            req->verifyResult = Hsm_CompareBits(mac, req->in2, req->in2Len);
        }
    }
    Hsm_SecureZero(mac, sizeof(mac));
    return erc;
}

static Hsm_ErrorType cmdKeyStatus(Hsm_RequestType *req)
{
    /* value = valid(bit8) | flags(bits0-4); out: counter in contextId-free u32 */
    const Hsm_KeySlotType *s = Hsm_KeyStoreSlot(req->keyId);
    if (s == NULL_PTR)
    {
        return HSM_ERC_KEY_INVALID;
    }
    req->value = ((s->valid == TRUE) ? 0x100u : 0u) | (uint32)s->flags |
                 ((uint32)s->counter << 12);
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType cmdCounter(Hsm_RequestType *req)
{
    Hsm_NvmType *nvm = Hsm_KeyStoreNvm();
    if (req->contextId >= HSM_NUM_COUNTERS)
    {
        return HSM_ERC_PARAM;
    }
    if (req->cmd == HSM_CMD_COUNTER_INCREMENT)
    {
        /* value = new value; must be strictly greater (monotonic) */
        if (req->value <= nvm->monotonicCounter[req->contextId])
        {
            return HSM_ERC_COUNTER_OVERFLOW;
        }
        nvm->monotonicCounter[req->contextId] = req->value;
    }
    req->value = nvm->monotonicCounter[req->contextId];
    return HSM_ERC_NO_ERROR;
}

static Hsm_ErrorType cmdSetLifecycle(const Hsm_RequestType *req)
{
    Hsm_NvmType *nvm = Hsm_KeyStoreNvm();
    /* Lifecycle can only advance */
    if ((req->value > (uint32)HSM_LC_IN_FIELD) || (req->value < (uint32)nvm->lifecycle))
    {
        return HSM_ERC_ACCESS_DENIED;
    }
    nvm->lifecycle = (Hsm_LifecycleType)req->value;
    return HSM_ERC_NO_ERROR;
}

/* ======================================================================== */
/* Public API                                                               */
/* ======================================================================== */
void Hsm_FactoryReset(const uint8 uid[15])
{
    Hsm_KeyStoreFactoryInit(uid);
}

void Hsm_Init(const Hsm_PlatformConfigType *cfg)
{
    uint8 i;
    Hsm_Platform = cfg;
    Hsm_Sreg = 0u;
    Hsm_DebugChallengeValid = FALSE;
    Hsm_SecureZero(Hsm_Ctx, sizeof(Hsm_Ctx));
    Hsm_DrbgUninstantiate(&Hsm_Drbg);
    for (i = 0u; i < HSM_IPC_QUEUE_LEN; i++)
    {
        Hsm_Mailbox[i].state = HSM_IPC_FREE;
        Hsm_Mailbox[i].req = NULL_PTR;
    }
    Hsm_MailboxNext = 0u;
    Hsm_KeyStoreResetVolatile();
    if (Hsm_DebuggerAttached == TRUE)
    {
        Hsm_Sreg |= HSM_SREG_EXT_DEBUGGER;
    }
    Hsm_BootResult = secureBoot();
    (void)rngInit();
}

uint8 Hsm_GetStatusRegister(void)
{
    return Hsm_Sreg;
}

Hsm_ErrorType Hsm_GetLastBootResult(void)
{
    return Hsm_BootResult;
}

void Hsm_SimSetDebuggerAttached(boolean attached)
{
    Hsm_DebuggerAttached = attached;
    if (attached == TRUE)
    {
        Hsm_Sreg |= HSM_SREG_EXT_DEBUGGER;
    }
    else
    {
        Hsm_Sreg &= (uint8)~HSM_SREG_EXT_DEBUGGER;
    }
}

Hsm_ErrorType Hsm_ProcessRequest(Hsm_RequestType *req)
{
    Hsm_ErrorType erc;

    if (req == NULL_PTR)
    {
        return HSM_ERC_PARAM;
    }
    Hsm_Sreg |= HSM_SREG_BUSY;
    switch (req->cmd)
    {
        case HSM_CMD_ENC_ECB:
        case HSM_CMD_ENC_CBC:
        case HSM_CMD_DEC_ECB:
        case HSM_CMD_DEC_CBC:            erc = cmdCipher(req); break;
        case HSM_CMD_GENERATE_MAC:       erc = cmdGenerateMac(req); break;
        case HSM_CMD_VERIFY_MAC:         erc = cmdVerifyMac(req); break;
        case HSM_CMD_LOAD_KEY:           erc = cmdLoadKey(req); break;
        case HSM_CMD_LOAD_PLAIN_KEY:     erc = cmdLoadPlainKey(req); break;
        case HSM_CMD_EXPORT_RAM_KEY:     erc = cmdExportRamKey(req); break;
        case HSM_CMD_INIT_RNG:           erc = rngInit(); break;
        case HSM_CMD_EXTEND_SEED:        erc = cmdExtendSeed(req); break;
        case HSM_CMD_RND:                erc = cmdRnd(req); break;
        case HSM_CMD_SECURE_BOOT:        Hsm_BootResult = secureBoot(); erc = Hsm_BootResult; break;
        case HSM_CMD_BOOT_FAILURE:
            lockBootProtectedKeys();
            erc = HSM_ERC_NO_ERROR;
            break;
        case HSM_CMD_BOOT_OK:
            /* only allowed once secure boot has finished successfully      */
            erc = (((Hsm_Sreg & HSM_SREG_BOOT_FINISHED) != 0u) && (BOOT_OK() == TRUE)) ?
                  HSM_ERC_NO_ERROR : HSM_ERC_SEQUENCE_ERROR;
            break;
        case HSM_CMD_GET_ID:             erc = cmdGetId(req); break;
        case HSM_CMD_CANCEL:
            Hsm_SecureZero(Hsm_Ctx, sizeof(Hsm_Ctx));
            erc = HSM_ERC_NO_ERROR;
            break;
        case HSM_CMD_DEBUG_CHALLENGE:    erc = cmdDebugChallenge(req); break;
        case HSM_CMD_DEBUG_AUTHORIZATION:erc = cmdDebugAuthorization(req); break;
        case HSM_CMD_MAC_START:
        case HSM_CMD_MAC_UPDATE:
        case HSM_CMD_MAC_FINISH:         erc = cmdMacStream(req); break;
        case HSM_CMD_HASH_SHA256:
        case HSM_CMD_HASH_START:
        case HSM_CMD_HASH_UPDATE:
        case HSM_CMD_HASH_FINISH:        erc = cmdHash(req); break;
        case HSM_CMD_HMAC_GENERATE:
        case HSM_CMD_HMAC_VERIFY:        erc = cmdHmac(req); break;
        case HSM_CMD_LOAD_PLAIN_KEY_EXT: erc = cmdLoadPlainKeyExt(req); break;
        case HSM_CMD_KEY_STATUS:         erc = cmdKeyStatus(req); break;
        case HSM_CMD_COUNTER_READ:
        case HSM_CMD_COUNTER_INCREMENT:  erc = cmdCounter(req); break;
        case HSM_CMD_SET_LIFECYCLE:      erc = cmdSetLifecycle(req); break;
        case HSM_CMD_GET_STATUS:
            /* bits 0-7: SREG, bits 8-15: result of the last secure boot */
            req->value = (uint32)Hsm_Sreg | ((uint32)Hsm_BootResult << 8);
            erc = HSM_ERC_NO_ERROR;
            break;
        default:                         erc = HSM_ERC_PARAM; break;
    }
    Hsm_Sreg &= (uint8)~HSM_SREG_BUSY;
    return erc;
}

/* ---------------------------- mailbox ---------------------------------- */
Hsm_IpcHandleType Hsm_IpcSubmit(Hsm_RequestType *req)
{
    uint8 i;
    for (i = 0u; i < HSM_IPC_QUEUE_LEN; i++)
    {
        if (Hsm_Mailbox[i].state == HSM_IPC_FREE)
        {
            Hsm_Mailbox[i].req = req;
            Hsm_Mailbox[i].erc = HSM_ERC_BUSY;
            Hsm_Mailbox[i].state = HSM_IPC_PENDING;
            return i;
        }
    }
    return HSM_IPC_INVALID_HANDLE;
}

Hsm_IpcStateType Hsm_IpcGetState(Hsm_IpcHandleType h)
{
    return (h < HSM_IPC_QUEUE_LEN) ? Hsm_Mailbox[h].state : HSM_IPC_FREE;
}

Hsm_ErrorType Hsm_IpcRelease(Hsm_IpcHandleType h)
{
    Hsm_ErrorType erc;
    if ((h >= HSM_IPC_QUEUE_LEN) || (Hsm_Mailbox[h].state != HSM_IPC_DONE))
    {
        return HSM_ERC_SEQUENCE_ERROR;
    }
    erc = Hsm_Mailbox[h].erc;
    Hsm_Mailbox[h].state = HSM_IPC_FREE;
    Hsm_Mailbox[h].req = NULL_PTR;
    return erc;
}

void Hsm_MainFunction(void)
{
    /* Process one pending request per call (round robin) */
    uint8 n;
    for (n = 0u; n < HSM_IPC_QUEUE_LEN; n++)
    {
        uint8 i = (uint8)((Hsm_MailboxNext + n) % HSM_IPC_QUEUE_LEN);
        if (Hsm_Mailbox[i].state == HSM_IPC_PENDING)
        {
            Hsm_Mailbox[i].erc = Hsm_ProcessRequest(Hsm_Mailbox[i].req);
            Hsm_Mailbox[i].state = HSM_IPC_DONE;
            Hsm_MailboxNext = (uint8)((i + 1u) % HSM_IPC_QUEUE_LEN);
            break;
        }
    }
}

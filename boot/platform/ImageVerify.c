/**
 * @file    ImageVerify.c
 */
#include "ImageVerify.h"
#include "AppHeader.h"
#include "Fls.h"
#include "Csm.h"
#include "Crypto_HsmExt.h"

#define IMGV_CHUNK 0x1000u

ImageVerify_ResultType ImageVerify_Application(uint32 *swVersion)
{
    const uint8 *hdr = Fls_GetPointer(APP_START);
    const uint8 *body = Fls_GetPointer(APP_BODY_START);
    AppHeader_Type h;
    uint8 digest[32];
    uint32 dlen = sizeof(digest);
    uint32 off;
    uint32 minVersion = 0u;
    Crypto_VerifyResultType vr = CRYPTO_E_VER_NOT_OK;
    Std_ReturnType r;

    AppHeader_Parse(hdr, &h);
    if (swVersion != NULL_PTR)
    {
        *swVersion = h.swVersion;
    }
    if ((h.magic != APPHDR_MAGIC) || (h.headerVersion != APPHDR_VERSION))
    {
        return IMGV_NO_IMAGE;
    }
    if ((h.size == 0u) || (h.size > APP_BODY_MAX) || (h.entry >= h.size))
    {
        return IMGV_BAD_SIZE;
    }

    /* 1. authenticity of the header (CMAC by HSM, key FLASH_VERIFY) */
    r = Csm_MacVerify(CSM_JOB_FLASH_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                      hdr, APPHDR_SIGNED_LEN, h.mac, APPHDR_MAC_LEN * 8u, &vr);
    if (r != E_OK)
    {
        return IMGV_CRYPTO_ERROR;
    }
    if (vr != CRYPTO_E_VER_OK)
    {
        return IMGV_MAC_INVALID;
    }

    /* 2. integrity of the body: streaming SHA-256 (START / UPDATE / FINISH) */
    if (Csm_Hash(CSM_JOB_HASH_SHA256, CRYPTO_OPERATIONMODE_START, NULL_PTR, 0u, NULL_PTR, NULL_PTR) != E_OK)
    {
        return IMGV_CRYPTO_ERROR;
    }
    for (off = 0u; off < h.size; off += IMGV_CHUNK)
    {
        uint32 n = ((h.size - off) > IMGV_CHUNK) ? IMGV_CHUNK : (h.size - off);
        if (Csm_Hash(CSM_JOB_HASH_SHA256, CRYPTO_OPERATIONMODE_UPDATE, &body[off], n, NULL_PTR, NULL_PTR) != E_OK)
        {
            return IMGV_CRYPTO_ERROR;
        }
    }
    if (Csm_Hash(CSM_JOB_HASH_SHA256, CRYPTO_OPERATIONMODE_FINISH, NULL_PTR, 0u, digest, &dlen) != E_OK)
    {
        return IMGV_CRYPTO_ERROR;
    }
    {
        uint8 diff = 0u;
        uint32 i;
        for (i = 0u; i < 32u; i++)
        {
            diff |= (uint8)(digest[i] ^ h.digest[i]);
        }
        if (diff != 0u)
        {
            return IMGV_DIGEST_MISMATCH;
        }
    }

    /* 3. anti roll-back against the HSM monotonic counter */
    if (Crypto_Hsm_CounterRead(APP_ROLLBACK_COUNTER_ID, &minVersion) != E_OK)
    {
        return IMGV_CRYPTO_ERROR;
    }
    if (h.swVersion < minVersion)
    {
        return IMGV_ROLLBACK;
    }
    return IMGV_OK;
}

const char *ImageVerify_ResultString(ImageVerify_ResultType r)
{
    switch (r)
    {
        case IMGV_OK:              return "OK";
        case IMGV_NO_IMAGE:        return "NO_IMAGE";
        case IMGV_BAD_SIZE:        return "BAD_SIZE";
        case IMGV_DIGEST_MISMATCH: return "DIGEST_MISMATCH";
        case IMGV_MAC_INVALID:     return "MAC_INVALID";
        case IMGV_ROLLBACK:        return "ROLLBACK";
        case IMGV_CRYPTO_ERROR:    return "CRYPTO_ERROR";
        default:                   return "?";
    }
}

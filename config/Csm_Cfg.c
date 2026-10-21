/**
 * @file    Csm_Cfg.c
 * @brief   CSM job configuration (CsmJobs / CsmPrimitives).
 */
#include "Csm.h"
#include "App_Callbacks.h"

/* ---- primitives ---- */
static const Crypto_PrimitiveInfoType Prim_CmacGen    = { 16u, CRYPTO_MACGENERATE, { CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, 16u, CRYPTO_ALGOMODE_CMAC } };
static const Crypto_PrimitiveInfoType Prim_CmacVerify = { 16u, CRYPTO_MACVERIFY,   { CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, 16u, CRYPTO_ALGOMODE_CMAC } };
static const Crypto_PrimitiveInfoType Prim_Sha256     = { 32u, CRYPTO_HASH,        { CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOFAM_NOT_SET, 0u, CRYPTO_ALGOMODE_NOT_SET } };
static const Crypto_PrimitiveInfoType Prim_AesCbcEnc  = { 0u,  CRYPTO_ENCRYPT,     { CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, 16u, CRYPTO_ALGOMODE_CBC } };
static const Crypto_PrimitiveInfoType Prim_AesCbcDec  = { 0u,  CRYPTO_DECRYPT,     { CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, 16u, CRYPTO_ALGOMODE_CBC } };
static const Crypto_PrimitiveInfoType Prim_AesEcbEnc  = { 0u,  CRYPTO_ENCRYPT,     { CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, 16u, CRYPTO_ALGOMODE_ECB } };
static const Crypto_PrimitiveInfoType Prim_AesEcbDec  = { 0u,  CRYPTO_DECRYPT,     { CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, 16u, CRYPTO_ALGOMODE_ECB } };
static const Crypto_PrimitiveInfoType Prim_Rng        = { 0u,  CRYPTO_RANDOMGENERATE, { CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET, 0u, CRYPTO_ALGOMODE_CTRDRBG } };
static const Crypto_PrimitiveInfoType Prim_HmacGen    = { 32u, CRYPTO_MACGENERATE, { CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOFAM_NOT_SET, 32u, CRYPTO_ALGOMODE_HMAC } };
static const Crypto_PrimitiveInfoType Prim_HmacVerify = { 32u, CRYPTO_MACVERIFY,   { CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOFAM_NOT_SET, 32u, CRYPTO_ALGOMODE_HMAC } };

#define SYNC   CRYPTO_PROCESSING_SYNC
#define ASYNC  CRYPTO_PROCESSING_ASYNC

const Csm_JobConfigType Csm_JobConfig[CSM_NUM_JOBS] =
{
    /* key                     queue / channel       primitive        proc   prio callback */
    { CSM_KEY_FLASH_VERIFY,   CRYIF_CHANNEL_SYM,   &Prim_CmacGen,    SYNC,  10u, NULL_PTR },
    { CSM_KEY_FLASH_VERIFY,   CRYIF_CHANNEL_SYM,   &Prim_CmacVerify, SYNC,  10u, NULL_PTR },
    { CSM_KEY_DIAG_SECACCESS, CRYIF_CHANNEL_SYM,   &Prim_CmacGen,    SYNC,  20u, NULL_PTR },
    { CSM_KEY_DIAG_SECACCESS, CRYIF_CHANNEL_SYM,   &Prim_CmacVerify, SYNC,  20u, NULL_PTR },
    { CSM_KEY_SECOC,          CRYIF_CHANNEL_SECOC, &Prim_CmacGen,    SYNC,  30u, NULL_PTR },
    { CSM_KEY_SECOC,          CRYIF_CHANNEL_SECOC, &Prim_CmacVerify, SYNC,  30u, NULL_PTR },
    { CSM_KEY_FLASH_VERIFY,   CRYIF_CHANNEL_SYM,   &Prim_CmacGen,    ASYNC, 5u,  App_CsmJobFinished },
    { CSM_KEY_FLASH_VERIFY,   CRYIF_CHANNEL_SYM,   &Prim_CmacVerify, ASYNC, 15u, App_CsmJobFinished },
    { CSM_KEY_FLASH_VERIFY,   CRYIF_CHANNEL_HASH,  &Prim_Sha256,     SYNC,  10u, NULL_PTR },
    { CSM_KEY_FLASH_VERIFY,   CRYIF_CHANNEL_HASH,  &Prim_Sha256,     ASYNC, 10u, App_CsmJobFinished },
    { CSM_KEY_APP_CIPHER,     CRYIF_CHANNEL_SYM,   &Prim_AesCbcEnc,  SYNC,  10u, NULL_PTR },
    { CSM_KEY_APP_CIPHER,     CRYIF_CHANNEL_SYM,   &Prim_AesCbcDec,  SYNC,  10u, NULL_PTR },
    { CSM_KEY_APP_CIPHER,     CRYIF_CHANNEL_SYM,   &Prim_AesEcbEnc,  SYNC,  10u, NULL_PTR },
    { CSM_KEY_APP_CIPHER,     CRYIF_CHANNEL_SYM,   &Prim_AesEcbDec,  SYNC,  10u, NULL_PTR },
    { CSM_KEY_FLASH_VERIFY,   CRYIF_CHANNEL_RNG,   &Prim_Rng,        SYNC,  10u, NULL_PTR },
    { CSM_KEY_HMAC,           CRYIF_CHANNEL_SYM,   &Prim_HmacGen,    SYNC,  10u, NULL_PTR },
    { CSM_KEY_HMAC,           CRYIF_CHANNEL_SYM,   &Prim_HmacVerify, SYNC,  10u, NULL_PTR },
    { CSM_KEY_RAM,            CRYIF_CHANNEL_SYM,   &Prim_CmacGen,    SYNC,  10u, NULL_PTR }
};

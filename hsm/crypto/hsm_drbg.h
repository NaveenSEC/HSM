/**
 * @file    hsm_drbg.h
 * @brief   AES-128 CTR_DRBG (NIST SP 800-90A, no derivation function).
 */
#ifndef HSM_DRBG_H
#define HSM_DRBG_H

#include "hsm_aes.h"

#define HSM_DRBG_SEEDLEN          32u          /* keylen(16) + outlen(16) */
#define HSM_DRBG_RESEED_INTERVAL  100000u

typedef struct
{
    uint8   key[16];
    uint8   v[16];
    uint32  reseedCounter;
    boolean instantiated;
} Hsm_DrbgCtxType;

Std_ReturnType Hsm_DrbgInstantiate(Hsm_DrbgCtxType *ctx, const uint8 seed[HSM_DRBG_SEEDLEN]);
Std_ReturnType Hsm_DrbgReseed(Hsm_DrbgCtxType *ctx, const uint8 seed[HSM_DRBG_SEEDLEN]);
/** @return E_OK, E_NOT_OK, or 2 when a reseed is required */
Std_ReturnType Hsm_DrbgGenerate(Hsm_DrbgCtxType *ctx, uint8 *out, uint32 len);
void           Hsm_DrbgUninstantiate(Hsm_DrbgCtxType *ctx);

#define HSM_DRBG_E_RESEED_REQUIRED 2u

#endif /* HSM_DRBG_H */

/**
 * @file    hsm_drbg.c
 * @brief   AES-128 CTR_DRBG implementation.
 */
#include "hsm_drbg.h"

static void incV(uint8 v[16])
{
    sint32 i;
    for (i = 15; i >= 0; i--)
    {
        v[i]++;
        if (v[i] != 0u)
        {
            break;
        }
    }
}

static void drbgUpdate(Hsm_DrbgCtxType *ctx, const uint8 *provided)
{
    Hsm_AesCtxType aes;
    uint8 temp[32];
    uint32 i;

    Hsm_AesInit(&aes, ctx->key);
    incV(ctx->v);
    Hsm_AesEncryptBlock(&aes, ctx->v, &temp[0]);
    incV(ctx->v);
    Hsm_AesEncryptBlock(&aes, ctx->v, &temp[16]);
    if (provided != NULL_PTR)
    {
        for (i = 0u; i < 32u; i++)
        {
            temp[i] ^= provided[i];
        }
    }
    for (i = 0u; i < 16u; i++)
    {
        ctx->key[i] = temp[i];
        ctx->v[i] = temp[16u + i];
    }
    Hsm_AesWipe(&aes);
    Hsm_SecureZero(temp, sizeof(temp));
}

Std_ReturnType Hsm_DrbgInstantiate(Hsm_DrbgCtxType *ctx, const uint8 seed[HSM_DRBG_SEEDLEN])
{
    if ((ctx == NULL_PTR) || (seed == NULL_PTR))
    {
        return E_NOT_OK;
    }
    Hsm_SecureZero(ctx->key, sizeof(ctx->key));
    Hsm_SecureZero(ctx->v, sizeof(ctx->v));
    drbgUpdate(ctx, seed);
    ctx->reseedCounter = 1u;
    ctx->instantiated = TRUE;
    return E_OK;
}

Std_ReturnType Hsm_DrbgReseed(Hsm_DrbgCtxType *ctx, const uint8 seed[HSM_DRBG_SEEDLEN])
{
    if ((ctx == NULL_PTR) || (seed == NULL_PTR) || (ctx->instantiated == FALSE))
    {
        return E_NOT_OK;
    }
    drbgUpdate(ctx, seed);
    ctx->reseedCounter = 1u;
    return E_OK;
}

Std_ReturnType Hsm_DrbgGenerate(Hsm_DrbgCtxType *ctx, uint8 *out, uint32 len)
{
    Hsm_AesCtxType aes;
    uint8 blk[16];
    uint32 off = 0u;

    if ((ctx == NULL_PTR) || (out == NULL_PTR) || (ctx->instantiated == FALSE))
    {
        return E_NOT_OK;
    }
    if (ctx->reseedCounter > HSM_DRBG_RESEED_INTERVAL)
    {
        return HSM_DRBG_E_RESEED_REQUIRED;
    }
    Hsm_AesInit(&aes, ctx->key);
    while (off < len)
    {
        uint32 n = ((len - off) > 16u) ? 16u : (len - off);
        uint32 i;
        incV(ctx->v);
        Hsm_AesEncryptBlock(&aes, ctx->v, blk);
        for (i = 0u; i < n; i++)
        {
            out[off + i] = blk[i];
        }
        off += n;
    }
    Hsm_AesWipe(&aes);
    Hsm_SecureZero(blk, sizeof(blk));
    drbgUpdate(ctx, NULL_PTR);   /* backtracking resistance */
    ctx->reseedCounter++;
    return E_OK;
}

void Hsm_DrbgUninstantiate(Hsm_DrbgCtxType *ctx)
{
    Hsm_SecureZero(ctx, sizeof(*ctx));
}

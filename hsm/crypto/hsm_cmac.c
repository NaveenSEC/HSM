/**
 * @file    hsm_cmac.c
 * @brief   AES-CMAC implementation (RFC 4493).
 */
#include "hsm_cmac.h"

static void leftShiftOne(const uint8 in[16], uint8 out[16])
{
    uint8 overflow = 0u;
    sint32 i;
    for (i = 15; i >= 0; i--)
    {
        uint8 b = in[i];
        out[i] = (uint8)((uint8)(b << 1) | overflow);
        overflow = (uint8)(b >> 7);
    }
}

static void generateSubkeys(Hsm_CmacCtxType *ctx)
{
    uint8 L[16] = { 0u };
    uint8 msb;

    Hsm_AesEncryptBlock(&ctx->aes, L, L);
    msb = (uint8)(L[0] & 0x80u);
    leftShiftOne(L, ctx->k1);
    if (msb != 0u)
    {
        ctx->k1[15] ^= 0x87u;
    }
    msb = (uint8)(ctx->k1[0] & 0x80u);
    leftShiftOne(ctx->k1, ctx->k2);
    if (msb != 0u)
    {
        ctx->k2[15] ^= 0x87u;
    }
    Hsm_SecureZero(L, sizeof(L));
}

void Hsm_CmacStart(Hsm_CmacCtxType *ctx, const uint8 key[16])
{
    uint8 i;
    Hsm_AesInit(&ctx->aes, key);
    generateSubkeys(ctx);
    for (i = 0u; i < 16u; i++)
    {
        ctx->x[i] = 0u;
        ctx->buf[i] = 0u;
    }
    ctx->bufLen = 0u;
}

static void processBlock(Hsm_CmacCtxType *ctx, const uint8 blk[16])
{
    uint8 i;
    for (i = 0u; i < 16u; i++)
    {
        ctx->x[i] ^= blk[i];
    }
    Hsm_AesEncryptBlock(&ctx->aes, ctx->x, ctx->x);
}

void Hsm_CmacUpdate(Hsm_CmacCtxType *ctx, const uint8 *data, uint32 len)
{
    uint32 i = 0u;

    /* The last block must be kept back until Finish, therefore a full buffer
     * is only processed once more data arrives. */
    while (i < len)
    {
        if (ctx->bufLen == 16u)
        {
            processBlock(ctx, ctx->buf);
            ctx->bufLen = 0u;
        }
        ctx->buf[ctx->bufLen] = data[i];
        ctx->bufLen++;
        i++;
    }
}

void Hsm_CmacFinish(Hsm_CmacCtxType *ctx, uint8 mac[16])
{
    uint8 last[16];
    uint8 i;

    if (ctx->bufLen == 16u)
    {
        for (i = 0u; i < 16u; i++)
        {
            last[i] = (uint8)(ctx->buf[i] ^ ctx->k1[i]);
        }
    }
    else
    {
        for (i = 0u; i < 16u; i++)
        {
            uint8 b;
            if (i < ctx->bufLen)
            {
                b = ctx->buf[i];
            }
            else if (i == ctx->bufLen)
            {
                b = 0x80u;
            }
            else
            {
                b = 0x00u;
            }
            last[i] = (uint8)(b ^ ctx->k2[i]);
        }
    }
    processBlock(ctx, last);
    for (i = 0u; i < 16u; i++)
    {
        mac[i] = ctx->x[i];
    }
    Hsm_SecureZero(last, sizeof(last));
    Hsm_SecureZero(ctx, sizeof(*ctx));
}

void Hsm_Cmac(const uint8 key[16], const uint8 *data, uint32 len, uint8 mac[16])
{
    Hsm_CmacCtxType ctx;
    Hsm_CmacStart(&ctx, key);
    Hsm_CmacUpdate(&ctx, data, len);
    Hsm_CmacFinish(&ctx, mac);
}

boolean Hsm_CompareBits(const uint8 *a, const uint8 *b, uint32 nBits)
{
    uint32 fullBytes = nBits / 8u;
    uint32 remBits = nBits % 8u;
    uint8 diff = 0u;
    uint32 i;

    for (i = 0u; i < fullBytes; i++)
    {
        diff |= (uint8)(a[i] ^ b[i]);
    }
    if (remBits != 0u)
    {
        uint8 mask = (uint8)(0xFFu << (8u - remBits));
        diff |= (uint8)((a[fullBytes] ^ b[fullBytes]) & mask);
    }
    return (diff == 0u) ? TRUE : FALSE;
}

boolean Hsm_CmacVerify(const uint8 key[16], const uint8 *data, uint32 len,
                       const uint8 *mac, uint32 macBits)
{
    uint8 calc[16];
    boolean ok;

    if ((macBits == 0u) || (macBits > 128u))
    {
        return FALSE;
    }
    Hsm_Cmac(key, data, len, calc);
    ok = Hsm_CompareBits(calc, mac, macBits);
    Hsm_SecureZero(calc, sizeof(calc));
    return ok;
}

/**
 * @file    hsm_sha256.c
 * @brief   SHA-256 / HMAC-SHA-256 implementation.
 */
#include "hsm_sha256.h"
#include "hsm_aes.h"   /* Hsm_SecureZero */

static const uint32 K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32u - (n))))

static void compress(uint32 st[8], const uint8 blk[64])
{
    uint32 w[64];
    uint32 a, b, c, d, e, f, g, h;
    uint32 i;

    for (i = 0u; i < 16u; i++)
    {
        w[i] = ((uint32)blk[i * 4u] << 24) | ((uint32)blk[i * 4u + 1u] << 16) |
               ((uint32)blk[i * 4u + 2u] << 8) | (uint32)blk[i * 4u + 3u];
    }
    for (i = 16u; i < 64u; i++)
    {
        uint32 s0 = ROTR(w[i - 15u], 7u) ^ ROTR(w[i - 15u], 18u) ^ (w[i - 15u] >> 3);
        uint32 s1 = ROTR(w[i - 2u], 17u) ^ ROTR(w[i - 2u], 19u) ^ (w[i - 2u] >> 10);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }
    a = st[0]; b = st[1]; c = st[2]; d = st[3];
    e = st[4]; f = st[5]; g = st[6]; h = st[7];
    for (i = 0u; i < 64u; i++)
    {
        uint32 S1 = ROTR(e, 6u) ^ ROTR(e, 11u) ^ ROTR(e, 25u);
        uint32 ch = (e & f) ^ ((~e) & g);
        uint32 t1 = h + S1 + ch + K[i] + w[i];
        uint32 S0 = ROTR(a, 2u) ^ ROTR(a, 13u) ^ ROTR(a, 22u);
        uint32 mj = (a & b) ^ (a & c) ^ (b & c);
        uint32 t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
    Hsm_SecureZero(w, sizeof(w));
}

void Hsm_Sha256Start(Hsm_Sha256CtxType *ctx)
{
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
    ctx->totalLen = 0u;
    ctx->bufLen = 0u;
}

void Hsm_Sha256Update(Hsm_Sha256CtxType *ctx, const uint8 *data, uint32 len)
{
    uint32 i;
    for (i = 0u; i < len; i++)
    {
        ctx->buf[ctx->bufLen++] = data[i];
        if (ctx->bufLen == 64u)
        {
            compress(ctx->state, ctx->buf);
            ctx->bufLen = 0u;
        }
    }
    ctx->totalLen += len;
}

void Hsm_Sha256Finish(Hsm_Sha256CtxType *ctx, uint8 digest[32])
{
    uint64 bits = ctx->totalLen * 8u;
    uint32 i;

    ctx->buf[ctx->bufLen++] = 0x80u;
    if (ctx->bufLen > 56u)
    {
        while (ctx->bufLen < 64u)
        {
            ctx->buf[ctx->bufLen++] = 0u;
        }
        compress(ctx->state, ctx->buf);
        ctx->bufLen = 0u;
    }
    while (ctx->bufLen < 56u)
    {
        ctx->buf[ctx->bufLen++] = 0u;
    }
    for (i = 0u; i < 8u; i++)
    {
        ctx->buf[56u + i] = (uint8)(bits >> (56u - (8u * i)));
    }
    compress(ctx->state, ctx->buf);
    for (i = 0u; i < 8u; i++)
    {
        digest[i * 4u]      = (uint8)(ctx->state[i] >> 24);
        digest[i * 4u + 1u] = (uint8)(ctx->state[i] >> 16);
        digest[i * 4u + 2u] = (uint8)(ctx->state[i] >> 8);
        digest[i * 4u + 3u] = (uint8)(ctx->state[i]);
    }
    Hsm_SecureZero(ctx, sizeof(*ctx));
}

void Hsm_Sha256(const uint8 *data, uint32 len, uint8 digest[32])
{
    Hsm_Sha256CtxType ctx;
    Hsm_Sha256Start(&ctx);
    Hsm_Sha256Update(&ctx, data, len);
    Hsm_Sha256Finish(&ctx, digest);
}

void Hsm_HmacSha256Start(Hsm_HmacCtxType *ctx, const uint8 *key, uint32 keyLen)
{
    uint8 k[64] = { 0u };
    uint8 ipad[64];
    uint32 i;

    if (keyLen > 64u)
    {
        Hsm_Sha256(key, keyLen, k);
    }
    else
    {
        for (i = 0u; i < keyLen; i++)
        {
            k[i] = key[i];
        }
    }
    for (i = 0u; i < 64u; i++)
    {
        ipad[i] = (uint8)(k[i] ^ 0x36u);
        ctx->okeyPad[i] = (uint8)(k[i] ^ 0x5cu);
    }
    Hsm_Sha256Start(&ctx->inner);
    Hsm_Sha256Update(&ctx->inner, ipad, 64u);
    Hsm_SecureZero(k, sizeof(k));
    Hsm_SecureZero(ipad, sizeof(ipad));
}

void Hsm_HmacSha256Update(Hsm_HmacCtxType *ctx, const uint8 *data, uint32 len)
{
    Hsm_Sha256Update(&ctx->inner, data, len);
}

void Hsm_HmacSha256Finish(Hsm_HmacCtxType *ctx, uint8 mac[32])
{
    uint8 ih[32];
    Hsm_Sha256CtxType outer;

    Hsm_Sha256Finish(&ctx->inner, ih);
    Hsm_Sha256Start(&outer);
    Hsm_Sha256Update(&outer, ctx->okeyPad, 64u);
    Hsm_Sha256Update(&outer, ih, 32u);
    Hsm_Sha256Finish(&outer, mac);
    Hsm_SecureZero(ih, sizeof(ih));
    Hsm_SecureZero(ctx, sizeof(*ctx));
}

void Hsm_HmacSha256(const uint8 *key, uint32 keyLen, const uint8 *data, uint32 len, uint8 mac[32])
{
    Hsm_HmacCtxType ctx;
    Hsm_HmacSha256Start(&ctx, key, keyLen);
    Hsm_HmacSha256Update(&ctx, data, len);
    Hsm_HmacSha256Finish(&ctx, mac);
}

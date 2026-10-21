/**
 * @file    hsm_aes.c
 * @brief   Portable AES-128 implementation (FIPS-197).
 *
 * NOTE: Table based S-box lookup. On a real HSM core this is replaced by the
 *       hardware AES accelerator; the software version is used for host
 *       simulation and as a reference model.
 */
#include "hsm_aes.h"

static const uint8 sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8 inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8 rcon[11] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };

static uint8 xtime(uint8 x)
{
    return (uint8)((uint8)(x << 1) ^ (uint8)(((x >> 7) & 1u) * 0x1bu));
}

static uint8 gmul(uint8 a, uint8 b)
{
    uint8 p = 0u;
    uint8 i;
    for (i = 0u; i < 8u; i++)
    {
        p ^= (uint8)(((uint8)(-(sint8)(b & 1u))) & a);
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

void Hsm_AesInit(Hsm_AesCtxType *ctx, const uint8 key[HSM_AES128_KEY_SIZE])
{
    uint32 i;
    uint8 *w = ctx->roundKeys;
    uint8 t[4];

    for (i = 0u; i < 16u; i++)
    {
        w[i] = key[i];
    }
    for (i = 4u; i < 44u; i++)
    {
        t[0] = w[(i - 1u) * 4u + 0u];
        t[1] = w[(i - 1u) * 4u + 1u];
        t[2] = w[(i - 1u) * 4u + 2u];
        t[3] = w[(i - 1u) * 4u + 3u];
        if ((i % 4u) == 0u)
        {
            uint8 tmp = t[0];
            t[0] = (uint8)(sbox[t[1]] ^ rcon[i / 4u]);
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[tmp];
        }
        w[i * 4u + 0u] = (uint8)(w[(i - 4u) * 4u + 0u] ^ t[0]);
        w[i * 4u + 1u] = (uint8)(w[(i - 4u) * 4u + 1u] ^ t[1]);
        w[i * 4u + 2u] = (uint8)(w[(i - 4u) * 4u + 2u] ^ t[2]);
        w[i * 4u + 3u] = (uint8)(w[(i - 4u) * 4u + 3u] ^ t[3]);
    }
}

static void addRoundKey(uint8 s[16], const uint8 *rk)
{
    uint8 i;
    for (i = 0u; i < 16u; i++)
    {
        s[i] ^= rk[i];
    }
}

static void subBytes(uint8 s[16])
{
    uint8 i;
    for (i = 0u; i < 16u; i++)
    {
        s[i] = sbox[s[i]];
    }
}

static void invSubBytes(uint8 s[16])
{
    uint8 i;
    for (i = 0u; i < 16u; i++)
    {
        s[i] = inv_sbox[s[i]];
    }
}

/* state is column major: s[c*4 + r] */
static void shiftRows(uint8 s[16])
{
    uint8 t;
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void invShiftRows(uint8 s[16])
{
    uint8 t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void mixColumns(uint8 s[16])
{
    uint8 c;
    for (c = 0u; c < 4u; c++)
    {
        uint8 *col = &s[c * 4u];
        uint8 a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        col[1] = (uint8)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        col[2] = (uint8)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        col[3] = (uint8)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

static void invMixColumns(uint8 s[16])
{
    uint8 c;
    for (c = 0u; c < 4u; c++)
    {
        uint8 *col = &s[c * 4u];
        uint8 a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8)(gmul(a0, 14u) ^ gmul(a1, 11u) ^ gmul(a2, 13u) ^ gmul(a3, 9u));
        col[1] = (uint8)(gmul(a0, 9u)  ^ gmul(a1, 14u) ^ gmul(a2, 11u) ^ gmul(a3, 13u));
        col[2] = (uint8)(gmul(a0, 13u) ^ gmul(a1, 9u)  ^ gmul(a2, 14u) ^ gmul(a3, 11u));
        col[3] = (uint8)(gmul(a0, 11u) ^ gmul(a1, 13u) ^ gmul(a2, 9u)  ^ gmul(a3, 14u));
    }
}

void Hsm_AesEncryptBlock(const Hsm_AesCtxType *ctx, const uint8 in[16], uint8 out[16])
{
    uint8 s[16];
    uint8 r;
    uint8 i;

    for (i = 0u; i < 16u; i++)
    {
        s[i] = in[i];
    }
    addRoundKey(s, &ctx->roundKeys[0]);
    for (r = 1u; r < HSM_AES128_ROUNDS; r++)
    {
        subBytes(s);
        shiftRows(s);
        mixColumns(s);
        addRoundKey(s, &ctx->roundKeys[r * 16u]);
    }
    subBytes(s);
    shiftRows(s);
    addRoundKey(s, &ctx->roundKeys[HSM_AES128_ROUNDS * 16u]);
    for (i = 0u; i < 16u; i++)
    {
        out[i] = s[i];
    }
    Hsm_SecureZero(s, sizeof(s));
}

void Hsm_AesDecryptBlock(const Hsm_AesCtxType *ctx, const uint8 in[16], uint8 out[16])
{
    uint8 s[16];
    uint8 r;
    uint8 i;

    for (i = 0u; i < 16u; i++)
    {
        s[i] = in[i];
    }
    addRoundKey(s, &ctx->roundKeys[HSM_AES128_ROUNDS * 16u]);
    for (r = (uint8)(HSM_AES128_ROUNDS - 1u); r > 0u; r--)
    {
        invShiftRows(s);
        invSubBytes(s);
        addRoundKey(s, &ctx->roundKeys[r * 16u]);
        invMixColumns(s);
    }
    invShiftRows(s);
    invSubBytes(s);
    addRoundKey(s, &ctx->roundKeys[0]);
    for (i = 0u; i < 16u; i++)
    {
        out[i] = s[i];
    }
    Hsm_SecureZero(s, sizeof(s));
}

void Hsm_AesWipe(Hsm_AesCtxType *ctx)
{
    Hsm_SecureZero(ctx, sizeof(*ctx));
}

Std_ReturnType Hsm_AesEcbEncrypt(const uint8 key[16], const uint8 *in, uint32 len, uint8 *out)
{
    Hsm_AesCtxType ctx;
    uint32 off;

    if ((len % HSM_AES_BLOCK_SIZE) != 0u)
    {
        return E_NOT_OK;
    }
    Hsm_AesInit(&ctx, key);
    for (off = 0u; off < len; off += HSM_AES_BLOCK_SIZE)
    {
        Hsm_AesEncryptBlock(&ctx, &in[off], &out[off]);
    }
    Hsm_AesWipe(&ctx);
    return E_OK;
}

Std_ReturnType Hsm_AesEcbDecrypt(const uint8 key[16], const uint8 *in, uint32 len, uint8 *out)
{
    Hsm_AesCtxType ctx;
    uint32 off;

    if ((len % HSM_AES_BLOCK_SIZE) != 0u)
    {
        return E_NOT_OK;
    }
    Hsm_AesInit(&ctx, key);
    for (off = 0u; off < len; off += HSM_AES_BLOCK_SIZE)
    {
        Hsm_AesDecryptBlock(&ctx, &in[off], &out[off]);
    }
    Hsm_AesWipe(&ctx);
    return E_OK;
}

Std_ReturnType Hsm_AesCbcEncrypt(const uint8 key[16], const uint8 iv[16], const uint8 *in, uint32 len, uint8 *out)
{
    Hsm_AesCtxType ctx;
    uint8 chain[16];
    uint8 blk[16];
    uint32 off;
    uint8 i;

    if ((len % HSM_AES_BLOCK_SIZE) != 0u)
    {
        return E_NOT_OK;
    }
    Hsm_AesInit(&ctx, key);
    for (i = 0u; i < 16u; i++)
    {
        chain[i] = iv[i];
    }
    for (off = 0u; off < len; off += HSM_AES_BLOCK_SIZE)
    {
        for (i = 0u; i < 16u; i++)
        {
            blk[i] = (uint8)(in[off + i] ^ chain[i]);
        }
        Hsm_AesEncryptBlock(&ctx, blk, &out[off]);
        for (i = 0u; i < 16u; i++)
        {
            chain[i] = out[off + i];
        }
    }
    Hsm_AesWipe(&ctx);
    Hsm_SecureZero(blk, sizeof(blk));
    return E_OK;
}

Std_ReturnType Hsm_AesCbcDecrypt(const uint8 key[16], const uint8 iv[16], const uint8 *in, uint32 len, uint8 *out)
{
    Hsm_AesCtxType ctx;
    uint8 chain[16];
    uint8 next[16];
    uint8 blk[16];
    uint32 off;
    uint8 i;

    if ((len % HSM_AES_BLOCK_SIZE) != 0u)
    {
        return E_NOT_OK;
    }
    Hsm_AesInit(&ctx, key);
    for (i = 0u; i < 16u; i++)
    {
        chain[i] = iv[i];
    }
    for (off = 0u; off < len; off += HSM_AES_BLOCK_SIZE)
    {
        for (i = 0u; i < 16u; i++)
        {
            next[i] = in[off + i];   /* supports in-place */
        }
        Hsm_AesDecryptBlock(&ctx, &in[off], blk);
        for (i = 0u; i < 16u; i++)
        {
            out[off + i] = (uint8)(blk[i] ^ chain[i]);
            chain[i] = next[i];
        }
    }
    Hsm_AesWipe(&ctx);
    Hsm_SecureZero(blk, sizeof(blk));
    return E_OK;
}

void Hsm_SecureZero(void *p, uint32 len)
{
    volatile uint8 *v = (volatile uint8 *)p;
    while (len-- > 0u)
    {
        *v++ = 0u;
    }
}

boolean Hsm_ConstTimeEqual(const uint8 *a, const uint8 *b, uint32 len)
{
    uint8 diff = 0u;
    uint32 i;
    for (i = 0u; i < len; i++)
    {
        diff |= (uint8)(a[i] ^ b[i]);
    }
    return (diff == 0u) ? TRUE : FALSE;
}

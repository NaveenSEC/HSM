/**
 * @file    hsm_sha256.h
 * @brief   SHA-256 (FIPS 180-4) and HMAC-SHA-256 (RFC 2104).
 */
#ifndef HSM_SHA256_H
#define HSM_SHA256_H

#include "Std_Types.h"

#define HSM_SHA256_DIGEST_SIZE 32u
#define HSM_SHA256_BLOCK_SIZE  64u

typedef struct
{
    uint32 state[8];
    uint64 totalLen;
    uint8  buf[64];
    uint32 bufLen;
} Hsm_Sha256CtxType;

void Hsm_Sha256Start(Hsm_Sha256CtxType *ctx);
void Hsm_Sha256Update(Hsm_Sha256CtxType *ctx, const uint8 *data, uint32 len);
void Hsm_Sha256Finish(Hsm_Sha256CtxType *ctx, uint8 digest[32]);
void Hsm_Sha256(const uint8 *data, uint32 len, uint8 digest[32]);

typedef struct
{
    Hsm_Sha256CtxType inner;
    uint8 okeyPad[64];
} Hsm_HmacCtxType;

void Hsm_HmacSha256Start(Hsm_HmacCtxType *ctx, const uint8 *key, uint32 keyLen);
void Hsm_HmacSha256Update(Hsm_HmacCtxType *ctx, const uint8 *data, uint32 len);
void Hsm_HmacSha256Finish(Hsm_HmacCtxType *ctx, uint8 mac[32]);
void Hsm_HmacSha256(const uint8 *key, uint32 keyLen, const uint8 *data, uint32 len, uint8 mac[32]);

#endif /* HSM_SHA256_H */

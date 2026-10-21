/**
 * @file    hsm_cmac.h
 * @brief   AES-CMAC (NIST SP 800-38B / RFC 4493) with streaming support.
 */
#ifndef HSM_CMAC_H
#define HSM_CMAC_H

#include "hsm_aes.h"

#define HSM_CMAC_SIZE 16u

typedef struct
{
    Hsm_AesCtxType aes;
    uint8  k1[16];
    uint8  k2[16];
    uint8  x[16];       /* running chain value                      */
    uint8  buf[16];     /* pending (possibly last) block            */
    uint32 bufLen;      /* number of bytes in buf                   */
} Hsm_CmacCtxType;

void Hsm_CmacStart(Hsm_CmacCtxType *ctx, const uint8 key[16]);
void Hsm_CmacUpdate(Hsm_CmacCtxType *ctx, const uint8 *data, uint32 len);
void Hsm_CmacFinish(Hsm_CmacCtxType *ctx, uint8 mac[16]);

void Hsm_Cmac(const uint8 key[16], const uint8 *data, uint32 len, uint8 mac[16]);

/**
 * @brief Verify a (possibly truncated) CMAC. macBits is the length of the
 *        received MAC in bits (AUTOSAR MacVerify semantics).
 */
boolean Hsm_CmacVerify(const uint8 key[16], const uint8 *data, uint32 len,
                       const uint8 *mac, uint32 macBits);

/** @brief Compare the first nBits bits of two buffers in constant time. */
boolean Hsm_CompareBits(const uint8 *a, const uint8 *b, uint32 nBits);

#endif /* HSM_CMAC_H */

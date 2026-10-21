/**
 * @file    hsm_aes.h
 * @brief   AES-128 block cipher (FIPS-197) and ECB/CBC modes used by the HSM firmware.
 */
#ifndef HSM_AES_H
#define HSM_AES_H

#include "Std_Types.h"

#define HSM_AES_BLOCK_SIZE   16u
#define HSM_AES128_KEY_SIZE  16u
#define HSM_AES128_ROUNDS    10u

typedef struct
{
    uint8 roundKeys[(HSM_AES128_ROUNDS + 1u) * HSM_AES_BLOCK_SIZE];
} Hsm_AesCtxType;

void Hsm_AesInit(Hsm_AesCtxType *ctx, const uint8 key[HSM_AES128_KEY_SIZE]);
void Hsm_AesEncryptBlock(const Hsm_AesCtxType *ctx, const uint8 in[16], uint8 out[16]);
void Hsm_AesDecryptBlock(const Hsm_AesCtxType *ctx, const uint8 in[16], uint8 out[16]);
void Hsm_AesWipe(Hsm_AesCtxType *ctx);

/* len must be a multiple of 16 */
Std_ReturnType Hsm_AesEcbEncrypt(const uint8 key[16], const uint8 *in, uint32 len, uint8 *out);
Std_ReturnType Hsm_AesEcbDecrypt(const uint8 key[16], const uint8 *in, uint32 len, uint8 *out);
Std_ReturnType Hsm_AesCbcEncrypt(const uint8 key[16], const uint8 iv[16], const uint8 *in, uint32 len, uint8 *out);
Std_ReturnType Hsm_AesCbcDecrypt(const uint8 key[16], const uint8 iv[16], const uint8 *in, uint32 len, uint8 *out);

/* Secure helpers */
void    Hsm_SecureZero(void *p, uint32 len);
boolean Hsm_ConstTimeEqual(const uint8 *a, const uint8 *b, uint32 len);

#endif /* HSM_AES_H */

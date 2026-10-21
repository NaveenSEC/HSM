/**
 * @file    Csm_Cfg.h
 * @brief   Crypto Service Manager configuration (jobs, keys, queues).
 */
#ifndef CSM_CFG_H
#define CSM_CFG_H

#include "CryIf_Cfg.h"

#define CSM_DEV_ERROR_DETECT          STD_ON
#define CSM_QUEUE_SIZE                8u

/* ---- CSM keys (CsmKeyId -> CryIfKeyId 1:1) ---- */
#define CSM_NUM_KEYS                  CRYIF_NUM_KEYS
#define CSM_KEY_MASTER_ECU            CRYPTO_KEY_MASTER_ECU
#define CSM_KEY_BOOT_MAC_KEY          CRYPTO_KEY_BOOT_MAC_KEY
#define CSM_KEY_FLASH_VERIFY          CRYPTO_KEY_FLASH_VERIFY
#define CSM_KEY_DIAG_SECACCESS        CRYPTO_KEY_DIAG_SECACCESS
#define CSM_KEY_SECOC                 CRYPTO_KEY_SECOC
#define CSM_KEY_APP_CIPHER            CRYPTO_KEY_APP_CIPHER
#define CSM_KEY_HMAC                  CRYPTO_KEY_HMAC
#define CSM_KEY_RAM                   CRYPTO_KEY_RAM

/* ---- CSM jobs ---- */
#define CSM_JOB_FLASH_MAC_GENERATE    0u   /* CMAC, sync                 */
#define CSM_JOB_FLASH_MAC_VERIFY      1u   /* CMAC, sync, streaming      */
#define CSM_JOB_SECACCESS_MAC_GEN     2u   /* UDS 0x27 key calculation   */
#define CSM_JOB_SECACCESS_MAC_VERIFY  3u   /* UDS 0x27 key verification  */
#define CSM_JOB_SECOC_MAC_GENERATE    4u
#define CSM_JOB_SECOC_MAC_VERIFY      5u
#define CSM_JOB_MAC_GENERATE_ASYNC    6u   /* CMAC, async + callback     */
#define CSM_JOB_MAC_VERIFY_ASYNC      7u
#define CSM_JOB_HASH_SHA256           8u
#define CSM_JOB_HASH_SHA256_ASYNC     9u
#define CSM_JOB_ENCRYPT_AES_CBC       10u
#define CSM_JOB_DECRYPT_AES_CBC       11u
#define CSM_JOB_ENCRYPT_AES_ECB       12u
#define CSM_JOB_DECRYPT_AES_ECB       13u
#define CSM_JOB_RANDOM_GENERATE       14u
#define CSM_JOB_HMAC_GENERATE         15u
#define CSM_JOB_HMAC_VERIFY           16u
#define CSM_JOB_RAMKEY_MAC_GENERATE   17u
#define CSM_NUM_JOBS                  18u

#endif

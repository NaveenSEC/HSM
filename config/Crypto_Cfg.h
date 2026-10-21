/**
 * @file    Crypto_Cfg.h
 * @brief   Pre-compile configuration of the HSM Crypto Driver.
 */
#ifndef CRYPTO_CFG_H
#define CRYPTO_CFG_H

#include "Std_Types.h"

#define CRYPTO_DEV_ERROR_DETECT       STD_ON
#define CRYPTO_VERSION_INFO_API       STD_ON
#define CRYPTO_INSTANCE_ID            0u

/* Crypto driver objects (independent HSM channels) */
#define CRYPTO_NUM_DRIVER_OBJECTS     4u
#define CRYPTO_DRIVER_OBJECT_SYM      0u   /* MAC / cipher                 */
#define CRYPTO_DRIVER_OBJECT_HASH     1u   /* hash                         */
#define CRYPTO_DRIVER_OBJECT_RNG      2u   /* random                       */
#define CRYPTO_DRIVER_OBJECT_SECOC    3u   /* SecOC dedicated channel      */

#define CRYPTO_QUEUE_SIZE             8u   /* async jobs per driver object */
#define CRYPTO_HSM_TIMEOUT_LOOPS      1000u

/* Crypto keys (CryptoKeyId) */
#define CRYPTO_NUM_KEYS               8u
#define CRYPTO_KEY_MASTER_ECU         0u
#define CRYPTO_KEY_BOOT_MAC_KEY       1u
#define CRYPTO_KEY_FLASH_VERIFY       2u   /* SW package authenticity (CMAC) */
#define CRYPTO_KEY_DIAG_SECACCESS     3u   /* UDS 0x27 seed/key (CMAC)      */
#define CRYPTO_KEY_SECOC              4u   /* SecOC PDU authentication      */
#define CRYPTO_KEY_APP_CIPHER         5u   /* AES encrypt/decrypt           */
#define CRYPTO_KEY_HMAC               6u   /* HMAC-SHA-256 (extended slot)  */
#define CRYPTO_KEY_RAM                7u   /* SHE RAM key                   */

#endif /* CRYPTO_CFG_H */

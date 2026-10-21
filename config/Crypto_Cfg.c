/**
 * @file    Crypto_Cfg.c
 * @brief   Crypto driver key configuration: CryptoKey -> HSM key slot.
 */
#include "Crypto.h"
#include "Hsm_Types.h"

const Crypto_KeyConfigType Crypto_KeyConfig[CRYPTO_NUM_KEYS] =
{
    /* CRYPTO_KEY_MASTER_ECU   */ { HSM_KEY_MASTER_ECU_KEY },
    /* CRYPTO_KEY_BOOT_MAC_KEY */ { HSM_KEY_BOOT_MAC_KEY },
    /* CRYPTO_KEY_FLASH_VERIFY */ { HSM_KEY_1 },
    /* CRYPTO_KEY_DIAG_SECACCESS*/{ HSM_KEY_2 },
    /* CRYPTO_KEY_SECOC        */ { HSM_KEY_3 },
    /* CRYPTO_KEY_APP_CIPHER   */ { HSM_KEY_4 },
    /* CRYPTO_KEY_HMAC         */ { HSM_KEY_EXT_0 },
    /* CRYPTO_KEY_RAM          */ { HSM_RAM_KEY }
};

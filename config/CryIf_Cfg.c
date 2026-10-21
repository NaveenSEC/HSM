/**
 * @file    CryIf_Cfg.c
 */
#include "CryIf.h"

const CryIf_ChannelConfigType CryIf_ChannelConfig[CRYIF_NUM_CHANNELS] =
{
    { CRYPTO_DRIVER_OBJECT_SYM   },
    { CRYPTO_DRIVER_OBJECT_HASH  },
    { CRYPTO_DRIVER_OBJECT_RNG   },
    { CRYPTO_DRIVER_OBJECT_SECOC }
};

const CryIf_KeyConfigType CryIf_KeyConfig[CRYIF_NUM_KEYS] =
{
    { CRYPTO_KEY_MASTER_ECU },
    { CRYPTO_KEY_BOOT_MAC_KEY },
    { CRYPTO_KEY_FLASH_VERIFY },
    { CRYPTO_KEY_DIAG_SECACCESS },
    { CRYPTO_KEY_SECOC },
    { CRYPTO_KEY_APP_CIPHER },
    { CRYPTO_KEY_HMAC },
    { CRYPTO_KEY_RAM }
};

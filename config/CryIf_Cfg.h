/**
 * @file    CryIf_Cfg.h
 * @brief   Crypto Interface configuration.
 */
#ifndef CRYIF_CFG_H
#define CRYIF_CFG_H

#include "Crypto_Cfg.h"

#define CRYIF_DEV_ERROR_DETECT  STD_ON

/* CryIf channels -> Crypto driver objects */
#define CRYIF_NUM_CHANNELS      4u
#define CRYIF_CHANNEL_SYM       0u
#define CRYIF_CHANNEL_HASH      1u
#define CRYIF_CHANNEL_RNG       2u
#define CRYIF_CHANNEL_SECOC     3u

/* CryIf keys -> Crypto keys (1:1 in this configuration) */
#define CRYIF_NUM_KEYS          CRYPTO_NUM_KEYS

#endif

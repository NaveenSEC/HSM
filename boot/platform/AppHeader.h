/**
 * @file    AppHeader.h
 * @brief   Application image header (first APP_HEADER_SIZE bytes of the app area).
 *
 *  off  size  field
 *    0     4  magic "APPH"
 *    4     4  header version
 *    8     4  software version (anti roll-back, compared to HSM counter)
 *   12     4  body size in bytes
 *   16     4  entry offset
 *   20    12  reserved (0)
 *   32    32  SHA-256 digest of body
 *   64    16  AES-CMAC over bytes [0..63] with the FLASH_VERIFY key
 *   80    48  padding (0xFF)
 */
#ifndef APPHEADER_H
#define APPHEADER_H

#include "Std_Types.h"

#define APPHDR_MAGIC             0x41505048u   /* "APPH" */
#define APPHDR_VERSION           1u
#define APPHDR_OFF_MAGIC         0u
#define APPHDR_OFF_HDRVER        4u
#define APPHDR_OFF_SWVER         8u
#define APPHDR_OFF_SIZE          12u
#define APPHDR_OFF_ENTRY         16u
#define APPHDR_OFF_DIGEST        32u
#define APPHDR_OFF_MAC           64u
#define APPHDR_SIGNED_LEN        64u
#define APPHDR_MAC_LEN           16u

/* HSM monotonic counter used for application anti roll-back */
#define APP_ROLLBACK_COUNTER_ID  0u

typedef struct
{
    uint32 magic;
    uint32 headerVersion;
    uint32 swVersion;
    uint32 size;
    uint32 entry;
    const uint8 *digest;
    const uint8 *mac;
} AppHeader_Type;

static inline uint32 AppHeader_Get32(const uint8 *p)
{
    return ((uint32)p[0] << 24) | ((uint32)p[1] << 16) | ((uint32)p[2] << 8) | (uint32)p[3];
}

static inline void AppHeader_Put32(uint8 *p, uint32 v)
{
    p[0] = (uint8)(v >> 24);
    p[1] = (uint8)(v >> 16);
    p[2] = (uint8)(v >> 8);
    p[3] = (uint8)v;
}

static inline void AppHeader_Parse(const uint8 *raw, AppHeader_Type *h)
{
    h->magic = AppHeader_Get32(&raw[APPHDR_OFF_MAGIC]);
    h->headerVersion = AppHeader_Get32(&raw[APPHDR_OFF_HDRVER]);
    h->swVersion = AppHeader_Get32(&raw[APPHDR_OFF_SWVER]);
    h->size = AppHeader_Get32(&raw[APPHDR_OFF_SIZE]);
    h->entry = AppHeader_Get32(&raw[APPHDR_OFF_ENTRY]);
    h->digest = &raw[APPHDR_OFF_DIGEST];
    h->mac = &raw[APPHDR_OFF_MAC];
}

#endif

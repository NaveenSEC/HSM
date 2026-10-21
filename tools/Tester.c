/**
 * @file    Tester.c
 */
#include <stdio.h>
#include "Tester.h"
#include "Backend.h"
#include "Ecu.h"
#include "AppHeader.h"
#include "MemMap_Layout.h"
#include "Bootloader.h"

Tester_InfoType Tester_Info;

static uint8 Tester_Resp[BL_MAX_BLOCK_LEN + 16u];

static void dump(const char *dir, const uint8 *p, uint32 n)
{
    uint32 i;
    printf("      %s ", dir);
    for (i = 0u; (i < n) && (i < 20u); i++)
    {
        printf("%02X ", p[i]);
    }
    if (n > 20u)
    {
        printf("... (%u bytes)", (unsigned)n);
    }
    printf("\n");
}

uint32 Tester_Request(const uint8 *req, uint32 len, uint8 *resp)
{
    uint32 n;
    Tester_Info.requests++;
    if (Tester_Info.verbose == TRUE)
    {
        dump("Tx:", req, len);
    }
    n = Ecu_Diag(req, len, resp, BL_MAX_BLOCK_LEN + 16u);
    if (Tester_Info.verbose == TRUE)
    {
        dump("Rx:", resp, n);
    }
    Tester_Info.lastNrc = ((n >= 3u) && (resp[0] == 0x7Fu)) ? resp[2] : 0u;
    return n;
}

Tester_ResultType Tester_Unlock(const uint8 diagKey[16])
{
    uint8 req[2u + BL_SEED_LEN];
    uint8 key[16];
    uint32 n, i;

    req[0] = 0x27u; req[1] = 0x11u;
    n = Tester_Request(req, 2u, Tester_Resp);
    if ((n != (2u + BL_SEED_LEN)) || (Tester_Resp[0] != 0x67u))
    {
        return TESTER_SECURITY_FAILED;
    }
    {
        /* ISO 14229: an all-zero seed means the ECU is already unlocked */
        uint8 acc = 0u;
        for (i = 0u; i < BL_SEED_LEN; i++)
        {
            acc |= Tester_Resp[2u + i];
        }
        if (acc == 0u)
        {
            return TESTER_OK;
        }
    }
    Backend_SecurityAccessKey(diagKey, &Tester_Resp[2], BL_SEED_LEN, key);
    req[0] = 0x27u; req[1] = 0x12u;
    for (i = 0u; i < 16u; i++)
    {
        req[2u + i] = key[i];
    }
    n = Tester_Request(req, 18u, Tester_Resp);
    if ((n != 2u) || (Tester_Resp[0] != 0x67u))
    {
        return TESTER_SECURITY_FAILED;
    }
    return TESTER_OK;
}

Tester_ResultType Tester_FlashApplication(const uint8 *image, uint32 len, const uint8 diagKey[16])
{
    static uint8 req[BL_MAX_BLOCK_LEN];
    uint32 n, off, maxData;
    uint8 seq = 1u;
    Tester_ResultType r;

    Tester_Info.checkReason = 0u;

    /* 1. programming session (application jumps to the bootloader) */
    req[0] = 0x10u; req[1] = 0x02u;
    n = Tester_Request(req, 2u, Tester_Resp);
    if ((n < 2u) || (Tester_Resp[0] != 0x50u))
    {
        return TESTER_ENTER_PROG_FAILED;
    }
    if (Ecu_GetState() != ECU_STATE_BOOTLOADER)
    {
        return TESTER_ENTER_PROG_FAILED;
    }
    /* bootloader: confirm programming session */
    n = Tester_Request(req, 2u, Tester_Resp);
    if ((n < 2u) || (Tester_Resp[0] != 0x50u))
    {
        return TESTER_ENTER_PROG_FAILED;
    }

    /* 2. security access */
    r = Tester_Unlock(diagKey);
    if (r != TESTER_OK)
    {
        return r;
    }

    /* 3. erase application area */
    req[0] = 0x31u; req[1] = 0x01u; req[2] = 0xFFu; req[3] = 0x00u; req[4] = 0x44u;
    AppHeader_Put32(&req[5], APP_START);
    AppHeader_Put32(&req[9], APP_SIZE);
    n = Tester_Request(req, 13u, Tester_Resp);
    if ((n != 5u) || (Tester_Resp[0] != 0x71u) || (Tester_Resp[4] != 0x00u))
    {
        return TESTER_ERASE_FAILED;
    }

    /* 4. download */
    req[0] = 0x34u; req[1] = 0x00u; req[2] = 0x44u;
    AppHeader_Put32(&req[3], APP_START);
    AppHeader_Put32(&req[7], len);
    n = Tester_Request(req, 11u, Tester_Resp);
    if ((n != 4u) || (Tester_Resp[0] != 0x74u))
    {
        return TESTER_DOWNLOAD_FAILED;
    }
    maxData = (((uint32)Tester_Resp[2] << 8) | Tester_Resp[3]) - 2u;
    for (off = 0u; off < len; off += maxData)
    {
        uint32 chunk = ((len - off) > maxData) ? maxData : (len - off);
        uint32 i;
        req[0] = 0x36u;
        req[1] = seq;
        for (i = 0u; i < chunk; i++)
        {
            req[2u + i] = image[off + i];
        }
        n = Tester_Request(req, chunk + 2u, Tester_Resp);
        if ((n != 2u) || (Tester_Resp[0] != 0x76u) || (Tester_Resp[1] != seq))
        {
            return TESTER_DOWNLOAD_FAILED;
        }
        seq++;
    }
    req[0] = 0x37u;
    n = Tester_Request(req, 1u, Tester_Resp);
    if ((n != 1u) || (Tester_Resp[0] != 0x77u))
    {
        return TESTER_DOWNLOAD_FAILED;
    }

    /* 5. check programming dependencies (HSM verifies the image) */
    req[0] = 0x31u; req[1] = 0x01u; req[2] = 0xFFu; req[3] = 0x01u;
    n = Tester_Request(req, 4u, Tester_Resp);
    if ((n != 6u) || (Tester_Resp[0] != 0x71u))
    {
        return TESTER_CHECK_FAILED;
    }
    Tester_Info.checkReason = Tester_Resp[5];
    if (Tester_Resp[4] != 0x00u)
    {
        return TESTER_CHECK_FAILED;
    }

    /* 6. reset into the new application */
    req[0] = 0x11u; req[1] = 0x01u;
    n = Tester_Request(req, 2u, Tester_Resp);
    if ((n != 2u) || (Tester_Resp[0] != 0x51u))
    {
        return TESTER_RESET_FAILED;
    }
    return TESTER_OK;
}

const char *Tester_ResultString(Tester_ResultType r)
{
    switch (r)
    {
        case TESTER_OK:                return "OK";
        case TESTER_ENTER_PROG_FAILED: return "ENTER_PROG_FAILED";
        case TESTER_SECURITY_FAILED:   return "SECURITY_FAILED";
        case TESTER_ERASE_FAILED:      return "ERASE_FAILED";
        case TESTER_DOWNLOAD_FAILED:   return "DOWNLOAD_FAILED";
        case TESTER_CHECK_FAILED:      return "CHECK_FAILED";
        case TESTER_RESET_FAILED:      return "RESET_FAILED";
        default:                       return "?";
    }
}

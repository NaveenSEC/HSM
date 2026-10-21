/**
 * @file    Bootloader.c
 * @brief   UDS flash bootloader.
 */
#include "Bootloader.h"
#include "AppHeader.h"
#include "BootData.h"
#include "Fls.h"
#include "ImageVerify.h"
#include "Csm.h"
#include "Crypto_HsmExt.h"

typedef enum
{
    BL_SESSION_DEFAULT     = 0x01,
    BL_SESSION_PROGRAMMING = 0x02,
    BL_SESSION_EXTENDED    = 0x03
} Bl_SessionType;

typedef struct
{
    Bl_SessionType session;
    boolean unlocked;
    boolean seedValid;
    uint8   seed[BL_SEED_LEN];
    uint8   failedAttempts;
    boolean lockedOut;
    boolean erased;
    boolean dlActive;
    uint32  dlAddress;
    uint32  dlRemaining;
    uint8   dlSeq;
    boolean dlComplete;
    boolean resetRequested;
} Bl_StateType;

static Bl_StateType Bl;

/* ------------------------------------------------------------------------ */
static uint32 nrc(uint8 *resp, uint8 sid, uint8 code)
{
    resp[0] = 0x7Fu;
    resp[1] = sid;
    resp[2] = code;
    return 3u;
}

static uint32 rd32(const uint8 *p)
{
    return AppHeader_Get32(p);
}

static void resetSecurity(void)
{
    Bl.unlocked = FALSE;
    Bl.seedValid = FALSE;
}

static void resetDownload(void)
{
    Bl.dlActive = FALSE;
    Bl.dlAddress = 0u;
    Bl.dlRemaining = 0u;
    Bl.dlSeq = 0u;
}

static boolean inAppArea(uint32 addr, uint32 size)
{
    return ((addr >= APP_START) && (size <= APP_SIZE) && ((addr - APP_START) <= (APP_SIZE - size))) ? TRUE : FALSE;
}

/* ------------------------------------------------------------------------ */
static uint32 svcSession(const uint8 *req, uint32 len, uint8 *resp)
{
    uint8 sub;
    if (len != 2u)
    {
        return nrc(resp, 0x10u, UDS_NRC_IMLOIF);
    }
    sub = (uint8)(req[1] & 0x7Fu);
    if ((sub != (uint8)BL_SESSION_DEFAULT) && (sub != (uint8)BL_SESSION_PROGRAMMING) &&
        (sub != (uint8)BL_SESSION_EXTENDED))
    {
        return nrc(resp, 0x10u, UDS_NRC_SFNS);
    }
    /* every session (re-)entry re-locks the ECU and aborts a running download */
    resetSecurity();
    resetDownload();
    Bl.session = (Bl_SessionType)sub;
    if ((req[1] & 0x80u) != 0u)
    {
        return 0u;            /* suppressPosRspMsgIndicationBit */
    }
    resp[0] = 0x50u;
    resp[1] = sub;
    resp[2] = 0x00u; resp[3] = 0x32u;   /* P2   = 50 ms   */
    resp[4] = 0x01u; resp[5] = 0xF4u;   /* P2*  = 5000 ms */
    return 6u;
}

static uint32 svcReset(const uint8 *req, uint32 len, uint8 *resp)
{
    if (len != 2u)
    {
        return nrc(resp, 0x11u, UDS_NRC_IMLOIF);
    }
    if ((req[1] & 0x7Fu) != 0x01u)
    {
        return nrc(resp, 0x11u, UDS_NRC_SFNS);
    }
    Bl.resetRequested = TRUE;
    resp[0] = 0x51u;
    resp[1] = 0x01u;
    return 2u;
}

static uint32 svcReadDid(const uint8 *req, uint32 len, uint8 *resp)
{
    uint16 did;
    if (len != 3u)
    {
        return nrc(resp, 0x22u, UDS_NRC_IMLOIF);
    }
    did = (uint16)(((uint16)req[1] << 8) | req[2]);
    resp[0] = 0x62u;
    resp[1] = req[1];
    resp[2] = req[2];
    switch (did)
    {
        case 0xF180u:
            resp[3] = BL_VERSION_MAJOR;
            resp[4] = BL_VERSION_MINOR;
            resp[5] = BL_VERSION_PATCH;
            return 6u;
        case 0xF181u:
        {
            const uint8 *hdr = Fls_GetPointer(APP_START);
            uint32 v = (rd32(hdr) == APPHDR_MAGIC) ? rd32(&hdr[APPHDR_OFF_SWVER]) : 0u;
            AppHeader_Put32(&resp[3], v);
            return 7u;
        }
        case 0xF18Cu:
        {
            /* UID via SHE CMD_GET_ID */
            static const uint8 challenge[16] = { 0u };
            uint8 id[32];
            uint8 i;
            if (Crypto_Hsm_GetId(challenge, id) != E_OK)
            {
                return nrc(resp, 0x22u, UDS_NRC_CNC);
            }
            for (i = 0u; i < 15u; i++)
            {
                resp[3u + i] = id[i];
            }
            return 18u;
        }
        case 0xFD00u:
        {
            uint8 sreg = 0u;
            Hsm_ErrorType erc = 0u;
            (void)Crypto_Hsm_GetStatus(&sreg, &erc);
            resp[3] = sreg;
            resp[4] = erc;
            return 5u;
        }
        default:
            return nrc(resp, 0x22u, UDS_NRC_ROOR);
    }
}

static uint32 svcSecurityAccess(const uint8 *req, uint32 len, uint8 *resp)
{
    uint8 sub;
    if (len < 2u)
    {
        return nrc(resp, 0x27u, UDS_NRC_IMLOIF);
    }
    if (Bl.session == BL_SESSION_DEFAULT)
    {
        return nrc(resp, 0x27u, UDS_NRC_SNSIAS);
    }
    sub = req[1];
    if (Bl.lockedOut == TRUE)
    {
        return nrc(resp, 0x27u, UDS_NRC_RTDNE);
    }
    if (sub == 0x11u)
    {
        uint32 n = BL_SEED_LEN;
        uint8 i;
        if (len != 2u)
        {
            return nrc(resp, 0x27u, UDS_NRC_IMLOIF);
        }
        resp[0] = 0x67u;
        resp[1] = 0x11u;
        if (Bl.unlocked == TRUE)
        {
            /* already unlocked: zero seed */
            for (i = 0u; i < BL_SEED_LEN; i++)
            {
                resp[2u + i] = 0u;
            }
            return 2u + BL_SEED_LEN;
        }
        if (Csm_RandomGenerate(CSM_JOB_RANDOM_GENERATE, Bl.seed, &n) != E_OK)
        {
            return nrc(resp, 0x27u, UDS_NRC_CNC);
        }
        Bl.seedValid = TRUE;
        for (i = 0u; i < BL_SEED_LEN; i++)
        {
            resp[2u + i] = Bl.seed[i];
        }
        return 2u + BL_SEED_LEN;
    }
    if (sub == 0x12u)
    {
        Crypto_VerifyResultType vr = CRYPTO_E_VER_NOT_OK;
        if (len != (2u + BL_SEED_LEN))
        {
            return nrc(resp, 0x27u, UDS_NRC_IMLOIF);
        }
        if (Bl.seedValid == FALSE)
        {
            return nrc(resp, 0x27u, UDS_NRC_RSE);
        }
        Bl.seedValid = FALSE;   /* a seed can only be used once */
        if (Csm_MacVerify(CSM_JOB_SECACCESS_MAC_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                          Bl.seed, BL_SEED_LEN, &req[2], BL_SEED_LEN * 8u, &vr) != E_OK)
        {
            return nrc(resp, 0x27u, UDS_NRC_CNC);
        }
        if (vr != CRYPTO_E_VER_OK)
        {
            Bl.failedAttempts++;
            if (Bl.failedAttempts >= BL_MAX_ATTEMPTS)
            {
                Bl.lockedOut = TRUE;
                return nrc(resp, 0x27u, UDS_NRC_ENOA);
            }
            return nrc(resp, 0x27u, UDS_NRC_IK);
        }
        Bl.failedAttempts = 0u;
        Bl.unlocked = TRUE;
        resp[0] = 0x67u;
        resp[1] = 0x12u;
        return 2u;
    }
    return nrc(resp, 0x27u, UDS_NRC_SFNS);
}

static uint32 svcRoutine(const uint8 *req, uint32 len, uint8 *resp)
{
    uint16 rid;
    if (len < 4u)
    {
        return nrc(resp, 0x31u, UDS_NRC_IMLOIF);
    }
    if (req[1] != 0x01u)   /* only startRoutine */
    {
        return nrc(resp, 0x31u, UDS_NRC_SFNS);
    }
    rid = (uint16)(((uint16)req[2] << 8) | req[3]);
    if (Bl.session != BL_SESSION_PROGRAMMING)
    {
        return nrc(resp, 0x31u, UDS_NRC_SNSIAS);
    }
    if (Bl.unlocked == FALSE)
    {
        return nrc(resp, 0x31u, UDS_NRC_SAD);
    }
    resp[0] = 0x71u;
    resp[1] = 0x01u;
    resp[2] = req[2];
    resp[3] = req[3];

    if (rid == BL_ROUTINE_ERASE)
    {
        uint32 addr, size;
        /* 31 01 FF00 44 AAAAAAAA SSSSSSSS */
        if ((len != 13u) || (req[4] != 0x44u))
        {
            return nrc(resp, 0x31u, UDS_NRC_IMLOIF);
        }
        addr = rd32(&req[5]);
        size = rd32(&req[9]);
        if ((inAppArea(addr, size) == FALSE) || ((addr % FLS_SECTOR_SIZE) != 0u))
        {
            return nrc(resp, 0x31u, UDS_NRC_ROOR);
        }
        size = ((size + FLS_SECTOR_SIZE - 1u) / FLS_SECTOR_SIZE) * FLS_SECTOR_SIZE;
        if (Fls_Erase(addr, size) != E_OK)
        {
            return nrc(resp, 0x31u, UDS_NRC_GPF);
        }
        Bl.erased = TRUE;
        Bl.dlComplete = FALSE;
        resp[4] = 0x00u;   /* routine status: OK */
        return 5u;
    }
    if (rid == BL_ROUTINE_CHECK_DEPS)
    {
        uint32 swVersion = 0u;
        uint32 minVersion = 0u;
        ImageVerify_ResultType r;
        if (len != 4u)
        {
            return nrc(resp, 0x31u, UDS_NRC_IMLOIF);
        }
        r = ImageVerify_Application(&swVersion);
        if (r == IMGV_OK)
        {
            /* commit anti roll-back counter in the HSM */
            if ((Crypto_Hsm_CounterRead(APP_ROLLBACK_COUNTER_ID, &minVersion) == E_OK) &&
                (swVersion > minVersion))
            {
                (void)Crypto_Hsm_CounterIncrement(APP_ROLLBACK_COUNTER_ID, swVersion);
            }
            (void)BootData_ClearProgrammingRequest();
        }
        resp[4] = (r == IMGV_OK) ? 0x00u : 0x01u;   /* 00 correct, 01 incorrect */
        resp[5] = (uint8)r;                          /* detailed reason          */
        return 6u;
    }
    return nrc(resp, 0x31u, UDS_NRC_ROOR);
}

static uint32 svcRequestDownload(const uint8 *req, uint32 len, uint8 *resp)
{
    uint32 addr, size;
    if (Bl.session != BL_SESSION_PROGRAMMING)
    {
        return nrc(resp, 0x34u, UDS_NRC_SNSIAS);
    }
    if (Bl.unlocked == FALSE)
    {
        return nrc(resp, 0x34u, UDS_NRC_SAD);
    }
    /* 34 dataFormat(00) addrLenFmt(44) addr(4) size(4) */
    if ((len != 11u) || (req[2] != 0x44u))
    {
        return nrc(resp, 0x34u, UDS_NRC_IMLOIF);
    }
    if (req[1] != 0x00u)
    {
        return nrc(resp, 0x34u, UDS_NRC_ROOR);   /* no compression/encryption */
    }
    if ((Bl.dlActive == TRUE) || (Bl.erased == FALSE))
    {
        return nrc(resp, 0x34u, UDS_NRC_CNC);
    }
    addr = rd32(&req[3]);
    size = rd32(&req[7]);
    if ((size == 0u) || (inAppArea(addr, size) == FALSE))
    {
        return nrc(resp, 0x34u, UDS_NRC_ROOR);
    }
    Bl.dlActive = TRUE;
    Bl.dlAddress = addr;
    Bl.dlRemaining = size;
    Bl.dlSeq = 1u;
    resp[0] = 0x74u;
    resp[1] = 0x20u;                               /* 2 byte maxNumberOfBlockLength */
    resp[2] = (uint8)(BL_MAX_BLOCK_LEN >> 8);
    resp[3] = (uint8)(BL_MAX_BLOCK_LEN);
    return 4u;
}

static uint32 svcTransferData(const uint8 *req, uint32 len, uint8 *resp)
{
    uint32 n;
    if (Bl.dlActive == FALSE)
    {
        return nrc(resp, 0x36u, UDS_NRC_RSE);
    }
    if ((len < 3u) || (len > BL_MAX_BLOCK_LEN))
    {
        return nrc(resp, 0x36u, UDS_NRC_IMLOIF);
    }
    if (req[1] != Bl.dlSeq)
    {
        /* repetition of the previous block is acknowledged without writing */
        if (req[1] == (uint8)(Bl.dlSeq - 1u))
        {
            resp[0] = 0x76u;
            resp[1] = req[1];
            return 2u;
        }
        return nrc(resp, 0x36u, UDS_NRC_WBSC);
    }
    n = len - 2u;
    if (n > Bl.dlRemaining)
    {
        return nrc(resp, 0x36u, UDS_NRC_ROOR);
    }
    if (Fls_Write(Bl.dlAddress, &req[2], n) != E_OK)
    {
        resetDownload();
        return nrc(resp, 0x36u, UDS_NRC_GPF);
    }
    Bl.dlAddress += n;
    Bl.dlRemaining -= n;
    Bl.dlSeq++;
    resp[0] = 0x76u;
    resp[1] = req[1];
    return 2u;
}

static uint32 svcTransferExit(uint32 len, uint8 *resp)
{
    if (len != 1u)
    {
        return nrc(resp, 0x37u, UDS_NRC_IMLOIF);
    }
    if ((Bl.dlActive == FALSE) || (Bl.dlRemaining != 0u))
    {
        return nrc(resp, 0x37u, UDS_NRC_RSE);
    }
    resetDownload();
    Bl.dlComplete = TRUE;
    resp[0] = 0x77u;
    return 1u;
}

/* ------------------------------------------------------------------------ */
void Bootloader_Init(void)
{
    uint8 *p = (uint8 *)&Bl;
    uint32 i;
    for (i = 0u; i < sizeof(Bl); i++)
    {
        p[i] = 0u;
    }
    Bl.session = BL_SESSION_DEFAULT;
    /* entered on request of the application -> start in programming session */
    if (BootData_IsProgrammingRequested() == TRUE)
    {
        Bl.session = BL_SESSION_PROGRAMMING;
    }
}

uint32 Bootloader_HandleRequest(const uint8 *req, uint32 reqLen, uint8 *resp, uint32 respMax)
{
    if ((req == NULL_PTR) || (resp == NULL_PTR) || (reqLen == 0u) || (respMax < 32u))
    {
        return 0u;
    }
    switch (req[0])
    {
        case 0x10u: return svcSession(req, reqLen, resp);
        case 0x11u: return svcReset(req, reqLen, resp);
        case 0x22u: return svcReadDid(req, reqLen, resp);
        case 0x27u: return svcSecurityAccess(req, reqLen, resp);
        case 0x31u: return svcRoutine(req, reqLen, resp);
        case 0x34u: return svcRequestDownload(req, reqLen, resp);
        case 0x36u: return svcTransferData(req, reqLen, resp);
        case 0x37u: return svcTransferExit(reqLen, resp);
        case 0x3Eu:
            if ((reqLen == 2u) && ((req[1] & 0x80u) != 0u))
            {
                return 0u;
            }
            resp[0] = 0x7Eu;
            resp[1] = 0x00u;
            return 2u;
        default:
            return nrc(resp, req[0], UDS_NRC_SNS);
    }
}

boolean Bootloader_IsResetRequested(void)
{
    return Bl.resetRequested;
}

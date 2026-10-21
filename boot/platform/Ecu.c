/**
 * @file    Ecu.c
 */
#include "Ecu.h"
#include "Fls.h"
#include "Hsm.h"
#include "Det.h"
#include "Crypto.h"
#include "CryIf.h"
#include "Csm.h"
#include "Bootloader.h"
#include "App.h"

static Ecu_StateType Ecu_State = ECU_STATE_OFF;
static uint32        Ecu_ResetCount;
static uint32        Ecu_EntropyState = 0x12345678u;

static const uint8 *Ecu_GetBootImage(uint32 *size)
{
    *size = SECURE_BOOT_SIZE;
    return Fls_GetPointer(SECURE_BOOT_START);
}

static Std_ReturnType Ecu_GetEntropy(uint8 *buf, uint32 len)
{
    /* xorshift32 as TRNG stand-in (real HW: ring oscillator TRNG) */
    uint32 i;
    for (i = 0u; i < len; i++)
    {
        Ecu_EntropyState ^= Ecu_EntropyState << 13;
        Ecu_EntropyState ^= Ecu_EntropyState >> 17;
        Ecu_EntropyState ^= Ecu_EntropyState << 5;
        buf[i] = (uint8)Ecu_EntropyState;
    }
    return E_OK;
}

static const Hsm_PlatformConfigType Ecu_HsmPlatform = { Ecu_GetBootImage, Ecu_GetEntropy };

void Ecu_SimSetEntropySeed(uint32 seed)
{
    Ecu_EntropyState = (seed == 0u) ? 1u : seed;
}

void Ecu_BuildBootCode(uint8 *bm, uint32 bmLen, uint8 *bl, uint32 blLen)
{
    static const char bmId[] = "BOOTMANAGER v1.0.0";
    static const char blId[] = "BOOTLOADER v1.0.0";
    uint32 s = 0xB007C0DEu;
    uint32 i;
    for (i = 0u; i < bmLen; i++)
    {
        s = (s * 1103515245u) + 12345u;
        bm[i] = (i < (sizeof(bmId) - 1u)) ? (uint8)bmId[i] : (uint8)(s >> 16);
    }
    for (i = 0u; i < blLen; i++)
    {
        s = (s * 1103515245u) + 12345u;
        bl[i] = (i < (sizeof(blId) - 1u)) ? (uint8)blId[i] : (uint8)(s >> 16);
    }
}

void Ecu_FactoryInit(const uint8 uid[15])
{
    static uint8 bm[BM_SIZE];
    static uint8 bl[BL_SIZE];
    Fls_FactoryErase();
    Hsm_FactoryReset(uid);
    Ecu_BuildBootCode(bm, BM_SIZE, bl, BL_SIZE);
    (void)Fls_Write(BM_START, bm, BM_SIZE);
    (void)Fls_Write(BL_START, bl, BL_SIZE);
    Ecu_State = ECU_STATE_OFF;
    Ecu_ResetCount = 0u;
}

Ecu_StateType Ecu_Reset(void)
{
    BootManager_TargetType t;

    Ecu_ResetCount++;
    /* 1. HSM starts first and performs the secure boot of BM + BL */
    Hsm_Init(&Ecu_HsmPlatform);
    /* 2. host core released: basic software initialisation */
    Fls_Init();
    Det_Init();
    Crypto_Init(NULL_PTR);
    CryIf_Init(NULL_PTR);
    Csm_Init(NULL_PTR);
    /* 3. Boot Manager */
    t = BootManager_Run();
    switch (t)
    {
        case BM_TARGET_APPLICATION:
            App_Init();
            Ecu_State = ECU_STATE_APPLICATION;
            break;
        case BM_TARGET_BOOTLOADER:
            Bootloader_Init();
            Ecu_State = ECU_STATE_BOOTLOADER;
            break;
        default:
            Ecu_State = ECU_STATE_HALTED;
            break;
    }
    return Ecu_State;
}

Ecu_StateType Ecu_GetState(void)
{
    return Ecu_State;
}

uint32 Ecu_GetResetCount(void)
{
    return Ecu_ResetCount;
}

const char *Ecu_StateString(Ecu_StateType s)
{
    switch (s)
    {
        case ECU_STATE_OFF:         return "OFF";
        case ECU_STATE_APPLICATION: return "APPLICATION";
        case ECU_STATE_BOOTLOADER:  return "BOOTLOADER";
        case ECU_STATE_HALTED:      return "HALTED";
        default:                    return "?";
    }
}

uint32 Ecu_Diag(const uint8 *req, uint32 reqLen, uint8 *resp, uint32 respMax)
{
    uint32 n = 0u;
    if (Ecu_State == ECU_STATE_BOOTLOADER)
    {
        n = Bootloader_HandleRequest(req, reqLen, resp, respMax);
        if (Bootloader_IsResetRequested() == TRUE)
        {
            (void)Ecu_Reset();
        }
    }
    else if (Ecu_State == ECU_STATE_APPLICATION)
    {
        n = App_HandleDiag(req, reqLen, resp, respMax);
        if (App_IsResetRequested() == TRUE)
        {
            (void)Ecu_Reset();
        }
    }
    else
    {
        /* halted / off: no response */
    }
    return n;
}

void Ecu_MainFunction(void)
{
    if ((Ecu_State == ECU_STATE_APPLICATION) || (Ecu_State == ECU_STATE_BOOTLOADER))
    {
        Csm_MainFunction();
        Crypto_MainFunction();
        if (Ecu_State == ECU_STATE_APPLICATION)
        {
            App_MainFunction();
        }
    }
}

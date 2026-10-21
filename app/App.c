/**
 * @file    App.c
 */
#include "App.h"
#include "App_Callbacks.h"
#include "AppHeader.h"
#include "BootData.h"
#include "Fls.h"
#include "Csm.h"

App_CsmNotificationType App_CsmNotification;
static boolean App_ResetRequested;
static uint32  App_Cycle;

void App_CsmJobFinished(uint32 jobId, Std_ReturnType result)
{
    App_CsmNotification.count++;
    App_CsmNotification.lastJobId = jobId;
    App_CsmNotification.lastResult = result;
}

void App_Init(void)
{
    App_ResetRequested = FALSE;
    App_Cycle = 0u;
    App_CsmNotification.count = 0u;
    App_CsmNotification.lastJobId = 0xFFFFFFFFu;
    App_CsmNotification.lastResult = E_NOT_OK;
    SecOC_Init();
}

void App_MainFunction(void)
{
    App_Cycle++;
}

Std_ReturnType App_SendVehicleSpeed(uint16 speed, uint8 *pdu, uint32 *pduLen)
{
    uint8 sig[2];
    sig[0] = (uint8)(speed >> 8);
    sig[1] = (uint8)speed;
    return SecOC_Authenticate(APP_PDU_VEHICLE_SPEED, sig, 2u, pdu, pduLen);
}

SecOC_VerificationResultType App_ReceiveVehicleSpeed(const uint8 *pdu, uint32 pduLen, uint16 *speed)
{
    uint8 sig[SECOC_MAX_PDU_LEN];
    uint32 n = 0u;
    SecOC_VerificationResultType r = SecOC_Verify(APP_PDU_VEHICLE_SPEED, pdu, pduLen, sig, &n);
    if ((r == SECOC_VERIFICATIONSUCCESS) && (n == 2u) && (speed != NULL_PTR))
    {
        *speed = (uint16)(((uint16)sig[0] << 8) | sig[1]);
    }
    return r;
}

uint32 App_HandleDiag(const uint8 *req, uint32 reqLen, uint8 *resp, uint32 respMax)
{
    if ((req == NULL_PTR) || (resp == NULL_PTR) || (reqLen == 0u) || (respMax < 8u))
    {
        return 0u;
    }
    switch (req[0])
    {
        case 0x10u:
            if (reqLen != 2u)
            {
                break;
            }
            if (req[1] == 0x02u)
            {
                /* jump to bootloader: set flag in boot data flash and reset */
                if (BootData_SetProgrammingRequest() != E_OK)
                {
                    resp[0] = 0x7Fu; resp[1] = 0x10u; resp[2] = 0x22u;
                    return 3u;
                }
                App_ResetRequested = TRUE;
            }
            resp[0] = 0x50u; resp[1] = req[1];
            resp[2] = 0x00u; resp[3] = 0x32u; resp[4] = 0x01u; resp[5] = 0xF4u;
            return 6u;
        case 0x11u:
            App_ResetRequested = TRUE;
            resp[0] = 0x51u; resp[1] = 0x01u;
            return 2u;
        case 0x22u:
            if ((reqLen == 3u) && (req[1] == 0xF1u) && (req[2] == 0x81u))
            {
                const uint8 *hdr = Fls_GetPointer(APP_START);
                resp[0] = 0x62u; resp[1] = 0xF1u; resp[2] = 0x81u;
                AppHeader_Put32(&resp[3], AppHeader_Get32(&hdr[APPHDR_OFF_SWVER]));
                return 7u;
            }
            resp[0] = 0x7Fu; resp[1] = 0x22u; resp[2] = 0x31u;
            return 3u;
        case 0x3Eu:
            resp[0] = 0x7Eu; resp[1] = 0x00u;
            return 2u;
        default:
            break;
    }
    resp[0] = 0x7Fu; resp[1] = req[0]; resp[2] = 0x11u;
    return 3u;
}

boolean App_IsResetRequested(void)
{
    return App_ResetRequested;
}

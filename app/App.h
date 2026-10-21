/**
 * @file    App.h
 * @brief   Example application SW-C running on the host core.
 *
 *  - sends/receives SecOC protected signals (MAC generate / verify by HSM)
 *  - encrypts calibration data (AES-CBC by HSM)
 *  - minimal UDS server: 0x10 02 triggers the jump to the bootloader
 */
#ifndef APP_H
#define APP_H

#include "Std_Types.h"
#include "SecOC.h"

#define APP_PDU_VEHICLE_SPEED   0u
#define APP_PDU_BRAKE_CMD       1u

void   App_Init(void);
void   App_MainFunction(void);
uint32 App_HandleDiag(const uint8 *req, uint32 reqLen, uint8 *resp, uint32 respMax);
boolean App_IsResetRequested(void);

Std_ReturnType App_SendVehicleSpeed(uint16 speed, uint8 *pdu, uint32 *pduLen);
SecOC_VerificationResultType App_ReceiveVehicleSpeed(const uint8 *pdu, uint32 pduLen, uint16 *speed);

#endif

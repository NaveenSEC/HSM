/**
 * @file    BootData.h
 * @brief   Shared boot data (data flash) between App, Boot Manager and Bootloader.
 */
#ifndef BOOTDATA_H
#define BOOTDATA_H

#include "Std_Types.h"

#define BOOTDATA_PROG_REQUEST_MAGIC  0x50524F47u   /* "PROG" */

typedef enum
{
    BOOTDATA_RESET_POWER_ON = 0,
    BOOTDATA_RESET_SW_RESET,
    BOOTDATA_RESET_PROG_REQUEST
} BootData_ResetReasonType;

boolean        BootData_IsProgrammingRequested(void);
Std_ReturnType BootData_SetProgrammingRequest(void);
Std_ReturnType BootData_ClearProgrammingRequest(void);

#endif

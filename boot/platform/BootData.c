/**
 * @file    BootData.c
 * @brief   Programming request flag stored in the boot data flash sector.
 */
#include "BootData.h"
#include "Fls.h"

boolean BootData_IsProgrammingRequested(void)
{
    uint8 b[4];
    uint32 v;
    if (Fls_Read(BOOTDATA_START, b, 4u) != E_OK)
    {
        return FALSE;
    }
    v = ((uint32)b[0] << 24) | ((uint32)b[1] << 16) | ((uint32)b[2] << 8) | b[3];
    return (v == BOOTDATA_PROG_REQUEST_MAGIC) ? TRUE : FALSE;
}

Std_ReturnType BootData_SetProgrammingRequest(void)
{
    const uint8 b[4] = { 0x50u, 0x52u, 0x4Fu, 0x47u };
    if (Fls_Erase(BOOTDATA_START, BOOTDATA_SIZE) != E_OK)
    {
        return E_NOT_OK;
    }
    return Fls_Write(BOOTDATA_START, b, 4u);
}

Std_ReturnType BootData_ClearProgrammingRequest(void)
{
    return Fls_Erase(BOOTDATA_START, BOOTDATA_SIZE);
}

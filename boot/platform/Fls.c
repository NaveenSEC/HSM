/**
 * @file    Fls.c
 * @brief   Simulated NOR flash.
 */
#include "Fls.h"

static uint8 Fls_Memory[FLS_TOTAL_SIZE];

void Fls_Init(void)
{
    /* nothing to do: content is non-volatile */
}

void Fls_FactoryErase(void)
{
    uint32 i;
    for (i = 0u; i < FLS_TOTAL_SIZE; i++)
    {
        Fls_Memory[i] = FLS_ERASED_VALUE;
    }
}

static boolean inRange(uint32 address, uint32 length)
{
    return ((address < FLS_TOTAL_SIZE) && (length <= (FLS_TOTAL_SIZE - address))) ? TRUE : FALSE;
}

Std_ReturnType Fls_Erase(uint32 address, uint32 length)
{
    uint32 i;
    if ((inRange(address, length) == FALSE) || ((address % FLS_SECTOR_SIZE) != 0u) ||
        ((length % FLS_SECTOR_SIZE) != 0u))
    {
        return E_NOT_OK;
    }
    for (i = 0u; i < length; i++)
    {
        Fls_Memory[address + i] = FLS_ERASED_VALUE;
    }
    return E_OK;
}

Std_ReturnType Fls_Write(uint32 address, const uint8 *data, uint32 length)
{
    uint32 i;
    if ((data == NULL_PTR) || (inRange(address, length) == FALSE))
    {
        return E_NOT_OK;
    }
    /* NOR: a bit can only be programmed from 1 to 0 */
    for (i = 0u; i < length; i++)
    {
        if ((uint8)(Fls_Memory[address + i] & data[i]) != data[i])
        {
            return E_NOT_OK;
        }
    }
    for (i = 0u; i < length; i++)
    {
        Fls_Memory[address + i] = data[i];
    }
    return E_OK;
}

Std_ReturnType Fls_Read(uint32 address, uint8 *data, uint32 length)
{
    uint32 i;
    if ((data == NULL_PTR) || (inRange(address, length) == FALSE))
    {
        return E_NOT_OK;
    }
    for (i = 0u; i < length; i++)
    {
        data[i] = Fls_Memory[address + i];
    }
    return E_OK;
}

const uint8 *Fls_GetPointer(uint32 address)
{
    return (address < FLS_TOTAL_SIZE) ? &Fls_Memory[address] : NULL_PTR;
}

void Fls_SimCorrupt(uint32 address, uint8 xorMask)
{
    if (address < FLS_TOTAL_SIZE)
    {
        Fls_Memory[address] ^= xorMask;
    }
}

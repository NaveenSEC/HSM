/**
 * @file    Fls.h
 * @brief   Flash driver (simplified AUTOSAR Fls API, synchronous).
 *          Models NOR flash semantics: erase sets 0xFF, program only clears bits.
 */
#ifndef FLS_H
#define FLS_H

#include "Std_Types.h"
#include "MemMap_Layout.h"

void           Fls_Init(void);
void           Fls_FactoryErase(void);
Std_ReturnType Fls_Erase(uint32 address, uint32 length);
Std_ReturnType Fls_Write(uint32 address, const uint8 *data, uint32 length);
Std_ReturnType Fls_Read(uint32 address, uint8 *data, uint32 length);
const uint8   *Fls_GetPointer(uint32 address);  /* memory mapped read access */

/* test helper: corrupt flash content (bypasses NOR semantics) */
void           Fls_SimCorrupt(uint32 address, uint8 xorMask);

#endif

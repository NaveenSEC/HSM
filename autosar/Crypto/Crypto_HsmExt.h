/**
 * @file    Crypto_HsmExt.h
 * @brief   Vendor specific extensions of the HSM Crypto Driver (not covered by
 *          the standard CSM API): secure boot status, monotonic counters,
 *          lifecycle, SHE CMD_BOOT_FAILURE / CMD_BOOT_OK.
 */
#ifndef CRYPTO_HSMEXT_H
#define CRYPTO_HSMEXT_H

#include "Std_Types.h"
#include "Hsm_Types.h"

/** sreg: SHE status register, bootResult: ERC of the last secure boot */
Std_ReturnType Crypto_Hsm_GetStatus(uint8 *sreg, Hsm_ErrorType *bootResult);
Std_ReturnType Crypto_Hsm_BootFailure(void);
Std_ReturnType Crypto_Hsm_BootOk(void);
Std_ReturnType Crypto_Hsm_CounterRead(uint8 counterId, uint32 *value);
Std_ReturnType Crypto_Hsm_CounterIncrement(uint8 counterId, uint32 newValue);
Std_ReturnType Crypto_Hsm_SetLifecycle(Hsm_LifecycleType lc);
Std_ReturnType Crypto_Hsm_GetId(const uint8 challenge[16], uint8 out[32]);

#endif

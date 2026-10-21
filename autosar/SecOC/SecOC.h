/**
 * @file    SecOC.h
 * @brief   Secure Onboard Communication (simplified AUTOSAR_SWS_SecureOnboardCommunication).
 *
 * Secured I-PDU layout:  | Authentic I-PDU | Freshness (truncated) | MAC (truncated) |
 * DataToAuthenticator :  | DataId (16 bit) | Authentic I-PDU | Freshness (full, 32 bit) |
 */
#ifndef SECOC_H
#define SECOC_H

#include "Std_Types.h"

#define SECOC_MODULE_ID             150u
#define SECOC_NUM_PDUS              2u
#define SECOC_MAX_PDU_LEN           64u

typedef uint16 PduIdType;

typedef enum
{
    SECOC_VERIFICATIONSUCCESS = 0,
    SECOC_VERIFICATIONFAILURE,
    SECOC_FRESHNESSFAILURE,
    SECOC_NO_VERIFICATION
} SecOC_VerificationResultType;

typedef struct
{
    uint16 dataId;
    uint8  freshnessTxBits;     /* transmitted freshness length (8/16/32) */
    uint16 authInfoTxBits;      /* transmitted MAC length in bits          */
    uint32 csmJobGenerate;
    uint32 csmJobVerify;
} SecOC_PduConfigType;

extern const SecOC_PduConfigType SecOC_PduConfig[SECOC_NUM_PDUS];

void           SecOC_Init(void);
Std_ReturnType SecOC_Authenticate(PduIdType pduId, const uint8 *data, uint32 len,
                                  uint8 *secured, uint32 *securedLen);
SecOC_VerificationResultType SecOC_Verify(PduIdType pduId, const uint8 *secured, uint32 securedLen,
                                          uint8 *data, uint32 *dataLen);

/* Freshness value manager (FVM) access for tests / sync */
uint32         SecOC_GetTxFreshness(PduIdType pduId);
uint32         SecOC_GetRxFreshness(PduIdType pduId);
void           SecOC_SetRxFreshness(PduIdType pduId, uint32 value);

#endif

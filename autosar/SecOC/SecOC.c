/**
 * @file    SecOC.c
 * @brief   SecOC: authentication / verification of I-PDUs via the CSM.
 */
#include "SecOC.h"
#include "Csm.h"

const SecOC_PduConfigType SecOC_PduConfig[SECOC_NUM_PDUS] =
{
    /* dataId  fvTx  macTx  gen job                     verify job                 */
    { 0x0100u, 8u,   24u,   CSM_JOB_SECOC_MAC_GENERATE, CSM_JOB_SECOC_MAC_VERIFY },
    { 0x0200u, 16u,  64u,   CSM_JOB_SECOC_MAC_GENERATE, CSM_JOB_SECOC_MAC_VERIFY }
};

static uint32 SecOC_TxFreshness[SECOC_NUM_PDUS];
static uint32 SecOC_RxFreshness[SECOC_NUM_PDUS];

static uint32 buildDataToAuth(const SecOC_PduConfigType *c, const uint8 *data, uint32 len,
                              uint32 fv, uint8 *buf)
{
    uint32 i;
    buf[0] = (uint8)(c->dataId >> 8);
    buf[1] = (uint8)(c->dataId);
    for (i = 0u; i < len; i++)
    {
        buf[2u + i] = data[i];
    }
    buf[2u + len] = (uint8)(fv >> 24);
    buf[3u + len] = (uint8)(fv >> 16);
    buf[4u + len] = (uint8)(fv >> 8);
    buf[5u + len] = (uint8)(fv);
    return len + 6u;
}

void SecOC_Init(void)
{
    uint32 i;
    for (i = 0u; i < SECOC_NUM_PDUS; i++)
    {
        SecOC_TxFreshness[i] = 0u;
        SecOC_RxFreshness[i] = 0u;
    }
}

Std_ReturnType SecOC_Authenticate(PduIdType pduId, const uint8 *data, uint32 len,
                                  uint8 *secured, uint32 *securedLen)
{
    const SecOC_PduConfigType *c;
    uint8 dta[SECOC_MAX_PDU_LEN + 6u];
    uint8 mac[16];
    uint32 macLen = 16u;
    uint32 fvBytes, macBytes, n, i;
    uint32 fv;

    if ((pduId >= SECOC_NUM_PDUS) || (data == NULL_PTR) || (secured == NULL_PTR) ||
        (securedLen == NULL_PTR) || (len > SECOC_MAX_PDU_LEN))
    {
        return E_NOT_OK;
    }
    c = &SecOC_PduConfig[pduId];
    fvBytes = c->freshnessTxBits / 8u;
    macBytes = (c->authInfoTxBits + 7u) / 8u;
    if (*securedLen < (len + fvBytes + macBytes))
    {
        return E_NOT_OK;
    }
    fv = SecOC_TxFreshness[pduId] + 1u;
    n = buildDataToAuth(c, data, len, fv, dta);
    if (Csm_MacGenerate(c->csmJobGenerate, CRYPTO_OPERATIONMODE_SINGLECALL, dta, n, mac, &macLen) != E_OK)
    {
        return E_NOT_OK;
    }
    SecOC_TxFreshness[pduId] = fv;

    for (i = 0u; i < len; i++)
    {
        secured[i] = data[i];
    }
    for (i = 0u; i < fvBytes; i++)
    {
        secured[len + i] = (uint8)(fv >> (8u * (fvBytes - 1u - i)));
    }
    for (i = 0u; i < macBytes; i++)
    {
        secured[len + fvBytes + i] = mac[i];
    }
    *securedLen = len + fvBytes + macBytes;
    return E_OK;
}

SecOC_VerificationResultType SecOC_Verify(PduIdType pduId, const uint8 *secured, uint32 securedLen,
                                          uint8 *data, uint32 *dataLen)
{
    const SecOC_PduConfigType *c;
    uint8 dta[SECOC_MAX_PDU_LEN + 6u];
    Crypto_VerifyResultType vr = CRYPTO_E_VER_NOT_OK;
    uint32 fvBytes, macBytes, len, n, i;
    uint32 truncFv = 0u, mask, fv, latest;

    if ((pduId >= SECOC_NUM_PDUS) || (secured == NULL_PTR) || (data == NULL_PTR) || (dataLen == NULL_PTR))
    {
        return SECOC_NO_VERIFICATION;
    }
    c = &SecOC_PduConfig[pduId];
    fvBytes = c->freshnessTxBits / 8u;
    macBytes = (c->authInfoTxBits + 7u) / 8u;
    if ((securedLen < (fvBytes + macBytes)) || ((securedLen - fvBytes - macBytes) > SECOC_MAX_PDU_LEN))
    {
        return SECOC_VERIFICATIONFAILURE;
    }
    len = securedLen - fvBytes - macBytes;
    for (i = 0u; i < fvBytes; i++)
    {
        truncFv = (truncFv << 8) | secured[len + i];
    }

    /* reconstruct the complete freshness value */
    latest = SecOC_RxFreshness[pduId];
    if (fvBytes >= 4u)
    {
        fv = truncFv;
    }
    else
    {
        mask = (1UL << (8u * fvBytes)) - 1u;
        fv = (latest & ~mask) | truncFv;
        if (truncFv <= (latest & mask))
        {
            fv += (mask + 1u);
        }
    }
    if (fv <= latest)
    {
        return SECOC_FRESHNESSFAILURE;   /* replay */
    }

    n = buildDataToAuth(c, secured, len, fv, dta);
    if (Csm_MacVerify(c->csmJobVerify, CRYPTO_OPERATIONMODE_SINGLECALL, dta, n,
                      &secured[len + fvBytes], c->authInfoTxBits, &vr) != E_OK)
    {
        return SECOC_VERIFICATIONFAILURE;
    }
    if (vr != CRYPTO_E_VER_OK)
    {
        return SECOC_VERIFICATIONFAILURE;
    }
    SecOC_RxFreshness[pduId] = fv;
    for (i = 0u; i < len; i++)
    {
        data[i] = secured[i];
    }
    *dataLen = len;
    return SECOC_VERIFICATIONSUCCESS;
}

uint32 SecOC_GetTxFreshness(PduIdType pduId)
{
    return (pduId < SECOC_NUM_PDUS) ? SecOC_TxFreshness[pduId] : 0u;
}

uint32 SecOC_GetRxFreshness(PduIdType pduId)
{
    return (pduId < SECOC_NUM_PDUS) ? SecOC_RxFreshness[pduId] : 0u;
}

void SecOC_SetRxFreshness(PduIdType pduId, uint32 value)
{
    if (pduId < SECOC_NUM_PDUS)
    {
        SecOC_RxFreshness[pduId] = value;
    }
}

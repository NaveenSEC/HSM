/**
 * @file    Eol.c
 */
#include "Eol.h"
#include "Csm.h"
#include "Crypto_HsmExt.h"
#include "Ecu.h"
#include "Hsm_Types.h"

static uint8 Eol_Uid[15];

Eol_ResultType Eol_InstallSheKey(uint32 csmKeyId, uint8 sheKeyId, uint8 authId,
                                 const uint8 authKey[16], const uint8 newKey[16],
                                 uint32 counter, uint8 flags)
{
    Hsm_SheUpdateMsgType m;
    uint8 m123[64];
    uint8 m45[48];
    uint32 l = sizeof(m45);
    uint32 i;

    Hsm_SheGenerateUpdate(Eol_Uid, sheKeyId, authId, authKey, newKey, counter, flags, &m);
    for (i = 0u; i < 16u; i++) { m123[i] = m.m1[i]; }
    for (i = 0u; i < 32u; i++) { m123[16u + i] = m.m2[i]; }
    for (i = 0u; i < 16u; i++) { m123[48u + i] = m.m3[i]; }

    if ((Csm_KeyElementSet(csmKeyId, CRYPTO_KE_CUSTOM_SHE_M1M2M3, m123, 64u) != E_OK) ||
        (Csm_KeySetValid(csmKeyId) != E_OK))
    {
        return EOL_KEY_UPDATE_FAILED;
    }
    if (Csm_KeyElementGet(csmKeyId, CRYPTO_KE_CUSTOM_SHE_M4M5, m45, &l) != E_OK)
    {
        return EOL_PROOF_MISMATCH;
    }
    /* the back-end verifies the proof M4/M5 of the HSM */
    for (i = 0u; i < 32u; i++)
    {
        if (m45[i] != m.m4[i]) { return EOL_PROOF_MISMATCH; }
    }
    for (i = 0u; i < 16u; i++)
    {
        if (m45[32u + i] != m.m5[i]) { return EOL_PROOF_MISMATCH; }
    }
    return EOL_OK;
}

Eol_ResultType Eol_ProvisionEcu(const uint8 uid[15], const Backend_KeySetType *k)
{
    uint8 sreg = 0u;
    Hsm_ErrorType erc = 0u;
    Eol_ResultType r;
    uint32 i;

    for (i = 0u; i < 15u; i++)
    {
        Eol_Uid[i] = uid[i];
    }

    /* MASTER_ECU_KEY first (authorized by the empty/default key) */
    r = Eol_InstallSheKey(CSM_KEY_MASTER_ECU, HSM_KEY_MASTER_ECU_KEY, HSM_KEY_MASTER_ECU_KEY,
                          Hsm_She_DefaultKey, k->masterEcuKey, 1u, 0u);
    if (r != EOL_OK) { return r; }
    r = Eol_InstallSheKey(CSM_KEY_BOOT_MAC_KEY, HSM_KEY_BOOT_MAC_KEY, HSM_KEY_MASTER_ECU_KEY,
                          k->masterEcuKey, k->bootMacKey, 1u, 0u);
    if (r != EOL_OK) { return r; }
    /* software verification key: MAC usage, boot protected, not wildcard updatable */
    r = Eol_InstallSheKey(CSM_KEY_FLASH_VERIFY, HSM_KEY_1, HSM_KEY_MASTER_ECU_KEY, k->masterEcuKey,
                          k->flashVerifyKey, 1u,
                          HSM_FLAG_KEY_USAGE | HSM_FLAG_BOOT_PROTECTION | HSM_FLAG_WILDCARD);
    if (r != EOL_OK) { return r; }
    r = Eol_InstallSheKey(CSM_KEY_DIAG_SECACCESS, HSM_KEY_2, HSM_KEY_MASTER_ECU_KEY, k->masterEcuKey,
                          k->diagKey, 1u, HSM_FLAG_KEY_USAGE | HSM_FLAG_DEBUGGER_PROTECTION);
    if (r != EOL_OK) { return r; }
    r = Eol_InstallSheKey(CSM_KEY_SECOC, HSM_KEY_3, HSM_KEY_MASTER_ECU_KEY, k->masterEcuKey,
                          k->secocKey, 1u, HSM_FLAG_KEY_USAGE | HSM_FLAG_BOOT_PROTECTION);
    if (r != EOL_OK) { return r; }
    r = Eol_InstallSheKey(CSM_KEY_APP_CIPHER, HSM_KEY_4, HSM_KEY_MASTER_ECU_KEY, k->masterEcuKey,
                          k->cipherKey, 1u, HSM_FLAG_BOOT_PROTECTION);
    if (r != EOL_OK) { return r; }

    /* HMAC key into extended slot (plain injection in production lifecycle) */
    if ((Csm_KeyElementSet(CSM_KEY_HMAC, CRYPTO_KE_MAC_KEY, k->hmacKey, 32u) != E_OK) ||
        (Csm_KeySetValid(CSM_KEY_HMAC) != E_OK))
    {
        return EOL_KEY_UPDATE_FAILED;
    }

    /* reset: HSM computes and stores BOOT_MAC (autonomous bootstrap) */
    (void)Ecu_Reset();
    if ((Crypto_Hsm_GetStatus(&sreg, &erc) != E_OK) || ((sreg & HSM_SREG_BOOT_OK) == 0u))
    {
        return EOL_BOOT_MAC_NOT_LEARNED;
    }
    if (Crypto_Hsm_SetLifecycle(HSM_LC_IN_FIELD) != E_OK)
    {
        return EOL_LIFECYCLE_FAILED;
    }
    (void)Ecu_Reset();
    return EOL_OK;
}

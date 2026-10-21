/**
 * @file    Hsm_KeyStore.c
 * @brief   HSM key storage implementation.
 */
#include "Hsm_KeyStore.h"
#include "hsm_aes.h"

#define HSM_NVM_MAGIC 0x48534D31u   /* "HSM1" */

static Hsm_NvmType Hsm_Nvm;

void Hsm_KeyStoreFactoryInit(const uint8 uid[15])
{
    uint8 i;
    Hsm_SecureZero(&Hsm_Nvm, sizeof(Hsm_Nvm));
    Hsm_Nvm.magic = HSM_NVM_MAGIC;
    for (i = 0u; i < 15u; i++)
    {
        Hsm_Nvm.uid[i] = uid[i];
    }
    Hsm_Nvm.lifecycle = HSM_LC_DEVELOPMENT;
}

void Hsm_KeyStoreResetVolatile(void)
{
    /* RAM_KEY is volatile: lost on every reset */
    Hsm_KeyStoreErase(HSM_RAM_KEY);
}

Hsm_NvmType *Hsm_KeyStoreNvm(void)
{
    return &Hsm_Nvm;
}

boolean Hsm_KeyStoreIsSheSlot(Hsm_KeyIdType id)
{
    return (id < HSM_NUM_SHE_SLOTS) ? TRUE : FALSE;
}

boolean Hsm_KeyStoreIsValidId(Hsm_KeyIdType id)
{
    if (id < HSM_NUM_SHE_SLOTS)
    {
        return TRUE;
    }
    if ((id >= HSM_KEY_EXT_0) && (id < HSM_NUM_KEY_SLOTS))
    {
        return TRUE;
    }
    return FALSE;
}

Hsm_KeySlotType *Hsm_KeyStoreSlot(Hsm_KeyIdType id)
{
    if (Hsm_KeyStoreIsValidId(id) == FALSE)
    {
        return NULL_PTR;
    }
    return &Hsm_Nvm.slot[id];
}

Hsm_ErrorType Hsm_KeyStoreCheckUsage(Hsm_KeyIdType id, boolean forMac,
                                     boolean bootOk, boolean debuggerAttached)
{
    const Hsm_KeySlotType *s = Hsm_KeyStoreSlot(id);

    if (s == NULL_PTR)
    {
        return HSM_ERC_KEY_INVALID;
    }
    /* Keys reserved for internal use cannot be used by crypto commands */
    if ((id == HSM_KEY_SECRET_KEY) || (id == HSM_KEY_MASTER_ECU_KEY) ||
        (id == HSM_KEY_BOOT_MAC_KEY) || (id == HSM_KEY_BOOT_MAC))
    {
        return HSM_ERC_KEY_INVALID;
    }
    if (s->valid == FALSE)
    {
        return HSM_ERC_KEY_EMPTY;
    }
    if (((s->flags & HSM_FLAG_BOOT_PROTECTION) != 0u) && (bootOk == FALSE))
    {
        return HSM_ERC_KEY_NOT_AVAILABLE;
    }
    if (((s->flags & HSM_FLAG_DEBUGGER_PROTECTION) != 0u) && (debuggerAttached == TRUE))
    {
        return HSM_ERC_KEY_NOT_AVAILABLE;
    }
    if ((id < HSM_RAM_KEY) && (Hsm_KeyStoreIsSheSlot(id) == TRUE))
    {
        boolean isMacKey = ((s->flags & HSM_FLAG_KEY_USAGE) != 0u) ? TRUE : FALSE;
        if (isMacKey != forMac)
        {
            return HSM_ERC_KEY_INVALID;
        }
    }
    return HSM_ERC_NO_ERROR;
}

void Hsm_KeyStoreWrite(Hsm_KeyIdType id, const uint8 *key, uint8 len,
                       uint8 flags, uint32 counter, boolean plain)
{
    Hsm_KeySlotType *s = Hsm_KeyStoreSlot(id);
    uint8 i;

    if ((s == NULL_PTR) || (len > HSM_MAX_KEY_LEN))
    {
        return;
    }
    Hsm_SecureZero(s->key, sizeof(s->key));
    for (i = 0u; i < len; i++)
    {
        s->key[i] = key[i];
    }
    s->keyLen = len;
    s->flags = flags;
    s->counter = counter & 0x0FFFFFFFu;
    s->valid = TRUE;
    s->plain = plain;
}

void Hsm_KeyStoreErase(Hsm_KeyIdType id)
{
    Hsm_KeySlotType *s = Hsm_KeyStoreSlot(id);
    if (s != NULL_PTR)
    {
        Hsm_SecureZero(s, sizeof(*s));
    }
}

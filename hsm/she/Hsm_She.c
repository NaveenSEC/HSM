/**
 * @file    Hsm_She.c
 * @brief   SHE KDF and memory update protocol.
 */
#include "Hsm_She.h"
#include "Hsm_KeyStore.h"
#include "hsm_aes.h"
#include "hsm_cmac.h"

/* Constants already contain the MP padding (0x80 .. length 0xB0 = 176 bit) */
const uint8 Hsm_She_KeyUpdateEncC[16] = {
    0x01,0x01,0x53,0x48,0x45,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xB0 };
const uint8 Hsm_She_KeyUpdateMacC[16] = {
    0x01,0x02,0x53,0x48,0x45,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xB0 };
const uint8 Hsm_She_DebugKeyC[16] = {
    0x01,0x03,0x53,0x48,0x45,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xB0 };
const uint8 Hsm_She_PrngKeyC[16] = {
    0x01,0x04,0x53,0x48,0x45,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xB0 };
const uint8 Hsm_She_PrngSeedKeyC[16] = {
    0x01,0x05,0x53,0x48,0x45,0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xB0 };

/* Value used for authentication against a slot that was never written       */
const uint8 Hsm_She_DefaultKey[16] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };

void Hsm_SheMpCompress(const uint8 *in, uint32 len, uint8 out[16])
{
    Hsm_AesCtxType aes;
    uint8 h[16] = { 0u };
    uint8 e[16];
    uint32 off;
    uint8 i;

    for (off = 0u; (off + 16u) <= len; off += 16u)
    {
        Hsm_AesInit(&aes, h);
        Hsm_AesEncryptBlock(&aes, &in[off], e);
        for (i = 0u; i < 16u; i++)
        {
            h[i] = (uint8)(e[i] ^ in[off + i] ^ h[i]);
        }
    }
    for (i = 0u; i < 16u; i++)
    {
        out[i] = h[i];
    }
    Hsm_AesWipe(&aes);
    Hsm_SecureZero(h, sizeof(h));
    Hsm_SecureZero(e, sizeof(e));
}

void Hsm_SheKdf(const uint8 key[16], const uint8 c[16], uint8 out[16])
{
    uint8 buf[32];
    uint8 i;
    for (i = 0u; i < 16u; i++)
    {
        buf[i] = key[i];
        buf[16u + i] = c[i];
    }
    Hsm_SheMpCompress(buf, 32u, out);
    Hsm_SecureZero(buf, sizeof(buf));
}

static void buildM1(const uint8 uid[15], Hsm_KeyIdType keyId, Hsm_KeyIdType authId, uint8 m1[16])
{
    uint8 i;
    for (i = 0u; i < 15u; i++)
    {
        m1[i] = uid[i];
    }
    m1[15] = (uint8)(((keyId & 0x0Fu) << 4) | (authId & 0x0Fu));
}

void Hsm_SheGenerateUpdate(const uint8 uid[15], Hsm_KeyIdType keyId, Hsm_KeyIdType authId,
                           const uint8 authKey[16], const uint8 newKey[16],
                           uint32 counter, uint8 flags, Hsm_SheUpdateMsgType *msg)
{
    static const uint8 zeroIv[16] = { 0u };
    uint8 k1[16], k2[16], k3[16], k4[16];
    uint8 plain[32] = { 0u };
    uint8 m1m2[48];
    uint32 word0;
    uint8 i;

    Hsm_SheKdf(authKey, Hsm_She_KeyUpdateEncC, k1);
    Hsm_SheKdf(authKey, Hsm_She_KeyUpdateMacC, k2);
    Hsm_SheKdf(newKey, Hsm_She_KeyUpdateEncC, k3);
    Hsm_SheKdf(newKey, Hsm_She_KeyUpdateMacC, k4);

    /* M1 = UID | ID | AuthID */
    buildM1(uid, keyId, authId, msg->m1);

    /* M2 = ENC_CBC(K1, IV=0, CID(28) | FID(5) | 0(95) | KEY(128)) */
    word0 = ((counter & 0x0FFFFFFFu) << 4) | ((uint32)(flags >> 1) & 0x0Fu);
    plain[0] = (uint8)(word0 >> 24);
    plain[1] = (uint8)(word0 >> 16);
    plain[2] = (uint8)(word0 >> 8);
    plain[3] = (uint8)(word0);
    plain[4] = (uint8)((flags & 0x01u) << 7);
    for (i = 0u; i < 16u; i++)
    {
        plain[16u + i] = newKey[i];
    }
    (void)Hsm_AesCbcEncrypt(k1, zeroIv, plain, 32u, msg->m2);

    /* M3 = CMAC(K2, M1 | M2) */
    for (i = 0u; i < 16u; i++)
    {
        m1m2[i] = msg->m1[i];
    }
    for (i = 0u; i < 32u; i++)
    {
        m1m2[16u + i] = msg->m2[i];
    }
    Hsm_Cmac(k2, m1m2, 48u, msg->m3);

    /* M4 = UID | ID | AuthID | ENC_ECB(K3, CID(28) | 1 | 0(99)) */
    for (i = 0u; i < 16u; i++)
    {
        msg->m4[i] = msg->m1[i];
        plain[i] = 0u;
    }
    word0 = ((counter & 0x0FFFFFFFu) << 4) | 0x8u;
    plain[0] = (uint8)(word0 >> 24);
    plain[1] = (uint8)(word0 >> 16);
    plain[2] = (uint8)(word0 >> 8);
    plain[3] = (uint8)(word0);
    (void)Hsm_AesEcbEncrypt(k3, plain, 16u, &msg->m4[16]);

    /* M5 = CMAC(K4, M4) */
    Hsm_Cmac(k4, msg->m4, 32u, msg->m5);

    Hsm_SecureZero(k1, 16u); Hsm_SecureZero(k2, 16u);
    Hsm_SecureZero(k3, 16u); Hsm_SecureZero(k4, 16u);
    Hsm_SecureZero(plain, sizeof(plain));
}

/* SHE: which authorizing keys may update which slot */
static boolean isAuthAllowed(Hsm_KeyIdType keyId, Hsm_KeyIdType authId)
{
    boolean ok = FALSE;

    switch (keyId)
    {
        case HSM_KEY_MASTER_ECU_KEY:
            ok = (authId == HSM_KEY_MASTER_ECU_KEY) ? TRUE : FALSE;
            break;
        case HSM_KEY_BOOT_MAC_KEY:
            ok = ((authId == HSM_KEY_MASTER_ECU_KEY) || (authId == HSM_KEY_BOOT_MAC_KEY)) ? TRUE : FALSE;
            break;
        case HSM_KEY_BOOT_MAC:
            ok = ((authId == HSM_KEY_MASTER_ECU_KEY) || (authId == HSM_KEY_BOOT_MAC_KEY)) ? TRUE : FALSE;
            break;
        case HSM_RAM_KEY:
            ok = ((authId != HSM_KEY_SECRET_KEY) && (authId < HSM_NUM_SHE_SLOTS)) ? TRUE : FALSE;
            break;
        default:
            if ((keyId >= HSM_KEY_1) && (keyId <= HSM_KEY_10))
            {
                ok = ((authId == HSM_KEY_MASTER_ECU_KEY) || (authId == keyId)) ? TRUE : FALSE;
            }
            break;
    }
    return ok;
}

static boolean isWildcardUid(const uint8 uid[15])
{
    uint8 acc = 0u;
    uint8 i;
    for (i = 0u; i < 15u; i++)
    {
        acc |= uid[i];
    }
    return (acc == 0u) ? TRUE : FALSE;
}

Hsm_ErrorType Hsm_SheLoadKey(const uint8 m1[16], const uint8 m2[32], const uint8 m3[16],
                             uint8 m4[32], uint8 m5[16])
{
    static const uint8 zeroIv[16] = { 0u };
    Hsm_NvmType *nvm = Hsm_KeyStoreNvm();
    Hsm_KeyIdType keyId = (Hsm_KeyIdType)(m1[15] >> 4);
    Hsm_KeyIdType authId = (Hsm_KeyIdType)(m1[15] & 0x0Fu);
    Hsm_KeySlotType *target;
    const Hsm_KeySlotType *auth;
    const uint8 *authKey;
    uint8 k1[16], k2[16];
    uint8 mac[16];
    uint8 m1m2[48];
    uint8 plain[32];
    uint32 counter;
    uint8 flags;
    Hsm_SheUpdateMsgType out;
    Hsm_ErrorType erc = HSM_ERC_NO_ERROR;
    uint8 i;

    if ((keyId == HSM_KEY_SECRET_KEY) || (keyId >= HSM_NUM_SHE_SLOTS) ||
        (authId >= HSM_NUM_SHE_SLOTS))
    {
        return HSM_ERC_KEY_INVALID;
    }
    if (isAuthAllowed(keyId, authId) == FALSE)
    {
        return HSM_ERC_KEY_INVALID;
    }
    target = Hsm_KeyStoreSlot(keyId);
    auth = Hsm_KeyStoreSlot(authId);

    /* UID check: own UID or wildcard (if the target slot permits it) */
    if (isWildcardUid(m1) == TRUE)
    {
        if ((target->valid == TRUE) && ((target->flags & HSM_FLAG_WILDCARD) != 0u))
        {
            return HSM_ERC_KEY_UPDATE_ERROR;
        }
    }
    else if (Hsm_ConstTimeEqual(m1, nvm->uid, 15u) == FALSE)
    {
        return HSM_ERC_KEY_UPDATE_ERROR;
    }

    if ((target->valid == TRUE) && ((target->flags & HSM_FLAG_WRITE_PROTECTION) != 0u))
    {
        return HSM_ERC_KEY_WRITE_PROTECTED;
    }

    authKey = (auth->valid == TRUE) ? auth->key : Hsm_She_DefaultKey;

    /* Authenticate M1|M2 with K2 */
    Hsm_SheKdf(authKey, Hsm_She_KeyUpdateMacC, k2);
    for (i = 0u; i < 16u; i++)
    {
        m1m2[i] = m1[i];
    }
    for (i = 0u; i < 32u; i++)
    {
        m1m2[16u + i] = m2[i];
    }
    Hsm_Cmac(k2, m1m2, 48u, mac);
    if (Hsm_ConstTimeEqual(mac, m3, 16u) == FALSE)
    {
        erc = HSM_ERC_KEY_UPDATE_ERROR;
    }

    if (erc == HSM_ERC_NO_ERROR)
    {
        Hsm_SheKdf(authKey, Hsm_She_KeyUpdateEncC, k1);
        (void)Hsm_AesCbcDecrypt(k1, zeroIv, m2, 32u, plain);
        counter = (((uint32)plain[0] << 24) | ((uint32)plain[1] << 16) |
                   ((uint32)plain[2] << 8) | (uint32)plain[3]) >> 4;
        flags = (uint8)(((plain[3] & 0x0Fu) << 1) | (plain[4] >> 7));

        /* Roll-back protection: counter must strictly increase */
        if ((target->valid == TRUE) && (counter <= target->counter))
        {
            erc = HSM_ERC_KEY_UPDATE_ERROR;
        }
        else
        {
            Hsm_KeyStoreWrite(keyId, &plain[16], 16u, flags, counter, FALSE);
            /* Proof of successful update: M4/M5 */
            Hsm_SheGenerateUpdate(m1, keyId, authId, authKey, &plain[16], counter, flags, &out);
            for (i = 0u; i < 32u; i++)
            {
                m4[i] = out.m4[i];
            }
            for (i = 0u; i < 16u; i++)
            {
                m5[i] = out.m5[i];
            }
            /* M4 carries the UID of this device even for wildcard updates */
            for (i = 0u; i < 15u; i++)
            {
                m4[i] = nvm->uid[i];
            }
            if (isWildcardUid(m1) == TRUE)
            {
                /* recompute M5 over the M4 carrying the real UID */
                uint8 k4[16];
                Hsm_SheKdf(&plain[16], Hsm_She_KeyUpdateMacC, k4);
                Hsm_Cmac(k4, m4, 32u, m5);
                Hsm_SecureZero(k4, sizeof(k4));
            }
        }
    }

    Hsm_SecureZero(k1, sizeof(k1));
    Hsm_SecureZero(k2, sizeof(k2));
    Hsm_SecureZero(plain, sizeof(plain));
    Hsm_SecureZero(&out, sizeof(out));
    return erc;
}

Hsm_ErrorType Hsm_SheExportRamKey(Hsm_SheUpdateMsgType *msg)
{
    const Hsm_KeySlotType *ram = Hsm_KeyStoreSlot(HSM_RAM_KEY);
    const Hsm_KeySlotType *secret = Hsm_KeyStoreSlot(HSM_KEY_SECRET_KEY);

    if ((ram->valid == FALSE) || (ram->plain == FALSE))
    {
        return HSM_ERC_KEY_INVALID;
    }
    if (secret->valid == FALSE)
    {
        return HSM_ERC_KEY_EMPTY;
    }
    Hsm_SheGenerateUpdate(Hsm_KeyStoreNvm()->uid, HSM_RAM_KEY, HSM_KEY_SECRET_KEY,
                          secret->key, ram->key, 0u, 0u, msg);
    return HSM_ERC_NO_ERROR;
}

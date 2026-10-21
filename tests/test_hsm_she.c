/**
 * @file  test_hsm_she.c
 * @brief HSM firmware tests: SHE memory update protocol (spec test vector),
 *        key protection flags, secure boot, RNG, debug authorization,
 *        mailbox IPC.
 */
#include "unity_lite.h"
#include "Hsm.h"
#include "Hsm_She.h"
#include "Hsm_KeyStore.h"
#include "hsm_cmac.h"

static uint8 bootImage[1024];
static uint32 bootSize = sizeof(bootImage);
static uint8 entropyCtr;

static const uint8 *getBootImage(uint32 *size) { *size = bootSize; return bootImage; }
static Std_ReturnType getEntropy(uint8 *b, uint32 n)
{
    uint32 i;
    for (i = 0; i < n; i++) { b[i] = (uint8)(0xA5u ^ (i * 7u) ^ entropyCtr); }
    entropyCtr++;
    return E_OK;
}
static const Hsm_PlatformConfigType cfg = { getBootImage, getEntropy };

static uint8 UID[15];
static const uint8 MASTER[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

static void fresh_device(void)
{
    memset(UID, 0, sizeof UID);
    UID[14] = 0x01;
    Hsm_SimSetDebuggerAttached(FALSE);
    Hsm_FactoryReset(UID);
    memset(bootImage, 0x5A, sizeof bootImage);
    Hsm_Init(&cfg);
}

static Hsm_ErrorType load_key(const Hsm_SheUpdateMsgType *m, uint8 m4[32], uint8 m5[16])
{
    uint32 l4 = 32, l5 = 16;
    Hsm_RequestType r = {0};
    r.cmd = HSM_CMD_LOAD_KEY;
    r.in1 = m->m1; r.in1Len = 16;
    r.in2 = m->m2; r.in2Len = 32;
    r.in3 = m->m3; r.in3Len = 16;
    r.out1 = m4; r.out1Len = &l4;
    r.out2 = m5; r.out2Len = &l5;
    return Hsm_ProcessRequest(&r);
}

static Hsm_ErrorType provision(Hsm_KeyIdType id, Hsm_KeyIdType authId, const uint8 *authKey,
                               const uint8 *newKey, uint32 counter, uint8 flags)
{
    Hsm_SheUpdateMsgType m;
    uint8 m4[32], m5[16];
    Hsm_SheGenerateUpdate(UID, id, authId, authKey, newKey, counter, flags, &m);
    return load_key(&m, m4, m5);
}

static Hsm_ErrorType gen_mac(Hsm_KeyIdType id, const uint8 *d, uint32 n, uint8 *mac)
{
    uint32 l = 16;
    Hsm_RequestType r = {0};
    r.cmd = HSM_CMD_GENERATE_MAC; r.keyId = id; r.in1 = d; r.in1Len = n;
    r.out1 = mac; r.out1Len = &l;
    return Hsm_ProcessRequest(&r);
}

/* ------------------------------------------------------------------------ */
static void test_she_kdf_and_mp(void)
{
    /* SHE spec example: KDF(MASTER_ECU_KEY 000102..0f, KEY_UPDATE_ENC_C) */
    uint8 k1[16], exp_[16];
    Hsm_SheKdf(MASTER, Hsm_She_KeyUpdateEncC, k1);
    ut_hex("118a46447a770d87828a69c222e2d17e", exp_);
    TEST_ASSERT_EQUAL_MEMORY(exp_, k1, 16);
}

static void test_she_memory_update_spec_vector(void)
{
    /* Test vector of the SHE functional specification (memory update):
     * AuthID = MASTER_ECU_KEY, ID = KEY_1, counter = 1, flags = 0 */
    static const uint8 newKey[16] = {0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00};
    Hsm_SheUpdateMsgType m;
    uint8 e[32];
    uint8 m4[32], m5[16];

    fresh_device();
    Hsm_SheGenerateUpdate(UID, HSM_KEY_1, HSM_KEY_MASTER_ECU_KEY, MASTER, newKey, 1, 0, &m);
    ut_hex("00000000000000000000000000000141", e); TEST_ASSERT_EQUAL_MEMORY(e, m.m1, 16);
    ut_hex("2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3", e); TEST_ASSERT_EQUAL_MEMORY(e, m.m2, 32);
    ut_hex("b9d745e5ace7d41860bc63c2b9f5bb46", e); TEST_ASSERT_EQUAL_MEMORY(e, m.m3, 16);
    ut_hex("00000000000000000000000000000141b472e8d8727d70d57295e74849a27917", e); TEST_ASSERT_EQUAL_MEMORY(e, m.m4, 32);
    ut_hex("820d8d95dc11b4668878160cb2a4e23e", e); TEST_ASSERT_EQUAL_MEMORY(e, m.m5, 16);

    /* Load the MASTER_ECU_KEY first (authorized by the default/empty key) */
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_MASTER_ECU_KEY, HSM_KEY_MASTER_ECU_KEY,
                                                  Hsm_She_DefaultKey, MASTER, 1, 0));
    /* Now the HSM must accept M1..M3 and answer with M4/M5 from the spec */
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, load_key(&m, m4, m5));
    TEST_ASSERT_EQUAL_MEMORY(m.m4, m4, 32);
    TEST_ASSERT_EQUAL_MEMORY(m.m5, m5, 16);
}

static void test_she_update_rejects_bad_mac_replay_and_wrong_uid(void)
{
    uint8 k[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    Hsm_SheUpdateMsgType m;
    uint8 m4[32], m5[16];
    uint8 otherUid[15] = {0};

    fresh_device();
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_MASTER_ECU_KEY, HSM_KEY_MASTER_ECU_KEY, Hsm_She_DefaultKey, MASTER, 1, 0));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_2, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 5, HSM_FLAG_KEY_USAGE));

    /* tampered M3 */
    Hsm_SheGenerateUpdate(UID, HSM_KEY_2, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 6, HSM_FLAG_KEY_USAGE, &m);
    m.m3[0] ^= 1;
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_UPDATE_ERROR, load_key(&m, m4, m5));
    /* replay / roll-back: counter not increased */
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_UPDATE_ERROR, provision(HSM_KEY_2, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 5, HSM_FLAG_KEY_USAGE));
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_UPDATE_ERROR, provision(HSM_KEY_2, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 4, HSM_FLAG_KEY_USAGE));
    /* wrong UID */
    otherUid[14] = 0x99;
    Hsm_SheGenerateUpdate(otherUid, HSM_KEY_2, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 7, HSM_FLAG_KEY_USAGE, &m);
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_UPDATE_ERROR, load_key(&m, m4, m5));
    /* wrong authorizing key (KEY_3 may not update KEY_2) */
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_INVALID, provision(HSM_KEY_2, HSM_KEY_3, k, k, 8, 0));
    /* SECRET_KEY can never be updated */
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_INVALID, provision(HSM_KEY_SECRET_KEY, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 8, 0));
    /* valid update with higher counter, self-authorized */
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_2, HSM_KEY_2, k, MASTER, 9, HSM_FLAG_KEY_USAGE));
}

static void test_she_wildcard_and_write_protection(void)
{
    uint8 k[16] = {9};
    uint8 wild[15] = {0};
    Hsm_SheUpdateMsgType m;
    uint8 m4[32], m5[16];

    fresh_device();
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_MASTER_ECU_KEY, HSM_KEY_MASTER_ECU_KEY, Hsm_She_DefaultKey, MASTER, 1, 0));
    /* wildcard UID allowed for first load */
    Hsm_SheGenerateUpdate(wild, HSM_KEY_3, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 1, HSM_FLAG_WILDCARD | HSM_FLAG_WRITE_PROTECTION, &m);
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, load_key(&m, m4, m5));
    /* M4 contains the real UID */
    TEST_ASSERT_EQUAL_MEMORY(UID, m4, 15);
    /* write protected key cannot be updated anymore */
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_WRITE_PROTECTED, provision(HSM_KEY_3, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 2, 0));
}

static void test_key_usage_flag_enforced(void)
{
    uint8 kMac[16] = {1}, kEnc[16] = {2};
    uint8 data[16] = {0}, out[16], mac[16];
    uint32 l = 16;
    Hsm_RequestType r = {0};

    fresh_device();
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_MASTER_ECU_KEY, HSM_KEY_MASTER_ECU_KEY, Hsm_She_DefaultKey, MASTER, 1, 0));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_4, HSM_KEY_MASTER_ECU_KEY, MASTER, kMac, 1, HSM_FLAG_KEY_USAGE));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_5, HSM_KEY_MASTER_ECU_KEY, MASTER, kEnc, 1, 0));

    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, gen_mac(HSM_KEY_4, data, 16, mac));
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_INVALID, gen_mac(HSM_KEY_5, data, 16, mac));
    r.cmd = HSM_CMD_ENC_ECB; r.keyId = HSM_KEY_4; r.in1 = data; r.in1Len = 16; r.out1 = out; r.out1Len = &l;
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_INVALID, Hsm_ProcessRequest(&r));
    r.keyId = HSM_KEY_5;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    /* empty slot / reserved slot */
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_EMPTY, gen_mac(HSM_KEY_9, data, 16, mac));
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_INVALID, gen_mac(HSM_KEY_MASTER_ECU_KEY, data, 16, mac));
}

static void test_mac_generate_verify_via_hsm(void)
{
    uint8 k[16];
    uint8 msg[40], mac[16], exp_[16];
    Hsm_RequestType r = {0};

    fresh_device();
    ut_hex("2b7e151628aed2a6abf7158809cf4f3c", k);
    ut_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", msg);
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_MASTER_ECU_KEY, HSM_KEY_MASTER_ECU_KEY, Hsm_She_DefaultKey, MASTER, 1, 0));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_1, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 1, HSM_FLAG_KEY_USAGE));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, gen_mac(HSM_KEY_1, msg, 40, mac));
    ut_hex("dfa66747de9ae63030ca32611497c827", exp_);
    TEST_ASSERT_EQUAL_MEMORY(exp_, mac, 16);

    r.cmd = HSM_CMD_VERIFY_MAC; r.keyId = HSM_KEY_1; r.in1 = msg; r.in1Len = 40; r.in2 = mac; r.in2Len = 128;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    TEST_ASSERT_TRUE(r.verifyResult);
    mac[15] ^= 0x80;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    TEST_ASSERT_FALSE(r.verifyResult);
    r.in2Len = 64;  /* truncated MAC: tampered byte not compared */
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    TEST_ASSERT_TRUE(r.verifyResult);
}

static void test_secure_boot_learn_verify_and_fail(void)
{
    uint8 bootKey[16] = {0xB0,0x07};
    uint8 kProt[16] = {0x77};
    uint8 data[4] = {1,2,3,4}, mac[16];

    fresh_device();
    /* no BOOT_MAC_KEY -> no secure boot */
    TEST_ASSERT_EQUAL(HSM_ERC_NO_SECURE_BOOT, Hsm_GetLastBootResult());
    TEST_ASSERT_TRUE((Hsm_GetStatusRegister() & HSM_SREG_BOOT_OK) == 0);

    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_MASTER_ECU_KEY, HSM_KEY_MASTER_ECU_KEY, Hsm_She_DefaultKey, MASTER, 1, 0));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_BOOT_MAC_KEY, HSM_KEY_MASTER_ECU_KEY, MASTER, bootKey, 1, 0));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_6, HSM_KEY_MASTER_ECU_KEY, MASTER, kProt, 1,
                                                  HSM_FLAG_KEY_USAGE | HSM_FLAG_BOOT_PROTECTION));
    /* boot protected key unusable before a successful secure boot */
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_NOT_AVAILABLE, gen_mac(HSM_KEY_6, data, 4, mac));

    /* reset: BOOT_MAC empty -> learned (autonomous bootstrap) */
    Hsm_Init(&cfg);
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_GetLastBootResult());
    TEST_ASSERT_TRUE(Hsm_KeyStoreSlot(HSM_KEY_BOOT_MAC)->valid);
    {
        /* BOOT_MAC = CMAC(BOOT_MAC_KEY, 0^96 | size_bits | image) */
        uint8 tmp[16 + sizeof bootImage] = {0};
        uint8 exp_[16];
        uint32 bits = bootSize * 8;
        tmp[12] = (uint8)(bits >> 24); tmp[13] = (uint8)(bits >> 16);
        tmp[14] = (uint8)(bits >> 8);  tmp[15] = (uint8)bits;
        memcpy(&tmp[16], bootImage, bootSize);
        Hsm_Cmac(bootKey, tmp, 16 + bootSize, exp_);
        TEST_ASSERT_EQUAL_MEMORY(exp_, Hsm_KeyStoreSlot(HSM_KEY_BOOT_MAC)->key, 16);
    }
    TEST_ASSERT_TRUE((Hsm_GetStatusRegister() & HSM_SREG_BOOT_OK) != 0);
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, gen_mac(HSM_KEY_6, data, 4, mac));

    /* reset with unmodified image -> OK */
    Hsm_Init(&cfg);
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_GetLastBootResult());

    /* tamper one byte of the boot loader -> boot failure, key locked */
    bootImage[500] ^= 0x01;
    Hsm_Init(&cfg);
    TEST_ASSERT_EQUAL(HSM_ERC_VERIFY_FAILED, Hsm_GetLastBootResult());
    TEST_ASSERT_TRUE((Hsm_GetStatusRegister() & HSM_SREG_BOOT_OK) == 0);
    TEST_ASSERT_TRUE((Hsm_GetStatusRegister() & HSM_SREG_BOOT_FINISHED) != 0);
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_NOT_AVAILABLE, gen_mac(HSM_KEY_6, data, 4, mac));
    /* restore -> works again */
    bootImage[500] ^= 0x01;
    Hsm_Init(&cfg);
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, gen_mac(HSM_KEY_6, data, 4, mac));

    /* CMD_BOOT_FAILURE from host locks boot protected keys */
    {
        Hsm_RequestType r = {0};
        r.cmd = HSM_CMD_BOOT_FAILURE;
        TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
        TEST_ASSERT_EQUAL(HSM_ERC_KEY_NOT_AVAILABLE, gen_mac(HSM_KEY_6, data, 4, mac));
        r.cmd = HSM_CMD_BOOT_OK;
        TEST_ASSERT_EQUAL(HSM_ERC_SEQUENCE_ERROR, Hsm_ProcessRequest(&r));
    }
}

static void test_secure_boot_no_learning_in_field(void)
{
    uint8 bootKey[16] = {0xB0,0x07};
    Hsm_RequestType r = {0};
    fresh_device();
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_MASTER_ECU_KEY, HSM_KEY_MASTER_ECU_KEY, Hsm_She_DefaultKey, MASTER, 1, 0));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_BOOT_MAC_KEY, HSM_KEY_MASTER_ECU_KEY, MASTER, bootKey, 1, 0));
    r.cmd = HSM_CMD_SET_LIFECYCLE; r.value = HSM_LC_IN_FIELD;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    r.value = HSM_LC_DEVELOPMENT;  /* cannot go back */
    TEST_ASSERT_EQUAL(HSM_ERC_ACCESS_DENIED, Hsm_ProcessRequest(&r));
    Hsm_Init(&cfg);
    TEST_ASSERT_EQUAL(HSM_ERC_NO_SECURE_BOOT, Hsm_GetLastBootResult());
    TEST_ASSERT_FALSE(Hsm_KeyStoreSlot(HSM_KEY_BOOT_MAC)->valid);
}

static void test_debugger_protection(void)
{
    uint8 k[16] = {3};
    uint8 data[4] = {0}, mac[16];
    fresh_device();
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_MASTER_ECU_KEY, HSM_KEY_MASTER_ECU_KEY, Hsm_She_DefaultKey, MASTER, 1, 0));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_7, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 1,
                                                  HSM_FLAG_KEY_USAGE | HSM_FLAG_DEBUGGER_PROTECTION));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, gen_mac(HSM_KEY_7, data, 4, mac));
    Hsm_SimSetDebuggerAttached(TRUE);
    TEST_ASSERT_EQUAL(HSM_ERC_KEY_NOT_AVAILABLE, gen_mac(HSM_KEY_7, data, 4, mac));
    Hsm_SimSetDebuggerAttached(FALSE);
}

static void test_debug_challenge_authorization(void)
{
    uint8 ch[16], auth[16], kdbg[16], buf[31];
    uint32 l = 16;
    Hsm_RequestType r = {0};
    uint8 k[16] = {4};

    fresh_device();
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_MASTER_ECU_KEY, HSM_KEY_MASTER_ECU_KEY, Hsm_She_DefaultKey, MASTER, 1, 0));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, provision(HSM_KEY_8, HSM_KEY_MASTER_ECU_KEY, MASTER, k, 1, HSM_FLAG_KEY_USAGE));

    r.cmd = HSM_CMD_DEBUG_AUTHORIZATION; r.in1 = auth; r.in1Len = 16;
    TEST_ASSERT_EQUAL(HSM_ERC_SEQUENCE_ERROR, Hsm_ProcessRequest(&r));

    r.cmd = HSM_CMD_DEBUG_CHALLENGE; r.out1 = ch; r.out1Len = &l;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    memset(auth, 0, 16);   /* wrong authorization */
    r.cmd = HSM_CMD_DEBUG_AUTHORIZATION;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_DEBUGGING, Hsm_ProcessRequest(&r));

    r.cmd = HSM_CMD_DEBUG_CHALLENGE;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    Hsm_SheKdf(MASTER, Hsm_She_DebugKeyC, kdbg);
    memcpy(buf, ch, 16); memcpy(&buf[16], UID, 15);
    Hsm_Cmac(kdbg, buf, 31, auth);
    r.cmd = HSM_CMD_DEBUG_AUTHORIZATION;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    TEST_ASSERT_FALSE(Hsm_KeyStoreSlot(HSM_KEY_8)->valid);       /* erased */
    TEST_ASSERT_FALSE(Hsm_KeyStoreSlot(HSM_KEY_MASTER_ECU_KEY)->valid);
}

static void test_rng_and_ram_key_export(void)
{
    uint8 a[32], b[32], o1[64], o2[48];
    uint32 la = 32, lb = 32, l1 = 64, l2 = 48;
    uint8 ram[16] = {0xCA,0xFE};
    uint8 secret[16] = {0x5E,0xC2};
    Hsm_RequestType r = {0};
    Hsm_SheUpdateMsgType chk;

    fresh_device();
    TEST_ASSERT_TRUE((Hsm_GetStatusRegister() & HSM_SREG_RND_INIT) != 0);
    r.cmd = HSM_CMD_RND; r.out1 = a; r.out1Len = &la;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    r.out1 = b; r.out1Len = &lb;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    TEST_ASSERT_TRUE(memcmp(a, b, 32) != 0);

    /* RAM key: load plain and export as M1..M5 protected by SECRET_KEY */
    Hsm_KeyStoreWrite(HSM_KEY_SECRET_KEY, secret, 16, 0, 0, FALSE);
    memset(&r, 0, sizeof r);
    r.cmd = HSM_CMD_LOAD_PLAIN_KEY; r.in1 = ram; r.in1Len = 16;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    r.cmd = HSM_CMD_EXPORT_RAM_KEY; r.out1 = o1; r.out1Len = &l1; r.out2 = o2; r.out2Len = &l2;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    Hsm_SheGenerateUpdate(UID, HSM_RAM_KEY, HSM_KEY_SECRET_KEY, secret, ram, 0, 0, &chk);
    TEST_ASSERT_EQUAL_MEMORY(chk.m1, &o1[0], 16);
    TEST_ASSERT_EQUAL_MEMORY(chk.m2, &o1[16], 32);
    TEST_ASSERT_EQUAL_MEMORY(chk.m3, &o1[48], 16);
    TEST_ASSERT_EQUAL_MEMORY(chk.m5, &o2[32], 16);
    /* RAM_KEY is volatile */
    Hsm_Init(&cfg);
    TEST_ASSERT_FALSE(Hsm_KeyStoreSlot(HSM_RAM_KEY)->valid);
}

static void test_monotonic_counter(void)
{
    Hsm_RequestType r = {0};
    fresh_device();
    r.cmd = HSM_CMD_COUNTER_INCREMENT; r.contextId = 0; r.value = 5;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    r.value = 5;
    TEST_ASSERT_EQUAL(HSM_ERC_COUNTER_OVERFLOW, Hsm_ProcessRequest(&r));
    r.value = 3;
    TEST_ASSERT_EQUAL(HSM_ERC_COUNTER_OVERFLOW, Hsm_ProcessRequest(&r));
    Hsm_Init(&cfg);  /* survives reset (NVM) */
    r.cmd = HSM_CMD_COUNTER_READ; r.value = 0;
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_ProcessRequest(&r));
    TEST_ASSERT_EQUAL(5, r.value);
}

static void test_ipc_mailbox(void)
{
    uint8 d[32], o[32];
    uint32 l = 32;
    Hsm_RequestType r = {0};
    Hsm_IpcHandleType h;

    fresh_device();
    memset(d, 'x', sizeof d);
    r.cmd = HSM_CMD_HASH_SHA256; r.in1 = d; r.in1Len = 32; r.out1 = o; r.out1Len = &l;
    h = Hsm_IpcSubmit(&r);
    TEST_ASSERT_TRUE(h != HSM_IPC_INVALID_HANDLE);
    TEST_ASSERT_EQUAL(HSM_IPC_PENDING, Hsm_IpcGetState(h));
    Hsm_MainFunction();
    TEST_ASSERT_EQUAL(HSM_IPC_DONE, Hsm_IpcGetState(h));
    TEST_ASSERT_EQUAL(HSM_ERC_NO_ERROR, Hsm_IpcRelease(h));
    TEST_ASSERT_EQUAL(HSM_IPC_FREE, Hsm_IpcGetState(h));
    TEST_ASSERT_EQUAL(32, l);
}

int main(void)
{
    printf("Suite: HSM firmware / SHE\n");
    RUN_TEST(test_she_kdf_and_mp);
    RUN_TEST(test_she_memory_update_spec_vector);
    RUN_TEST(test_she_update_rejects_bad_mac_replay_and_wrong_uid);
    RUN_TEST(test_she_wildcard_and_write_protection);
    RUN_TEST(test_key_usage_flag_enforced);
    RUN_TEST(test_mac_generate_verify_via_hsm);
    RUN_TEST(test_secure_boot_learn_verify_and_fail);
    RUN_TEST(test_secure_boot_no_learning_in_field);
    RUN_TEST(test_debugger_protection);
    RUN_TEST(test_debug_challenge_authorization);
    RUN_TEST(test_rng_and_ram_key_export);
    RUN_TEST(test_monotonic_counter);
    RUN_TEST(test_ipc_mailbox);
    return ut_summary("hsm_she");
}

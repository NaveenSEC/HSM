/**
 * @file  test_crypto_primitives.c
 * @brief Known answer tests for the HSM crypto library:
 *        AES-128 (FIPS-197), AES-CBC (SP 800-38A), AES-CMAC (RFC 4493),
 *        SHA-256 (FIPS 180-4), HMAC-SHA-256 (RFC 4231), CTR_DRBG sanity.
 */
#include "unity_lite.h"
#include "hsm_aes.h"
#include "hsm_cmac.h"
#include "hsm_sha256.h"
#include "hsm_drbg.h"

static uint8 key[16], buf[256], exp_[64], out[256];

/* RFC 4493 key and message */
static const char *RFC4493_KEY = "2b7e151628aed2a6abf7158809cf4f3c";
static const char *RFC4493_MSG =
    "6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710";

static void test_aes128_fips197(void)
{
    Hsm_AesCtxType ctx;
    ut_hex("000102030405060708090a0b0c0d0e0f", key);
    ut_hex("00112233445566778899aabbccddeeff", buf);
    ut_hex("69c4e0d86a7b0430d8cdb78070b4c55a", exp_);
    Hsm_AesInit(&ctx, key);
    Hsm_AesEncryptBlock(&ctx, buf, out);
    TEST_ASSERT_EQUAL_MEMORY(exp_, out, 16);
    Hsm_AesDecryptBlock(&ctx, out, out);
    TEST_ASSERT_EQUAL_MEMORY(buf, out, 16);
}

static void test_aes128_cbc_sp800_38a(void)
{
    uint8 iv[16];
    ut_hex(RFC4493_KEY, key);
    ut_hex("000102030405060708090a0b0c0d0e0f", iv);
    ut_hex(RFC4493_MSG, buf);
    ut_hex("7649abac8119b246cee98e9b12e9197d" "5086cb9b507219ee95db113a917678b2"
           "73bed6b8e3c1743b7116e69e22229516" "3ff1caa1681fac09120eca307586e1a7", exp_);
    TEST_ASSERT_EQUAL(E_OK, Hsm_AesCbcEncrypt(key, iv, buf, 64, out));
    TEST_ASSERT_EQUAL_MEMORY(exp_, out, 64);
    TEST_ASSERT_EQUAL(E_OK, Hsm_AesCbcDecrypt(key, iv, out, 64, out)); /* in place */
    TEST_ASSERT_EQUAL_MEMORY(buf, out, 64);
    TEST_ASSERT_EQUAL(E_NOT_OK, Hsm_AesCbcEncrypt(key, iv, buf, 15, out));
}

static void test_aes128_ecb_sp800_38a(void)
{
    ut_hex(RFC4493_KEY, key);
    ut_hex(RFC4493_MSG, buf);
    ut_hex("3ad77bb40d7a3660a89ecaf32466ef97" "f5d3d58503b9699de785895a96fdbaaf", exp_);
    TEST_ASSERT_EQUAL(E_OK, Hsm_AesEcbEncrypt(key, buf, 32, out));
    TEST_ASSERT_EQUAL_MEMORY(exp_, out, 32);
}

static void cmac_case(uint32 len, const char *expected)
{
    uint8 mac[16];
    ut_hex(RFC4493_KEY, key);
    ut_hex(RFC4493_MSG, buf);
    ut_hex(expected, exp_);
    Hsm_Cmac(key, buf, len, mac);
    TEST_ASSERT_EQUAL_MEMORY(exp_, mac, 16);
    TEST_ASSERT_TRUE(Hsm_CmacVerify(key, buf, len, exp_, 128));
}

static void test_cmac_rfc4493_examples(void)
{
    cmac_case(0,  "bb1d6929e95937287fa37d129b756746");
    cmac_case(16, "070a16b46b4d4144f79bdd9dd04a287c");
    cmac_case(40, "dfa66747de9ae63030ca32611497c827");
    cmac_case(64, "51f0bebf7e3b9d92fc49741779363cfe");
}

static void test_cmac_streaming_equals_oneshot(void)
{
    /* Arbitrary chunking must give the same result as one-shot */
    Hsm_CmacCtxType c;
    uint8 mac1[16], mac2[16];
    uint32 chunks[] = { 1, 15, 16, 3, 29 }; /* = 64 */
    uint32 i, off = 0;
    ut_hex(RFC4493_KEY, key);
    ut_hex(RFC4493_MSG, buf);
    Hsm_Cmac(key, buf, 64, mac1);
    Hsm_CmacStart(&c, key);
    for (i = 0; i < 5; i++) { Hsm_CmacUpdate(&c, &buf[off], chunks[i]); off += chunks[i]; }
    Hsm_CmacFinish(&c, mac2);
    TEST_ASSERT_EQUAL_MEMORY(mac1, mac2, 16);
}

static void test_cmac_verify_rejects_tampering_and_truncation(void)
{
    uint8 mac[16];
    ut_hex(RFC4493_KEY, key);
    ut_hex(RFC4493_MSG, buf);
    Hsm_Cmac(key, buf, 64, mac);
    /* truncated MACs (bits) */
    TEST_ASSERT_TRUE(Hsm_CmacVerify(key, buf, 64, mac, 64));
    TEST_ASSERT_TRUE(Hsm_CmacVerify(key, buf, 64, mac, 28));
    /* flipped bit in message */
    buf[10] ^= 0x01;
    TEST_ASSERT_FALSE(Hsm_CmacVerify(key, buf, 64, mac, 128));
    buf[10] ^= 0x01;
    /* flipped bit inside the compared portion of MAC */
    mac[3] ^= 0x10;
    TEST_ASSERT_FALSE(Hsm_CmacVerify(key, buf, 64, mac, 32));
    /* outside compared bits -> still OK (truncation semantics) */
    TEST_ASSERT_TRUE(Hsm_CmacVerify(key, buf, 64, mac, 24));
    TEST_ASSERT_FALSE(Hsm_CmacVerify(key, buf, 64, mac, 0));
    TEST_ASSERT_FALSE(Hsm_CmacVerify(key, buf, 64, mac, 129));
}

static void test_sha256_fips180(void)
{
    uint8 d[32];
    uint8 big[1000];
    Hsm_Sha256CtxType c;
    int i;

    Hsm_Sha256((const uint8 *)"abc", 3, d);
    ut_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", exp_);
    TEST_ASSERT_EQUAL_MEMORY(exp_, d, 32);

    Hsm_Sha256((const uint8 *)"", 0, d);
    ut_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", exp_);
    TEST_ASSERT_EQUAL_MEMORY(exp_, d, 32);

    Hsm_Sha256((const uint8 *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    ut_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", exp_);
    TEST_ASSERT_EQUAL_MEMORY(exp_, d, 32);

    /* one million 'a' */
    memset(big, 'a', sizeof big);
    Hsm_Sha256Start(&c);
    for (i = 0; i < 1000; i++) { Hsm_Sha256Update(&c, big, 1000); }
    Hsm_Sha256Finish(&c, d);
    ut_hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", exp_);
    TEST_ASSERT_EQUAL_MEMORY(exp_, d, 32);
}

static void test_hmac_sha256_rfc4231(void)
{
    uint8 k[131], m[32];
    size_t n;
    /* Test case 1 */
    memset(k, 0x0b, 20);
    Hsm_HmacSha256(k, 20, (const uint8 *)"Hi There", 8, m);
    ut_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", exp_);
    TEST_ASSERT_EQUAL_MEMORY(exp_, m, 32);
    /* Test case 2 */
    Hsm_HmacSha256((const uint8 *)"Jefe", 4, (const uint8 *)"what do ya want for nothing?", 28, m);
    ut_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", exp_);
    TEST_ASSERT_EQUAL_MEMORY(exp_, m, 32);
    /* Test case 6: key larger than block size */
    memset(k, 0xaa, 131);
    n = strlen("Test Using Larger Than Block-Size Key - Hash Key First");
    Hsm_HmacSha256(k, 131, (const uint8 *)"Test Using Larger Than Block-Size Key - Hash Key First", (uint32)n, m);
    ut_hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", exp_);
    TEST_ASSERT_EQUAL_MEMORY(exp_, m, 32);
}

static void test_drbg_basic(void)
{
    Hsm_DrbgCtxType d1, d2;
    uint8 seed[32], a[48], b[48];
    memset(seed, 0x42, sizeof seed);
    memset(&d1, 0, sizeof d1);
    TEST_ASSERT_EQUAL(E_NOT_OK, Hsm_DrbgGenerate(&d1, a, 16));
    TEST_ASSERT_EQUAL(E_OK, Hsm_DrbgInstantiate(&d1, seed));
    TEST_ASSERT_EQUAL(E_OK, Hsm_DrbgInstantiate(&d2, seed));
    TEST_ASSERT_EQUAL(E_OK, Hsm_DrbgGenerate(&d1, a, 48));
    TEST_ASSERT_EQUAL(E_OK, Hsm_DrbgGenerate(&d2, b, 48));
    TEST_ASSERT_EQUAL_MEMORY(a, b, 48);           /* deterministic */
    TEST_ASSERT_EQUAL(E_OK, Hsm_DrbgGenerate(&d1, b, 48));
    TEST_ASSERT_TRUE(memcmp(a, b, 48) != 0);       /* state advances */
    seed[0] ^= 1;
    TEST_ASSERT_EQUAL(E_OK, Hsm_DrbgReseed(&d2, seed));
    TEST_ASSERT_EQUAL(E_OK, Hsm_DrbgGenerate(&d2, a, 48));
    TEST_ASSERT_TRUE(memcmp(a, b, 48) != 0);
}

int main(void)
{
    printf("Suite: HSM crypto primitives\n");
    RUN_TEST(test_aes128_fips197);
    RUN_TEST(test_aes128_ecb_sp800_38a);
    RUN_TEST(test_aes128_cbc_sp800_38a);
    RUN_TEST(test_cmac_rfc4493_examples);
    RUN_TEST(test_cmac_streaming_equals_oneshot);
    RUN_TEST(test_cmac_verify_rejects_tampering_and_truncation);
    RUN_TEST(test_sha256_fips180);
    RUN_TEST(test_hmac_sha256_rfc4231);
    RUN_TEST(test_drbg_basic);
    return ut_summary("crypto_primitives");
}

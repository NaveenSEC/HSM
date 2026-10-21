/**
 * @file    unity_lite.h
 * @brief   Minimal unit test framework (Unity-like API) for host tests.
 */
#ifndef UNITY_LITE_H
#define UNITY_LITE_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern int ut_failures;
extern int ut_assertions;
extern int ut_tests;
extern const char *ut_current;

#define UT_FAIL(msg) do { \
    ut_failures++; \
    printf("    FAIL %s:%d [%s] %s\n", __FILE__, __LINE__, ut_current, msg); \
} while (0)

#define TEST_ASSERT(cond) do { ut_assertions++; if (!(cond)) { UT_FAIL(#cond); } } while (0)
#define TEST_ASSERT_TRUE(c)  TEST_ASSERT(c)
#define TEST_ASSERT_FALSE(c) TEST_ASSERT(!(c))
#define TEST_ASSERT_EQUAL(exp, act) do { \
    long long e_ = (long long)(exp), a_ = (long long)(act); ut_assertions++; \
    if (e_ != a_) { char m_[512]; snprintf(m_, sizeof m_, "%s: expected %lld (0x%llx) got %lld (0x%llx)", \
        #act, e_, (unsigned long long)e_, a_, (unsigned long long)a_); UT_FAIL(m_); } } while (0)
#define TEST_ASSERT_EQUAL_MEMORY(exp, act, len) do { ut_assertions++; \
    if (memcmp((exp), (act), (len)) != 0) { UT_FAIL("memory mismatch: " #act); \
        ut_dump("expected", (const uint8_t *)(exp), (len)); ut_dump("actual  ", (const uint8_t *)(act), (len)); } } while (0)

#define RUN_TEST(fn) do { \
    int f_ = ut_failures; ut_current = #fn; ut_tests++; fn(); \
    printf("  [%s] %s\n", (ut_failures == f_) ? "PASS" : "FAIL", #fn); } while (0)

void ut_dump(const char *label, const uint8_t *p, size_t len);
size_t ut_hex(const char *hex, uint8_t *out);
int  ut_summary(const char *suite);

#endif

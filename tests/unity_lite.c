#include "unity_lite.h"

int ut_failures = 0;
int ut_assertions = 0;
int ut_tests = 0;
const char *ut_current = "";

void ut_dump(const char *label, const uint8_t *p, size_t len)
{
    size_t i;
    printf("      %s: ", label);
    for (i = 0; i < len; i++) { printf("%02x", p[i]); }
    printf("\n");
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t ut_hex(const char *hex, uint8_t *out)
{
    size_t n = 0;
    while (hex[0] && hex[1])
    {
        if (hexval(hex[0]) < 0) { hex++; continue; }
        out[n++] = (uint8_t)((hexval(hex[0]) << 4) | hexval(hex[1]));
        hex += 2;
    }
    return n;
}

int ut_summary(const char *suite)
{
    printf("== %s: %d tests, %d assertions, %d failures ==\n",
           suite, ut_tests, ut_assertions, ut_failures);
    return ut_failures == 0 ? 0 : 1;
}

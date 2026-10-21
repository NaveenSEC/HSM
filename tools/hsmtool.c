/**
 * @file    hsmtool.c
 * @brief   Back-end command line tool.
 *
 *  hsmtool cmac      <key-hex> <file>
 *  hsmtool sha256    <file>
 *  hsmtool sign-app  <key-hex> <sw-version> <body.bin> <out.img>
 *  hsmtool verify-app <key-hex> <app.img>
 *  hsmtool keyupdate <uid-hex(15B)> <key-id> <auth-id> <auth-key-hex> <new-key-hex> <counter> <flags>
 *  hsmtool bootmac   <boot-mac-key-hex> <bootcode.bin>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Backend.h"
#include "Hsm_She.h"
#include "hsm_cmac.h"
#include "hsm_sha256.h"
#include "AppHeader.h"
#include "MemMap_Layout.h"

static int hexval(char c)
{
    if ((c >= '0') && (c <= '9')) { return c - '0'; }
    if ((c >= 'a') && (c <= 'f')) { return c - 'a' + 10; }
    if ((c >= 'A') && (c <= 'F')) { return c - 'A' + 10; }
    return -1;
}

static int parseHex(const char *s, uint8 *out, size_t expect)
{
    size_t n = strlen(s), i;
    if (n != expect * 2u) { return -1; }
    for (i = 0; i < expect; i++)
    {
        int h = hexval(s[2u * i]), l = hexval(s[2u * i + 1u]);
        if ((h < 0) || (l < 0)) { return -1; }
        out[i] = (uint8)((h << 4) | l);
    }
    return 0;
}

static void printHex(const char *label, const uint8 *p, size_t n)
{
    size_t i;
    printf("%s", label);
    for (i = 0; i < n; i++) { printf("%02x", p[i]); }
    printf("\n");
}

static uint8 *readFile(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8 *buf;
    long sz;
    if (f == NULL) { return NULL; }
    (void)fseek(f, 0, SEEK_END);
    sz = ftell(f);
    (void)fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    buf = (uint8 *)malloc((size_t)sz + 1u);
    if ((buf != NULL) && (fread(buf, 1, (size_t)sz, f) != (size_t)sz)) { free(buf); buf = NULL; }
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

static int usage(void)
{
    fprintf(stderr,
        "usage:\n"
        "  hsmtool cmac       <key-hex16> <file>\n"
        "  hsmtool sha256     <file>\n"
        "  hsmtool sign-app   <key-hex16> <sw-version> <body.bin> <out.img>\n"
        "  hsmtool verify-app <key-hex16> <app.img>\n"
        "  hsmtool keyupdate  <uid-hex15> <key-id> <auth-id> <auth-key-hex16> <new-key-hex16> <counter> <flags>\n"
        "  hsmtool bootmac    <boot-mac-key-hex16> <bootcode.bin>\n");
    return 2;
}

int main(int argc, char **argv)
{
    uint8 key[16], mac[16], dig[32];
    size_t len = 0;
    uint8 *data;

    if (argc < 2) { return usage(); }

    if ((strcmp(argv[1], "cmac") == 0) && (argc == 4))
    {
        if (parseHex(argv[2], key, 16) != 0) { return usage(); }
        data = readFile(argv[3], &len);
        if (data == NULL) { perror(argv[3]); return 1; }
        Hsm_Cmac(key, data, (uint32)len, mac);
        printHex("CMAC: ", mac, 16);
        free(data);
        return 0;
    }
    if ((strcmp(argv[1], "sha256") == 0) && (argc == 3))
    {
        data = readFile(argv[2], &len);
        if (data == NULL) { perror(argv[2]); return 1; }
        Hsm_Sha256(data, (uint32)len, dig);
        printHex("SHA-256: ", dig, 32);
        free(data);
        return 0;
    }
    if ((strcmp(argv[1], "sign-app") == 0) && (argc == 6))
    {
        uint8 *out;
        uint32 outLen = 0;
        FILE *f;
        if (parseHex(argv[2], key, 16) != 0) { return usage(); }
        data = readFile(argv[4], &len);
        if (data == NULL) { perror(argv[4]); return 1; }
        out = (uint8 *)malloc(len + APP_HEADER_SIZE);
        if ((out == NULL) || (Backend_BuildAppImage((uint32)strtoul(argv[3], NULL, 0), data, (uint32)len, key,
                                                    out, (uint32)(len + APP_HEADER_SIZE), &outLen) != E_OK))
        {
            fprintf(stderr, "signing failed (body size 1..%u bytes)\n", (unsigned)APP_BODY_MAX);
            return 1;
        }
        f = fopen(argv[5], "wb");
        if ((f == NULL) || (fwrite(out, 1, outLen, f) != outLen)) { perror(argv[5]); return 1; }
        fclose(f);
        printHex("header CMAC: ", &out[APPHDR_OFF_MAC], 16);
        printf("wrote %u bytes to %s\n", (unsigned)outLen, argv[5]);
        free(out);
        free(data);
        return 0;
    }
    if ((strcmp(argv[1], "verify-app") == 0) && (argc == 4))
    {
        AppHeader_Type h;
        boolean macOk;
        if (parseHex(argv[2], key, 16) != 0) { return usage(); }
        data = readFile(argv[3], &len);
        if ((data == NULL) || (len < APP_HEADER_SIZE)) { fprintf(stderr, "bad image\n"); return 1; }
        AppHeader_Parse(data, &h);
        macOk = Hsm_CmacVerify(key, data, APPHDR_SIGNED_LEN, h.mac, 128u);
        Hsm_Sha256(&data[APP_HEADER_SIZE], (uint32)(len - APP_HEADER_SIZE), dig);
        printf("magic %s, sw version %u, size %u\n", h.magic == APPHDR_MAGIC ? "OK" : "BAD",
               (unsigned)h.swVersion, (unsigned)h.size);
        printf("header CMAC : %s\n", macOk ? "VALID" : "INVALID");
        printf("body digest : %s\n", (memcmp(dig, h.digest, 32) == 0 && h.size == len - APP_HEADER_SIZE) ? "VALID" : "INVALID");
        free(data);
        return (macOk && memcmp(dig, h.digest, 32) == 0) ? 0 : 1;
    }
    if ((strcmp(argv[1], "keyupdate") == 0) && (argc == 9))
    {
        uint8 uid[15], authKey[16], newKey[16];
        Hsm_SheUpdateMsgType m;
        if ((parseHex(argv[2], uid, 15) != 0) || (parseHex(argv[5], authKey, 16) != 0) ||
            (parseHex(argv[6], newKey, 16) != 0)) { return usage(); }
        Hsm_SheGenerateUpdate(uid, (uint8)strtoul(argv[3], NULL, 0), (uint8)strtoul(argv[4], NULL, 0),
                              authKey, newKey, (uint32)strtoul(argv[7], NULL, 0),
                              (uint8)strtoul(argv[8], NULL, 0), &m);
        printHex("M1: ", m.m1, 16);
        printHex("M2: ", m.m2, 32);
        printHex("M3: ", m.m3, 16);
        printHex("M4: ", m.m4, 32);
        printHex("M5: ", m.m5, 16);
        return 0;
    }
    if ((strcmp(argv[1], "bootmac") == 0) && (argc == 4))
    {
        Hsm_CmacCtxType c;
        uint8 hdr[16] = { 0 };
        uint32 bits;
        if (parseHex(argv[2], key, 16) != 0) { return usage(); }
        data = readFile(argv[3], &len);
        if (data == NULL) { perror(argv[3]); return 1; }
        bits = (uint32)len * 8u;
        hdr[12] = (uint8)(bits >> 24); hdr[13] = (uint8)(bits >> 16);
        hdr[14] = (uint8)(bits >> 8);  hdr[15] = (uint8)bits;
        Hsm_CmacStart(&c, key);
        Hsm_CmacUpdate(&c, hdr, 16);
        Hsm_CmacUpdate(&c, data, (uint32)len);
        Hsm_CmacFinish(&c, mac);
        printHex("BOOT_MAC: ", mac, 16);
        free(data);
        return 0;
    }
    return usage();
}

/**
 * @file    Backend.h
 * @brief   OEM back-end functions (run off-board, e.g. in the key server /
 *          build system): application image signing, SHE key update message
 *          generation, security access key calculation.
 */
#ifndef BACKEND_H
#define BACKEND_H

#include "Std_Types.h"
#include "Hsm_She.h"

typedef struct
{
    uint8 masterEcuKey[16];
    uint8 bootMacKey[16];
    uint8 flashVerifyKey[16];
    uint8 diagKey[16];
    uint8 secocKey[16];
    uint8 cipherKey[16];
    uint8 hmacKey[32];
} Backend_KeySetType;

extern const Backend_KeySetType Backend_DemoKeys;

/** Build a signed application image: header (128 B) + body */
Std_ReturnType Backend_BuildAppImage(uint32 swVersion, const uint8 *body, uint32 bodyLen,
                                     const uint8 flashKey[16], uint8 *out, uint32 outMax,
                                     uint32 *outLen);

/** UDS 0x27 key = AES-CMAC(diagKey, seed) */
void Backend_SecurityAccessKey(const uint8 diagKey[16], const uint8 *seed, uint32 seedLen, uint8 key[16]);

/** Deterministic demo application body */
void Backend_BuildDemoAppBody(uint32 swVersion, uint8 *body, uint32 len);

#endif

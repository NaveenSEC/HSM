/**
 * @file    Hsm_Types.h
 * @brief   Public types of the HSM firmware (host <-> HSM mailbox interface).
 *
 * The HSM is modelled as a SHE (Secure Hardware Extension, AUTOSAR/HIS SHE
 * Functional Specification v1.1) compatible security core with a set of
 * extensions (SHA-256, HMAC, streaming MAC, monotonic counters, lifecycle).
 */
#ifndef HSM_TYPES_H
#define HSM_TYPES_H

#include "Std_Types.h"

/* ------------------------------------------------------------------------ */
/* Key slots (SHE memory slots + HSM extended slots)                        */
/* ------------------------------------------------------------------------ */
typedef uint8 Hsm_KeyIdType;

#define HSM_KEY_SECRET_KEY       0x00u
#define HSM_KEY_MASTER_ECU_KEY   0x01u
#define HSM_KEY_BOOT_MAC_KEY     0x02u
#define HSM_KEY_BOOT_MAC         0x03u
#define HSM_KEY_1                0x04u
#define HSM_KEY_2                0x05u
#define HSM_KEY_3                0x06u
#define HSM_KEY_4                0x07u
#define HSM_KEY_5                0x08u
#define HSM_KEY_6                0x09u
#define HSM_KEY_7                0x0Au
#define HSM_KEY_8                0x0Bu
#define HSM_KEY_9                0x0Cu
#define HSM_KEY_10               0x0Du
#define HSM_RAM_KEY              0x0Eu
#define HSM_NUM_SHE_SLOTS        0x0Fu

/* Extended slots (non-SHE): up to 32 byte keys, e.g. HMAC-SHA-256 keys     */
#define HSM_KEY_EXT_0            0x10u
#define HSM_NUM_EXT_SLOTS        8u
#define HSM_NUM_KEY_SLOTS        (0x10u + HSM_NUM_EXT_SLOTS)

#define HSM_MAX_KEY_LEN          32u

/* SHE key protection flags (bit positions as in M2: WP|BP|DP|KU|WC)          */
#define HSM_FLAG_WRITE_PROTECTION     0x10u
#define HSM_FLAG_BOOT_PROTECTION      0x08u
#define HSM_FLAG_DEBUGGER_PROTECTION  0x04u
#define HSM_FLAG_KEY_USAGE            0x02u   /* 1: MAC key, 0: cipher key */
#define HSM_FLAG_WILDCARD             0x01u   /* 1: wildcard UID forbidden */

/* ------------------------------------------------------------------------ */
/* Error codes (SHE ERC_xxx)                                                 */
/* ------------------------------------------------------------------------ */
typedef uint8 Hsm_ErrorType;

#define HSM_ERC_NO_ERROR             0x00u
#define HSM_ERC_SEQUENCE_ERROR       0x01u
#define HSM_ERC_KEY_NOT_AVAILABLE    0x02u
#define HSM_ERC_KEY_INVALID          0x03u
#define HSM_ERC_KEY_EMPTY            0x04u
#define HSM_ERC_NO_SECURE_BOOT       0x05u
#define HSM_ERC_KEY_WRITE_PROTECTED  0x06u
#define HSM_ERC_KEY_UPDATE_ERROR     0x07u
#define HSM_ERC_RNG_SEED             0x08u
#define HSM_ERC_NO_DEBUGGING         0x09u
#define HSM_ERC_BUSY                 0x0Au
#define HSM_ERC_MEMORY_FAILURE       0x0Bu
#define HSM_ERC_GENERAL_ERROR        0x0Cu
/* Extensions */
#define HSM_ERC_VERIFY_FAILED        0x10u
#define HSM_ERC_SMALL_BUFFER         0x11u
#define HSM_ERC_PARAM                0x12u
#define HSM_ERC_ACCESS_DENIED        0x13u
#define HSM_ERC_COUNTER_OVERFLOW     0x14u

/* ------------------------------------------------------------------------ */
/* Status register (SHE SREG)                                                */
/* ------------------------------------------------------------------------ */
#define HSM_SREG_BUSY          0x01u
#define HSM_SREG_SECURE_BOOT   0x02u
#define HSM_SREG_BOOT_INIT     0x04u
#define HSM_SREG_BOOT_FINISHED 0x08u
#define HSM_SREG_BOOT_OK       0x10u
#define HSM_SREG_RND_INIT      0x20u
#define HSM_SREG_EXT_DEBUGGER  0x40u
#define HSM_SREG_INT_DEBUGGER  0x80u

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------ */
typedef enum
{
    HSM_LC_DEVELOPMENT = 0,   /* plain key injection allowed                 */
    HSM_LC_PRODUCTION  = 1,   /* OEM provisioning, plain injection allowed   */
    HSM_LC_IN_FIELD    = 2    /* locked: only SHE M1..M5 key updates         */
} Hsm_LifecycleType;

/* ------------------------------------------------------------------------ */
/* Commands                                                                  */
/* ------------------------------------------------------------------------ */
typedef enum
{
    /* SHE standard commands */
    HSM_CMD_ENC_ECB = 0x01,
    HSM_CMD_ENC_CBC,
    HSM_CMD_DEC_ECB,
    HSM_CMD_DEC_CBC,
    HSM_CMD_GENERATE_MAC,
    HSM_CMD_VERIFY_MAC,
    HSM_CMD_LOAD_KEY,
    HSM_CMD_LOAD_PLAIN_KEY,
    HSM_CMD_EXPORT_RAM_KEY,
    HSM_CMD_INIT_RNG,
    HSM_CMD_EXTEND_SEED,
    HSM_CMD_RND,
    HSM_CMD_SECURE_BOOT,
    HSM_CMD_BOOT_FAILURE,
    HSM_CMD_BOOT_OK,
    HSM_CMD_GET_ID,
    HSM_CMD_CANCEL,
    HSM_CMD_DEBUG_CHALLENGE,
    HSM_CMD_DEBUG_AUTHORIZATION,
    /* HSM extensions */
    HSM_CMD_MAC_START = 0x40,
    HSM_CMD_MAC_UPDATE,
    HSM_CMD_MAC_FINISH,
    HSM_CMD_HASH_SHA256,
    HSM_CMD_HASH_START,
    HSM_CMD_HASH_UPDATE,
    HSM_CMD_HASH_FINISH,
    HSM_CMD_HMAC_GENERATE,
    HSM_CMD_HMAC_VERIFY,
    HSM_CMD_LOAD_PLAIN_KEY_EXT,
    HSM_CMD_KEY_STATUS,
    HSM_CMD_COUNTER_READ,
    HSM_CMD_COUNTER_INCREMENT,
    HSM_CMD_SET_LIFECYCLE,
    HSM_CMD_GET_STATUS
} Hsm_CommandType;

#define HSM_NUM_CONTEXTS     8u    /* parallel streaming jobs (channels)      */
#define HSM_NUM_COUNTERS     4u    /* monotonic counters (anti roll-back)     */

/**
 * @brief Mailbox request descriptor. The host fills the descriptor, the HSM
 *        consumes the input buffers and writes the output buffers.
 */
typedef struct
{
    Hsm_CommandType cmd;
    Hsm_KeyIdType   keyId;
    uint8           contextId;     /* streaming channel / counter id / misc  */
    const uint8    *in1;           /* primary input (data / M1 / plaintext) */
    uint32          in1Len;        /* bytes (MAC verify: data length)        */
    const uint8    *in2;           /* secondary input (IV / MAC / M2 ...)    */
    uint32          in2Len;        /* bytes, for VERIFY_MAC: MAC length bits */
    const uint8    *in3;           /* tertiary input (M3)                    */
    uint32          in3Len;
    uint8          *out1;          /* primary output                         */
    uint32         *out1Len;       /* in: capacity, out: written bytes       */
    uint8          *out2;          /* secondary output (M5)                  */
    uint32         *out2Len;
    uint32          value;         /* scalar in/out (counter, flags ...)     */
    boolean         verifyResult;  /* MAC verification result (TRUE = OK)    */
} Hsm_RequestType;

#endif /* HSM_TYPES_H */

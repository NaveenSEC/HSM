/**
 * @file    Crypto_GeneralTypes.h
 * @brief   Crypto stack common types (AUTOSAR_SWS_CryptoServiceManager,
 *          AUTOSAR_SWS_CryptoInterface, AUTOSAR_SWS_CryptoDriver - R4.4/R20-11)
 *
 * NOTE: type and API names follow the AUTOSAR crypto stack. The numeric values
 *       of the enumerations are project local; align them with the AUTOSAR
 *       release used by your integration before mixing with 3rd party BSW.
 */
#ifndef CRYPTO_GENERALTYPES_H
#define CRYPTO_GENERALTYPES_H

#include "Std_Types.h"

/* Std_ReturnType extension of the crypto stack */
#define CRYPTO_E_BUSY                 0x02u
#define CRYPTO_E_SMALL_BUFFER         0x03u
#define CRYPTO_E_ENTROPY_EXHAUSTED    0x04u
#define CRYPTO_E_QUEUE_FULL           0x05u
#define CRYPTO_E_KEY_READ_FAIL        0x06u
#define CRYPTO_E_KEY_WRITE_FAIL       0x07u
#define CRYPTO_E_KEY_NOT_AVAILABLE    0x08u
#define CRYPTO_E_KEY_NOT_VALID        0x09u
#define CRYPTO_E_KEY_SIZE_MISMATCH    0x0Au
#define CRYPTO_E_JOB_CANCELED         0x0Cu
#define CRYPTO_E_KEY_EMPTY            0x0Du

/* Crypto_ServiceInfoType */
typedef enum
{
    CRYPTO_HASH                  = 0x00,
    CRYPTO_MACGENERATE           = 0x01,
    CRYPTO_MACVERIFY             = 0x02,
    CRYPTO_ENCRYPT               = 0x03,
    CRYPTO_DECRYPT               = 0x04,
    CRYPTO_AEADENCRYPT           = 0x05,
    CRYPTO_AEADDECRYPT           = 0x06,
    CRYPTO_SIGNATUREGENERATE     = 0x07,
    CRYPTO_SIGNATUREVERIFY       = 0x08,
    CRYPTO_RANDOMGENERATE        = 0x0B,
    CRYPTO_RANDOMSEED            = 0x0C,
    CRYPTO_KEYGENERATE           = 0x0D,
    CRYPTO_KEYDERIVE             = 0x0E,
    CRYPTO_KEYSETVALID           = 0x13
} Crypto_ServiceInfoType;

/* Crypto_AlgorithmFamilyType (subset) */
typedef enum
{
    CRYPTO_ALGOFAM_NOT_SET   = 0x00,
    CRYPTO_ALGOFAM_SHA2_256  = 0x03,
    CRYPTO_ALGOFAM_AES       = 0x14,
    CRYPTO_ALGOFAM_RNG       = 0x1B,
    CRYPTO_ALGOFAM_CUSTOM    = 0xFF
} Crypto_AlgorithmFamilyType;

/* Crypto_AlgorithmModeType (subset) */
typedef enum
{
    CRYPTO_ALGOMODE_NOT_SET  = 0x00,
    CRYPTO_ALGOMODE_ECB      = 0x01,
    CRYPTO_ALGOMODE_CBC      = 0x02,
    CRYPTO_ALGOMODE_HMAC     = 0x0F,
    CRYPTO_ALGOMODE_CMAC     = 0x10,
    CRYPTO_ALGOMODE_CTRDRBG  = 0x12,
    CRYPTO_ALGOMODE_CUSTOM   = 0xFF
} Crypto_AlgorithmModeType;

/* Crypto_JobStateType */
typedef enum
{
    CRYPTO_JOBSTATE_IDLE   = 0x00,
    CRYPTO_JOBSTATE_ACTIVE = 0x01
} Crypto_JobStateType;

/* Crypto_ProcessingType */
typedef enum
{
    CRYPTO_PROCESSING_ASYNC = 0x00,
    CRYPTO_PROCESSING_SYNC  = 0x01
} Crypto_ProcessingType;

/* Crypto_VerifyResultType */
typedef enum
{
    CRYPTO_E_VER_OK     = 0x00,
    CRYPTO_E_VER_NOT_OK = 0x01
} Crypto_VerifyResultType;

/* Crypto_OperationModeType (bit mask) */
typedef uint8 Crypto_OperationModeType;
#define CRYPTO_OPERATIONMODE_START        0x01u
#define CRYPTO_OPERATIONMODE_UPDATE       0x02u
#define CRYPTO_OPERATIONMODE_STREAMSTART  0x03u
#define CRYPTO_OPERATIONMODE_FINISH       0x04u
#define CRYPTO_OPERATIONMODE_SINGLECALL   0x07u

/* Key element ids (AUTOSAR) + vendor specific SHE elements */
#define CRYPTO_KE_MAC_KEY             1u
#define CRYPTO_KE_MAC_PROOF           2u
#define CRYPTO_KE_RANDOM_SEED_STATE   3u
#define CRYPTO_KE_RANDOM_ALGORITHM    4u
#define CRYPTO_KE_CIPHER_KEY          1u
#define CRYPTO_KE_CIPHER_IV           5u
#define CRYPTO_KE_CIPHER_PROOF        6u
#define CRYPTO_KE_CUSTOM_SHE_M1M2M3   0x1001u  /* write: 64 byte M1|M2|M3   */
#define CRYPTO_KE_CUSTOM_SHE_M4M5     0x1002u  /* read : 48 byte M4|M5      */
#define CRYPTO_KE_CUSTOM_SHE_COUNTER  0x1003u  /* read : 4 byte key counter */

typedef uint8 Crypto_ResultType;  /* alias of Std_ReturnType values above   */

typedef struct
{
    Crypto_AlgorithmFamilyType family;
    Crypto_AlgorithmFamilyType secondaryFamily;
    uint32                     keyLength;
    Crypto_AlgorithmModeType   mode;
} Crypto_AlgorithmInfoType;

typedef struct
{
    uint32                   resultLength;
    Crypto_ServiceInfoType   service;
    Crypto_AlgorithmInfoType algorithm;
} Crypto_PrimitiveInfoType;

typedef struct
{
    uint32                          callbackId;
    const Crypto_PrimitiveInfoType *primitiveInfo;
    uint32                          cryIfKeyId;
    Crypto_ProcessingType           processingType;
    boolean                         callbackUpdateNotification;
} Crypto_JobPrimitiveInfoType;

typedef struct
{
    uint32 jobId;
    uint32 jobPriority;
} Crypto_JobInfoType;

typedef struct
{
    const uint8              *inputPtr;
    uint32                    inputLength;
    const uint8              *secondaryInputPtr;
    uint32                    secondaryInputLength;
    const uint8              *tertiaryInputPtr;
    uint32                    tertiaryInputLength;
    uint8                    *outputPtr;
    uint32                   *outputLengthPtr;
    uint8                    *secondaryOutputPtr;
    uint32                   *secondaryOutputLengthPtr;
    Crypto_VerifyResultType  *verifyPtr;
    Crypto_OperationModeType  mode;
} Crypto_JobPrimitiveInputOutputType;

typedef struct
{
    uint32                              jobId;
    Crypto_JobStateType                 jobState;
    Crypto_JobPrimitiveInputOutputType  jobPrimitiveInputOutput;
    const Crypto_JobPrimitiveInfoType  *jobPrimitiveInfo;
    const Crypto_JobInfoType           *jobInfo;
    uint32                              cryptoKeyId;   /* set by CryIf      */
} Crypto_JobType;

#endif /* CRYPTO_GENERALTYPES_H */

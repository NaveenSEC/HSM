/**
 * @file    ImageVerify.h
 * @brief   Application image authenticity check (used by Boot Manager and
 *          Bootloader). All cryptographic operations are executed by the HSM
 *          through the AUTOSAR CSM.
 */
#ifndef IMAGEVERIFY_H
#define IMAGEVERIFY_H

#include "Std_Types.h"

typedef enum
{
    IMGV_OK = 0,
    IMGV_NO_IMAGE,          /* header magic / version invalid  */
    IMGV_BAD_SIZE,
    IMGV_DIGEST_MISMATCH,   /* SHA-256 of body differs         */
    IMGV_MAC_INVALID,       /* header CMAC verification failed */
    IMGV_ROLLBACK,          /* sw version below HSM counter    */
    IMGV_CRYPTO_ERROR       /* key not available, HSM error    */
} ImageVerify_ResultType;

ImageVerify_ResultType ImageVerify_Application(uint32 *swVersion);
const char            *ImageVerify_ResultString(ImageVerify_ResultType r);

#endif

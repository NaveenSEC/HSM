/**
 * @file    Bootloader.h
 * @brief   UDS (ISO 14229) flash bootloader with HSM backed security.
 *
 * Supported services:
 *   0x10 DiagnosticSessionControl   (01 default, 02 programming, 03 extended)
 *   0x11 ECUReset                   (01 hard reset)
 *   0x22 ReadDataByIdentifier       (F180 boot SW version, F181 app SW version,
 *                                    F18C ECU UID, FD00 HSM status)
 *   0x27 SecurityAccess             (11 requestSeed, 12 sendKey)
 *                                    key = AES-CMAC(KEY_DIAG, seed) - verified by HSM
 *   0x31 RoutineControl             (FF00 eraseMemory, FF01 checkProgrammingDependencies)
 *   0x34 RequestDownload
 *   0x36 TransferData
 *   0x37 RequestTransferExit
 *   0x3E TesterPresent
 */
#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include "Std_Types.h"

#define BL_VERSION_MAJOR         1u
#define BL_VERSION_MINOR         0u
#define BL_VERSION_PATCH         0u

#define BL_MAX_BLOCK_LEN         0x402u   /* incl. SID + block sequence counter */
#define BL_SEED_LEN              16u
#define BL_MAX_ATTEMPTS          3u

/* UDS NRCs */
#define UDS_NRC_SNS              0x11u   /* serviceNotSupported                  */
#define UDS_NRC_SFNS             0x12u   /* subFunctionNotSupported              */
#define UDS_NRC_IMLOIF           0x13u   /* incorrectMessageLengthOrInvalidFormat*/
#define UDS_NRC_CNC              0x22u   /* conditionsNotCorrect                 */
#define UDS_NRC_RSE              0x24u   /* requestSequenceError                 */
#define UDS_NRC_ROOR             0x31u   /* requestOutOfRange                    */
#define UDS_NRC_SAD              0x33u   /* securityAccessDenied                 */
#define UDS_NRC_IK               0x35u   /* invalidKey                           */
#define UDS_NRC_ENOA             0x36u   /* exceededNumberOfAttempts             */
#define UDS_NRC_RTDNE            0x37u   /* requiredTimeDelayNotExpired          */
#define UDS_NRC_UDNA             0x70u   /* uploadDownloadNotAccepted            */
#define UDS_NRC_GPF              0x72u   /* generalProgrammingFailure            */
#define UDS_NRC_WBSC             0x73u   /* wrongBlockSequenceCounter            */
#define UDS_NRC_SNSIAS           0x7Fu   /* serviceNotSupportedInActiveSession   */

#define BL_ROUTINE_ERASE         0xFF00u
#define BL_ROUTINE_CHECK_DEPS    0xFF01u

void    Bootloader_Init(void);
/** Handle one UDS request. Returns response length (0 = no response). */
uint32  Bootloader_HandleRequest(const uint8 *req, uint32 reqLen, uint8 *resp, uint32 respMax);
boolean Bootloader_IsResetRequested(void);

#endif

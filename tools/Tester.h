/**
 * @file    Tester.h
 * @brief   Off-board diagnostic tester: UDS re-programming sequence.
 */
#ifndef TESTER_H
#define TESTER_H

#include "Std_Types.h"

typedef enum
{
    TESTER_OK = 0,
    TESTER_ENTER_PROG_FAILED,
    TESTER_SECURITY_FAILED,
    TESTER_ERASE_FAILED,
    TESTER_DOWNLOAD_FAILED,
    TESTER_CHECK_FAILED,
    TESTER_RESET_FAILED
} Tester_ResultType;

typedef struct
{
    uint8  lastNrc;          /* last negative response code (0 = none)  */
    uint8  checkReason;      /* ImageVerify result from routine FF01     */
    uint32 requests;         /* number of UDS requests sent              */
    boolean verbose;
} Tester_InfoType;

extern Tester_InfoType Tester_Info;

/** Send request and return response length */
uint32            Tester_Request(const uint8 *req, uint32 len, uint8 *resp);
Tester_ResultType Tester_Unlock(const uint8 diagKey[16]);
/** Full re-programming sequence (session, unlock, erase, download, check, reset) */
Tester_ResultType Tester_FlashApplication(const uint8 *image, uint32 len, const uint8 diagKey[16]);
const char       *Tester_ResultString(Tester_ResultType r);

#endif

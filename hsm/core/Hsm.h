/**
 * @file    Hsm.h
 * @brief   HSM firmware top level API.
 *
 * Two interfaces are provided:
 *  - Hsm_ProcessRequest(): direct (synchronous) command execution on the HSM
 *  - Hsm_Ipc*():           mailbox interface between host core and HSM core.
 *                          The host posts requests, the HSM core consumes them
 *                          in Hsm_MainFunction() (simulating a separate core).
 */
#ifndef HSM_H
#define HSM_H

#include "Hsm_Types.h"

/** Platform hooks of the HSM (filled by the ECU integration) */
typedef struct
{
    /* Read-only access of the HSM to host flash for secure boot */
    const uint8 *(*getBootImage)(uint32 *sizeBytes);
    /* True random number generator (entropy source) */
    Std_ReturnType (*getEntropy)(uint8 *buf, uint32 len);
} Hsm_PlatformConfigType;

/* ---- life cycle ------------------------------------------------------- */
void           Hsm_FactoryReset(const uint8 uid[15]);   /* virgin device      */
void           Hsm_Init(const Hsm_PlatformConfigType *cfg); /* power-on reset */
uint8          Hsm_GetStatusRegister(void);
Hsm_ErrorType  Hsm_GetLastBootResult(void);

/* ---- simulation hooks ------------------------------------------------- */
void           Hsm_SimSetDebuggerAttached(boolean attached);

/* ---- command execution ----------------------------------------------- */
Hsm_ErrorType  Hsm_ProcessRequest(Hsm_RequestType *req);

/* ---- mailbox (IPC) ---------------------------------------------------- */
#define HSM_IPC_QUEUE_LEN 8u
typedef uint8 Hsm_IpcHandleType;
#define HSM_IPC_INVALID_HANDLE 0xFFu

typedef enum
{
    HSM_IPC_FREE = 0,
    HSM_IPC_PENDING,
    HSM_IPC_DONE
} Hsm_IpcStateType;

Hsm_IpcHandleType Hsm_IpcSubmit(Hsm_RequestType *req);
Hsm_IpcStateType  Hsm_IpcGetState(Hsm_IpcHandleType h);
Hsm_ErrorType     Hsm_IpcRelease(Hsm_IpcHandleType h);  /* returns ERC     */
void              Hsm_MainFunction(void);                /* HSM core loop   */

#endif /* HSM_H */

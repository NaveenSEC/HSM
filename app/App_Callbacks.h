/**
 * @file    App_Callbacks.h
 * @brief   CSM job-finished callbacks of the application (async jobs).
 */
#ifndef APP_CALLBACKS_H
#define APP_CALLBACKS_H

#include "Std_Types.h"

typedef struct
{
    uint32         count;
    uint32         lastJobId;
    Std_ReturnType lastResult;
} App_CsmNotificationType;

extern App_CsmNotificationType App_CsmNotification;

void App_CsmJobFinished(uint32 jobId, Std_ReturnType result);

#endif

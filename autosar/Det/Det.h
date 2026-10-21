/**
 * @file    Det.h
 * @brief   AUTOSAR Default Error Tracer (simplified, AUTOSAR_SWS_DefaultErrorTracer)
 */
#ifndef DET_H
#define DET_H

#include "Std_Types.h"

#define DET_LOG_SIZE 16u

typedef struct
{
    uint16 moduleId;
    uint8  instanceId;
    uint8  apiId;
    uint8  errorId;
} Det_ErrorEntryType;

void           Det_Init(void);
Std_ReturnType Det_ReportError(uint16 ModuleId, uint8 InstanceId, uint8 ApiId, uint8 ErrorId);
Std_ReturnType Det_ReportRuntimeError(uint16 ModuleId, uint8 InstanceId, uint8 ApiId, uint8 ErrorId);

/* test / diagnostic helpers */
uint32                    Det_GetErrorCount(void);
const Det_ErrorEntryType *Det_GetLastError(void);

#endif /* DET_H */

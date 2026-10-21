/**
 * @file    Det.c
 * @brief   Default Error Tracer: records errors in a ring buffer.
 */
#include "Det.h"

static Det_ErrorEntryType Det_Log[DET_LOG_SIZE];
static uint32 Det_Count;

void Det_Init(void)
{
    uint32 i;
    for (i = 0u; i < DET_LOG_SIZE; i++)
    {
        Det_Log[i].moduleId = 0u;
        Det_Log[i].instanceId = 0u;
        Det_Log[i].apiId = 0u;
        Det_Log[i].errorId = 0u;
    }
    Det_Count = 0u;
}

Std_ReturnType Det_ReportError(uint16 ModuleId, uint8 InstanceId, uint8 ApiId, uint8 ErrorId)
{
    Det_ErrorEntryType *e = &Det_Log[Det_Count % DET_LOG_SIZE];
    e->moduleId = ModuleId;
    e->instanceId = InstanceId;
    e->apiId = ApiId;
    e->errorId = ErrorId;
    Det_Count++;
    return E_OK;
}

Std_ReturnType Det_ReportRuntimeError(uint16 ModuleId, uint8 InstanceId, uint8 ApiId, uint8 ErrorId)
{
    return Det_ReportError(ModuleId, InstanceId, ApiId, ErrorId);
}

uint32 Det_GetErrorCount(void)
{
    return Det_Count;
}

const Det_ErrorEntryType *Det_GetLastError(void)
{
    if (Det_Count == 0u)
    {
        return NULL_PTR;
    }
    return &Det_Log[(Det_Count - 1u) % DET_LOG_SIZE];
}

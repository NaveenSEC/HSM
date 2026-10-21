/**
 * @file    Std_Types.h
 * @brief   AUTOSAR Standard Types (AUTOSAR_SWS_StandardTypes)
 */
#ifndef STD_TYPES_H
#define STD_TYPES_H

#include "Platform_Types.h"
#include "Compiler.h"

typedef uint8 Std_ReturnType;

#ifndef STATUSTYPEDEFINED
#define STATUSTYPEDEFINED
#define E_OK            0x00u
typedef unsigned char StatusType;
#endif
#define E_NOT_OK        0x01u

#define STD_HIGH        0x01u
#define STD_LOW         0x00u
#define STD_ACTIVE      0x01u
#define STD_IDLE        0x00u
#define STD_ON          0x01u
#define STD_OFF         0x00u

typedef struct
{
    uint16 vendorID;
    uint16 moduleID;
    uint8  sw_major_version;
    uint8  sw_minor_version;
    uint8  sw_patch_version;
} Std_VersionInfoType;

#endif /* STD_TYPES_H */

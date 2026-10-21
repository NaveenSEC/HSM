/**
 * @file    Platform_Types.h
 * @brief   AUTOSAR Platform Types (AUTOSAR_SWS_PlatformTypes)
 */
#ifndef PLATFORM_TYPES_H
#define PLATFORM_TYPES_H

#include <stdint.h>

#define CPU_TYPE_8      8u
#define CPU_TYPE_16     16u
#define CPU_TYPE_32     32u
#define CPU_TYPE_64     64u

#define MSB_FIRST       0u
#define LSB_FIRST       1u
#define HIGH_BYTE_FIRST 0u
#define LOW_BYTE_FIRST  1u

#define CPU_TYPE        CPU_TYPE_32
#define CPU_BIT_ORDER   LSB_FIRST
#define CPU_BYTE_ORDER  LOW_BYTE_FIRST

#ifndef TRUE
#define TRUE  1u
#endif
#ifndef FALSE
#define FALSE 0u
#endif

typedef uint8_t   boolean;
typedef int8_t    sint8;
typedef uint8_t   uint8;
typedef int16_t   sint16;
typedef uint16_t  uint16;
typedef int32_t   sint32;
typedef uint32_t  uint32;
typedef int64_t   sint64;
typedef uint64_t  uint64;
typedef float     float32;
typedef double    float64;

#endif /* PLATFORM_TYPES_H */

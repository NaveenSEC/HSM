/**
 * @file    Compiler.h
 * @brief   AUTOSAR Compiler abstraction (simplified for host build)
 */
#ifndef COMPILER_H
#define COMPILER_H

#define AUTOMATIC
#define TYPEDEF
#define STATIC      static
#define INLINE      inline
#define LOCAL_INLINE static inline

#ifndef NULL_PTR
#define NULL_PTR    ((void *)0)
#endif

#define FUNC(rettype, memclass)                     rettype
#define P2VAR(ptrtype, memclass, ptrclass)          ptrtype *
#define P2CONST(ptrtype, memclass, ptrclass)        const ptrtype *
#define CONSTP2VAR(ptrtype, memclass, ptrclass)     ptrtype * const
#define CONST(type, memclass)                       const type
#define VAR(type, memclass)                         type

#endif /* COMPILER_H */

#pragma once

#include <arch/arch.h>
#include <drivers/logger.h>
#include <libs/klibc.h>

typedef uint8_t u8_t;
typedef int8_t s8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;
typedef uint64_t u64_t;
typedef int64_t s64_t;
typedef uintptr_t mem_ptr_t;
typedef ssize_t ssize_t;

#define U8_F "u"
#define X8_F "x"
#define U16_F "u"
#define S16_F "d"
#define X16_F "x"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define U64_F "llu"
#define S64_F "lld"
#define X64_F "llx"
#define SZT_F "zu"

#define LWIP_NO_STDINT_H 1
#define LWIP_NO_CTYPE_H 1
#define LWIP_NO_INTTYPES_H 1
#define LWIP_NO_LIMITS_H 1
#define LWIP_NO_STDDEF_H 1
#define LWIP_NO_STDIO_H 1
#define LWIP_NO_STDLIB_H 1
#define LWIP_NO_STRING_H 1
#define LWIP_NO_UNISTD_H 1

#ifndef INT_MAX
#define INT_MAX 2147483647
#endif

#ifndef SSIZE_MAX
#define SSIZE_MAX INT_MAX
#endif

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#define LWIP_CHKSUM_ALGORITHM 3

#define LWIP_PLATFORM_DIAG(x) printk x
#define LWIP_PLATFORM_ASSERT(x)                                                \
    do {                                                                       \
        printk("lwIP assert: %s\n", x);                                        \
        for (;;) {                                                             \
            arch_pause();                                                      \
        }                                                                      \
    } while (0)

#define LWIP_RAND() ((u32_t)nano_time())

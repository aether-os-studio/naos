#pragma once

#include <libs/klibc.h>

#define __csr_str1(x) #x
#define __csr_str(x) __csr_str1(x)

#define csr_read(csr)                                                          \
    ({                                                                         \
        uint64_t __v;                                                          \
        asm volatile("csrrd %0, " __csr_str(csr) : "=r"(__v));                 \
        __v;                                                                   \
    })

#define csr_write(csr, val)                                                    \
    ({                                                                         \
        uint64_t __v = (val);                                                  \
        asm volatile("csrwr %0, " __csr_str(csr) : : "r"(__v));                \
    })

#define csr_set(csr, mask)                                                     \
    ({                                                                         \
        uint64_t __m = (mask);                                                 \
        asm volatile("csrxchg %0, %0, " __csr_str(csr)                         \
                     : "+r"(__m)                                               \
                     :                                                         \
                     : "memory");                                              \
    })

#define csr_clear(csr, mask)                                                   \
    ({                                                                         \
        uint64_t __z = 0;                                                      \
        uint64_t __m = (mask);                                                 \
        asm volatile("csrxchg %0, %1, " __csr_str(csr)                         \
                     : "+r"(__z)                                               \
                     : "r"(__m)                                                \
                     : "memory");                                              \
    })

#define LOONGARCH_CSR_CRMD 0x0
#define LOONGARCH_CSR_PGDL 0x19
#define LOONGARCH_CSR_PGDH 0x1a
#define LOONGARCH_CSR_PGD 0x1b

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
#define LOONGARCH_CSR_PRMD 0x1
#define LOONGARCH_CSR_ECFG 0x4
#define LOONGARCH_CSR_ESTAT 0x5
#define LOONGARCH_CSR_ERA 0x6
#define LOONGARCH_CSR_BADV 0x7
#define LOONGARCH_CSR_EENTRY 0xc
#define LOONGARCH_CSR_PGDL 0x19
#define LOONGARCH_CSR_PGDH 0x1a
#define LOONGARCH_CSR_PGD 0x1b
#define LOONGARCH_CSR_CPUID 0x20
#define LOONGARCH_CSR_TCFG 0x41
#define LOONGARCH_CSR_TVAL 0x42
#define LOONGARCH_CSR_TICLR 0x44

#define LOONGARCH_CRMD_IE (1UL << 2)

#define LOONGARCH_ESTAT_IS_SHIFT 0
#define LOONGARCH_ESTAT_IS_MASK 0x1fffUL
#define LOONGARCH_ESTAT_ECODE_SHIFT 16
#define LOONGARCH_ESTAT_ECODE_MASK 0x3fUL
#define LOONGARCH_ECFG_VS_MASK (0x7UL << 16)

#define LOONGARCH_ECODE_INT 0
#define LOONGARCH_ECODE_SYS 0xb

#define LOONGARCH_INT_TIMER 11
#define LOONGARCH_ECFG_TIMER (1UL << LOONGARCH_INT_TIMER)

#define LOONGARCH_TCFG_EN (1UL << 0)
#define LOONGARCH_TCFG_PERIODIC (1UL << 1)
#define LOONGARCH_TCFG_INITVAL_SHIFT 2

#define LOONGARCH_TICLR_CLR (1UL << 0)

#define LOONGARCH_PRMD_PPLV_MASK 0x3UL
#define LOONGARCH_PRMD_PIE (1UL << 2)

#define LOONGARCH_PLV_KERNEL 0UL
#define LOONGARCH_PLV_USER 3UL
#define LOONGARCH_PRMD_USER (LOONGARCH_PLV_USER | LOONGARCH_PRMD_PIE)

#define LOONGARCH_ECODE_PIL 0x1
#define LOONGARCH_ECODE_PIS 0x2
#define LOONGARCH_ECODE_PIF 0x3
#define LOONGARCH_ECODE_PME 0x4
#define LOONGARCH_ECODE_PNR 0x5
#define LOONGARCH_ECODE_PNX 0x6
#define LOONGARCH_ECODE_PPI 0x7

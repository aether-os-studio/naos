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

static inline uint32_t iocsr_read32(uint32_t reg) {
    uint32_t value;
    asm volatile("iocsrrd.w %0, %1" : "=r"(value) : "r"(reg) : "memory");
    return value;
}

static inline uint64_t iocsr_read64(uint32_t reg) {
    uint64_t value;
    asm volatile("iocsrrd.d %0, %1" : "=r"(value) : "r"(reg) : "memory");
    return value;
}

static inline void iocsr_write32(uint32_t reg, uint32_t value) {
    asm volatile("iocsrwr.w %0, %1" : : "r"(value), "r"(reg) : "memory");
}

static inline void iocsr_write64(uint32_t reg, uint64_t value) {
    asm volatile("iocsrwr.d %0, %1" : : "r"(value), "r"(reg) : "memory");
}

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
#define LOONGARCH_CSR_PWCTL0 0x1c
#define LOONGARCH_CSR_PWCTL1 0x1d
#define LOONGARCH_CSR_STLBPGSIZE 0x1e
#define LOONGARCH_CSR_CPUID 0x20
#define LOONGARCH_CSR_TCFG 0x41
#define LOONGARCH_CSR_TVAL 0x42
#define LOONGARCH_CSR_TICLR 0x44
#define LOONGARCH_CSR_KS0 0x30
#define LOONGARCH_CSR_KS1 0x31
#define LOONGARCH_CSR_KS2 0x32
#define LOONGARCH_CSR_KS3 0x33
#define LOONGARCH_CSR_KS4 0x34
#define LOONGARCH_CSR_EUEN 0x2
#define LOONGARCH_CSR_TLBRENTRY 0x88
#define LOONGARCH_CSR_DMWIN0 0x180
#define LOONGARCH_CSR_DMWIN1 0x181
#define LOONGARCH_CSR_DMWIN2 0x182
#define LOONGARCH_CSR_DMWIN3 0x183

#define LOONGARCH_CRMD_PLV_MASK 0x3UL
#define LOONGARCH_CRMD_IE (1UL << 2)
#define LOONGARCH_CRMD_DA (1UL << 3)
#define LOONGARCH_CRMD_PG (1UL << 4)

#define LOONGARCH_EUEN_FPE (1UL << 0)
#define LOONGARCH_EUEN_SXE (1UL << 1)
#define LOONGARCH_EUEN_ASXE (1UL << 2)

#define LOONGARCH_ESTAT_IS_SHIFT 0
#define LOONGARCH_ESTAT_IS_MASK 0x1fffUL
#define LOONGARCH_ESTAT_ECODE_SHIFT 16
#define LOONGARCH_ESTAT_ECODE_MASK 0x3fUL
#define LOONGARCH_ECFG_VS_MASK (0x7UL << 16)

#define LOONGARCH_ECODE_INT 0
#define LOONGARCH_ECODE_SYS 0xb
#define LOONGARCH_ECODE_FPD 0xf
#define LOONGARCH_ECODE_SXD 0x10
#define LOONGARCH_ECODE_ASXD 0x11

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

#define LOONGARCH_IOCSR_IPI_STATUS 0x1000
#define LOONGARCH_IOCSR_IPI_EN 0x1004
#define LOONGARCH_IOCSR_IPI_SET 0x1008
#define LOONGARCH_IOCSR_IPI_CLEAR 0x100c
#define LOONGARCH_IOCSR_MBUF0 0x1020
#define LOONGARCH_IOCSR_MBUF1 0x1028
#define LOONGARCH_IOCSR_MBUF2 0x1030
#define LOONGARCH_IOCSR_MBUF3 0x1038
#define LOONGARCH_IOCSR_IPI_SEND 0x1040
#define LOONGARCH_IOCSR_MBUF_SEND 0x1048

#define LOONGARCH_IOCSR_IPI_SEND_IP_SHIFT 0
#define LOONGARCH_IOCSR_IPI_SEND_CPU_SHIFT 16
#define LOONGARCH_IOCSR_IPI_SEND_BLOCKING (1UL << 31)
#define LOONGARCH_IOCSR_MBUF_SEND_BLOCKING (1ULL << 31)
#define LOONGARCH_IOCSR_MBUF_SEND_BOX_SHIFT 2
#define LOONGARCH_IOCSR_MBUF_SEND_CPU_SHIFT 16

static inline void loongarch_iocsr_send_ipi(uint32_t cpu, uint32_t action) {
    uint32_t command = LOONGARCH_IOCSR_IPI_SEND_BLOCKING |
                       (cpu << LOONGARCH_IOCSR_IPI_SEND_CPU_SHIFT) |
                       (action << LOONGARCH_IOCSR_IPI_SEND_IP_SHIFT);
    iocsr_write32(LOONGARCH_IOCSR_IPI_SEND, command);
}

static inline void loongarch_iocsr_send_mbuf64(uint32_t cpu, uint32_t mailbox,
                                               uint64_t data) {
    uint64_t command = LOONGARCH_IOCSR_MBUF_SEND_BLOCKING |
                       ((uint64_t)cpu << LOONGARCH_IOCSR_MBUF_SEND_CPU_SHIFT);
    uint64_t box_hi = (((uint64_t)mailbox << 1) + 1)
                      << LOONGARCH_IOCSR_MBUF_SEND_BOX_SHIFT;
    uint64_t box_lo = ((uint64_t)mailbox << 1)
                      << LOONGARCH_IOCSR_MBUF_SEND_BOX_SHIFT;

    iocsr_write64(LOONGARCH_IOCSR_MBUF_SEND,
                  command | box_hi | (data & 0xffffffff00000000ULL));
    iocsr_write64(LOONGARCH_IOCSR_MBUF_SEND, command | box_lo | (data << 32));
}

static inline void loongarch_iocsr_clear_mbuf(uint32_t cpu, uint32_t mailbox) {
    loongarch_iocsr_send_mbuf64(cpu, mailbox, 0);
}

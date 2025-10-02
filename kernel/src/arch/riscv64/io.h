#pragma once

#include <libs/klibc.h>

/* CSR操作宏 */
#define csr_read(csr)                                                          \
    ({                                                                         \
        uint64_t __v;                                                          \
        asm volatile("csrr %0, " #csr : "=r"(__v) : : "memory");               \
        __v;                                                                   \
    })

#define csr_write(csr, val)                                                    \
    ({                                                                         \
        uint64_t __v = (uint64_t)(val);                                        \
        asm volatile("csrw " #csr ", %0" : : "r"(__v) : "memory");             \
    })

#define csr_set(csr, val)                                                      \
    ({                                                                         \
        uint64_t __v = (uint64_t)(val);                                        \
        asm volatile("csrs " #csr ", %0" : : "r"(__v) : "memory");             \
    })

#define csr_clear(csr, val)                                                    \
    ({                                                                         \
        uint64_t __v = (uint64_t)(val);                                        \
        asm volatile("csrc " #csr ", %0" : : "r"(__v) : "memory");             \
    })

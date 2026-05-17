#pragma once

#include <libs/klibc.h>
#include <stddef.h>

#define NO_SYSCALL ((uint64_t)-1)

struct pt_regs {
    uint64_t ra;
    uint64_t sp;
    uint64_t gp;
    uint64_t tp;
    uint64_t t0;
    uint64_t t1;
    uint64_t t2;
    uint64_t t3;
    uint64_t t4;
    uint64_t t5;
    uint64_t t6;
    uint64_t t7;
    uint64_t t8;
    uint64_t r21;
    uint64_t fp;
    uint64_t s0;
    uint64_t s1;
    uint64_t s2;
    uint64_t s3;
    uint64_t s4;
    uint64_t s5;
    uint64_t s6;
    uint64_t s7;
    uint64_t s8;
    uint64_t a0;
    uint64_t a1;
    uint64_t a2;
    uint64_t a3;
    uint64_t a4;
    uint64_t a5;
    uint64_t a6;
    uint64_t a7;
    uint64_t pc;
    uint64_t usp;
    uint64_t csr_prmd;
    uint64_t csr_estat;
    uint64_t csr_badv;
    uint64_t syscallno;
};

_Static_assert(offsetof(struct pt_regs, pc) == 256,
               "loongarch64 entry.S pt_regs pc offset mismatch");
_Static_assert(sizeof(struct pt_regs) == 304,
               "loongarch64 entry.S pt_regs size mismatch");

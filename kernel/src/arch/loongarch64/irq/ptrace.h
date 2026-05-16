#pragma once

#include <libs/klibc.h>

#define NO_SYSCALL ((uint64_t)-1)

struct pt_regs {
    uint64_t ra;
    uint64_t sp;
    uint64_t gp;
    uint64_t tp;
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
    uint64_t syscallno;
};

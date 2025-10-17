#pragma once

#include <libs/klibc.h>

struct pt_regs {
    uint64_t epc;     // sepc
    uint64_t ra;      // Return address
    uint64_t sp;      // Stack pointer
    uint64_t gp;      // Global pointer
    uint64_t tp;      // NX_Thread pointer
    uint64_t t0;      // Temporary
    uint64_t t1;      // Temporary
    uint64_t t2;      // Temporary
    uint64_t s0;      // Saved register/frame pointer
    uint64_t s1;      // Saved register
    uint64_t a0;      // Function argument/return value
    uint64_t a1;      // Function argument/return value
    uint64_t a2;      // Function argument
    uint64_t a3;      // Function argument
    uint64_t a4;      // Function argument
    uint64_t a5;      // Function argument
    uint64_t a6;      // Function argument
    uint64_t a7;      // Function argument
    uint64_t s2;      // Saved register
    uint64_t s3;      // Saved register
    uint64_t s4;      // Saved register
    uint64_t s5;      // Saved register
    uint64_t s6;      // Saved register
    uint64_t s7;      // Saved register
    uint64_t s8;      // Saved register
    uint64_t s9;      // Saved register
    uint64_t s10;     // Saved register
    uint64_t s11;     // Saved register
    uint64_t t3;      // Temporary
    uint64_t t4;      // Temporary
    uint64_t t5;      // Temporary
    uint64_t t6;      // Temporary
    uint64_t sstatus; // sstatus
};

#pragma once

#include <libs/klibc.h>

#define NO_SYSCALL ((uint64_t)-1)

struct pt_regs {
    uint64_t pc;
    uint64_t cpsr;
    uint64_t origin_x0;
    uint64_t syscallno;
    uint64_t sp_el0;
    uint64_t x30;
    uint64_t x28;
    uint64_t x29;
    uint64_t x26;
    uint64_t x27;
    uint64_t x24;
    uint64_t x25;
    uint64_t x22;
    uint64_t x23;
    uint64_t x20;
    uint64_t x21;
    uint64_t x18;
    uint64_t x19;
    uint64_t x16;
    uint64_t x17;
    uint64_t x14;
    uint64_t x15;
    uint64_t x12;
    uint64_t x13;
    uint64_t x10;
    uint64_t x11;
    uint64_t x8;
    uint64_t x9;
    uint64_t x6;
    uint64_t x7;
    uint64_t x4;
    uint64_t x5;
    uint64_t x2;
    uint64_t x3;
    uint64_t x0;
    uint64_t x1;
} __attribute__((packed));

_Static_assert(sizeof(struct pt_regs) == 0x120,
               "aarch64 pt_regs must stay 16-byte aligned");
_Static_assert(offsetof(struct pt_regs, pc) == 0x00,
               "pt_regs.pc offset must match entry.S");
_Static_assert(offsetof(struct pt_regs, cpsr) == 0x08,
               "pt_regs.cpsr offset must match entry.S");
_Static_assert(offsetof(struct pt_regs, origin_x0) == 0x10,
               "pt_regs.origin_x0 offset must match entry.S");
_Static_assert(offsetof(struct pt_regs, syscallno) == 0x18,
               "pt_regs.syscallno offset must match entry.S");
_Static_assert(offsetof(struct pt_regs, sp_el0) == 0x20,
               "pt_regs.sp_el0 offset must match entry.S");
_Static_assert(offsetof(struct pt_regs, x30) == 0x28,
               "pt_regs.x30 offset must match entry.S");

#pragma once

#include <libs/klibc.h>

struct pt_regs {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rax;
    uint64_t reserved;
    uint64_t orig_rax;
    uint64_t func;
    uint64_t errcode;
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
} __attribute__((packed));

_Static_assert(sizeof(struct pt_regs) == 0xc0,
               "x86_64 pt_regs must stay 16-byte aligned");
_Static_assert(offsetof(struct pt_regs, orig_rax) == 0x80,
               "x86_64 syscall asm pt_regs offset mismatch");
_Static_assert(offsetof(struct pt_regs, errcode) == 0x90,
               "x86_64 entry asm pt_regs offset mismatch");
_Static_assert(offsetof(struct pt_regs, rip) == 0x98,
               "x86_64 iret frame offset mismatch");
_Static_assert(offsetof(struct pt_regs, rsp) == 0xb0,
               "x86_64 iret frame offset mismatch");

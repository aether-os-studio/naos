#pragma once

#include <libs/klibc.h>

#define IA32_FS_BASE 0xc0000100

#define IA32_GS_BASE 0xc0000101

#define IA32_KERNEL_GS_BASE 0xc0000102

extern uint64_t (*read_fsbase)();
extern void (*write_fsbase)(uint64_t value);
extern uint64_t (*read_gsbase)();
extern void (*write_gsbase)(uint64_t value);

uint64_t read_kgsbase();
void write_kgsbase(uint64_t value);

static inline uint32_t has_fsgsbase()
{
    uint32_t eax, ebx, ecx, edx;
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0x07), "c"(0x00));
    return ebx & (1 << 0);
}

uint64_t fsgsbase_init();

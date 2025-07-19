#pragma once

#include <arch/x64/syscall/nr.h>
#include <arch/x64/irq/gate.h>
#include <drivers/kernel_logger.h>
#include <libs/klibc.h>

struct utsname
{
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

// MSR寄存器地址定义
#define MSR_EFER 0xC0000080         // EFER MSR寄存器
#define MSR_STAR 0xC0000081         // STAR MSR寄存器
#define MSR_LSTAR 0xC0000082        // LSTAR MSR寄存器
#define MSR_SYSCALL_MASK 0xC0000084 // SYSCALL_MASK MSR寄存器

extern void syscall_exception();

#define NR_SYSCALL 500

typedef uint64_t (*syscall_handler_t)(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
typedef uint64_t (*special_syscall_handler_t)(struct pt_regs *regs, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);
extern syscall_handler_t syscall_handlers[NR_SYSCALL];

void syscall_init();

void syscall_handlers_init();

static inline uint64_t syscall_dummy_handler()
{
    return 0;
}

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

void syscall_init();

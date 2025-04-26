#pragma once

#include <arch/x64/syscall/nr.h>
#include <arch/x64/irq/gate.h>
#include <drivers/kernel_logger.h>
#include <libs/klibc.h>

// MSR寄存器地址定义
#define MSR_EFER 0xC0000080         // EFER MSR寄存器
#define MSR_STAR 0xC0000081         // STAR MSR寄存器
#define MSR_LSTAR 0xC0000082        // LSTAR MSR寄存器
#define MSR_SYSCALL_MASK 0xC0000084 // SYSCALL_MASK MSR寄存器

extern void syscall_exception();

void syscall_init();

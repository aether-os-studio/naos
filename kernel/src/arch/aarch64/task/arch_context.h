#pragma once

#include <libs/klibc.h>
#include <task/task.h>
#include <arch/aarch64/irq/ptrace.h>
#include <arch/elf.h>

#define __sysop_encode(op1, crn, crm, op2) \
    "#" #op1 ",C" #crn ",C" #crm ",#" #op2

#define tlbi_alle1 __sysop_encode(4, 8, 7, 4)
#define tlbi_aside1 __sysop_encode(0, 8, 7, 2)
#define tlbi_rvaae1 __sysop_encode(0, 8, 6, 3)
#define tlbi_rvae1 __sysop_encode(0, 8, 6, 1)
#define tlbi_vaae1 __sysop_encode(0, 8, 7, 3)
#define tlbi_vae1 __sysop_encode(0, 8, 7, 1)

#define sys_a0(op) asm volatile("sys " op)

typedef struct arch_context
{
    struct pt_regs *ctx;
    uint64_t ttbr;
    bool usermode;
} arch_context_t;

typedef struct arch_signal_frame
{
} arch_signal_frame_t;

#define USER_STACK_START 0x00006fffffff0000
#define USER_STACK_END 0x0000700000000000

void arch_context_init(arch_context_t *context, uint64_t page_table_addr, uint64_t entry, uint64_t stack, bool user_mode);
void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack);
void arch_context_free(arch_context_t *context);
task_t *arch_get_current();
void arch_set_current(task_t *current);

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next, uint64_t kernel_stack);
void arch_task_switch_to(struct pt_regs *ctx, task_t *prev, task_t *next);
void arch_context_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack);
void arch_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack);

void arch_yield();

bool arch_check_elf(const Elf64_Ehdr *elf);

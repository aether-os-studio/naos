#pragma once

#include <libs/klibc.h>
#include <task/task.h>
#include <arch/aarch64/irq/ptrace.h>

typedef struct arch_context
{
    uint64_t page_table_addr;
    struct pt_regs *ctx;
} arch_context_t;

typedef struct arch_signal_frame
{
} arch_signal_frame_t;

#define USER_STACK_START 0x00006ffffff00000
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
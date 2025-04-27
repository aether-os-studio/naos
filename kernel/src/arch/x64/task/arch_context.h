#pragma once

#include <arch/x64/irq/ptrace.h>
#include <task/task.h>

#define USER_STACK_START 0x00006ffffff00000
#define USER_STACK_END 0x0000700000000000

typedef struct fpu_context
{
    uint16_t fcw;
    uint16_t fsw;
    uint16_t ftw;
    uint16_t fop;
    uint64_t word2;
    uint64_t word3;
    uint32_t mxscr;
    uint32_t mxcsr_mask;
    uint64_t mm[16];
    uint64_t xmm[32];
    uint64_t rest[12];
} __attribute__((aligned(16))) fpu_context_t;

typedef struct arch_context
{
    uint64_t fs;
    uint64_t gs;
    uint64_t fsbase;
    uint64_t gsbase;
    uint64_t cr3;
    struct pt_regs *ctx;
    fpu_context_t *fpu_ctx;
} arch_context_t;

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
uint64_t sys_arch_prctl(uint64_t cmd, uint64_t arg);

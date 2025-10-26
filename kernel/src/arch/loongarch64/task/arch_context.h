#pragma once

#include <arch/loongarch64/irq/ptrace.h>
#include <libs/elf.h>
#include <mm/mm.h>

#define USER_STACK_START 0x00006fffff000000
#define USER_STACK_END 0x0000700000000000

struct task;
typedef struct task task_t;

typedef struct arch_context {
    struct pt_regs *ctx;
    task_mm_info_t *mm;
} arch_context_t;

typedef struct arch_signal_frame {
} __attribute__((packed)) arch_signal_frame_t;

void arch_context_init(arch_context_t *context, uint64_t page_table_dir,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg);
void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags);
void arch_context_free(arch_context_t *context);
task_t *arch_get_current();
void arch_set_current(task_t *current);

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next,
                              uint64_t kernel_stack);
void arch_task_switch_to(struct pt_regs *ctx, task_t *prev, task_t *next);
void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack);
void arch_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack);

void arch_yield();

bool arch_check_elf(const Elf64_Ehdr *elf);

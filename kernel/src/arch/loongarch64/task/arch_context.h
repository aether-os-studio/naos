#pragma once

#include <arch/loongarch64/irq/ptrace.h>
#include <libs/elf.h>
#include <mm/mm.h>
#include <task/task_struct.h>

struct task;
typedef struct task task_t;

typedef struct arch_context {
    uint64_t ra;
    uint64_t sp;
    uint64_t page_table_addr;
    bool kernel_interrupt_enabled;
    struct pt_regs *ctx;
    struct fpu_context *fpu_ctx;
} arch_context_t;

typedef struct fpu_context {
    uint64_t f[32];
    uint32_t fcsr;
    uint32_t reserved;
} __attribute__((aligned(16))) fpu_context_t;

static inline uint64_t arch_regs_get_user_sp(const struct pt_regs *regs) {
    return regs->sp;
}

static inline void arch_regs_set_user_sp(struct pt_regs *regs, uint64_t sp) {
    regs->sp = sp;
}

static inline void arch_context_set_tls(arch_context_t *context, uint64_t tls) {
    context->ctx->tp = tls;
}

#define switch_mm(prev, next)                                                  \
    do {                                                                       \
        (void)(prev);                                                          \
        (void)(next);                                                          \
    } while (0)

#define switch_to(prev, next)                                                  \
    do {                                                                       \
        (void)(prev);                                                          \
        (void)(next);                                                          \
    } while (0)

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg);
void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags);
void arch_context_free(arch_context_t *context);
void arch_context_save_interrupt_state(arch_context_t *context, bool enabled);
task_t *arch_get_current();
void arch_set_current(task_t *current);

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack);
void arch_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack);

bool arch_check_elf(const Elf64_Ehdr *elf);

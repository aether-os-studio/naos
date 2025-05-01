#include <arch/aarch64/task/arch_context.h>

void arch_context_init(arch_context_t *context, uint64_t page_table_addr, uint64_t entry, uint64_t stack, bool user_mode)
{
    context->ctx = (struct pt_regs *)stack - 1;
    context->ctx->pc = entry;
    context->ctx->sp_el0 = stack;
    context->page_table_addr = page_table_addr;
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack) {}

void arch_context_free(arch_context_t *context) {}

task_t *arch_get_current()
{
}

void arch_set_current(task_t *current)
{
}

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next, uint64_t kernel_stack) {}

void arch_task_switch_to(struct pt_regs *ctx, task_t *prev, task_t *next) {}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack) {}

void arch_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack) {}

void arch_yield()
{
}

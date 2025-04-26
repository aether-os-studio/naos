#include "arch_context.h"
#include <arch/arch.h>

void arch_context_init(arch_context_t *context, uint64_t page_table_addr, uint64_t entry, uint64_t stack, bool user_mode)
{
    memset(context, 0, sizeof(arch_context_t));

    if (!context->fpu_ctx)
    {
        context->fpu_ctx = (fpu_context_t *)phys_to_virt(alloc_frames(1));
        memset(context->fpu_ctx, 0, sizeof(fpu_context_t));
        context->fpu_ctx->mxscr = 0x1f80;
        context->fpu_ctx->fcw = 0x037f;
    }
    context->cr3 = page_table_addr;
    context->ctx = (struct pt_regs *)stack - 1;
    context->ctx->rip = entry;
    context->ctx->rsp = stack;
    context->ctx->rbp = stack;
    if (user_mode)
    {
        context->ctx->cs = SELECTOR_USER_CS;
        context->ctx->ss = SELECTOR_USER_DS;
    }
    else
    {
        context->ctx->cs = SELECTOR_KERNEL_CS;
        context->ctx->ss = SELECTOR_KERNEL_DS;
    }
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src)
{
    dst->cr3 = clone_page_table(src->cr3, USER_STACK_START, USER_STACK_END);
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
    memcpy(dst->fpu_ctx, src->fpu_ctx, sizeof(fpu_context_t));
}

task_t *arch_get_current()
{
    return (task_t *)read_kgsbase();
}

void arch_set_current(task_t *current)
{
    return write_kgsbase((uint64_t)current);
}

extern tss_t tss[MAX_CPU_NUM];

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next, uint64_t kernel_stack)
{
    __asm__ __volatile__("movq %%fs, %0\n\t" : "=r"(prev->fs));
    __asm__ __volatile__("movq %%gs, %0\n\t" : "=r"(prev->gs));

    prev->fsbase = read_fsbase();
    prev->gsbase = read_gsbase();

    __asm__ __volatile__("fxsave (%0)" ::"r"(prev->fpu_ctx));

    // Start to switch
    __asm__ __volatile__("fxrstor (%0)" ::"r"(next->fpu_ctx));

    __asm__ __volatile__("movq %0, %%cr3\n\t" ::"r"(next->cr3));

    tss[current_cpu_id].rsp0 = kernel_stack;

    __asm__ __volatile__("movq %0, %%fs\n\t" ::"r"(next->fs));
    __asm__ __volatile__("movq %0, %%gs\n\t" ::"r"(next->gs));

    write_fsbase(next->fsbase);
    write_gsbase(next->gsbase);

    __asm__ __volatile__(
        "movq %0, %%rsp\n\t"
        "jmp ret_from_exception" ::"r"(next->ctx));
}

void arch_task_switch_to(struct pt_regs *ctx, task_t *prev, task_t *next)
{
    if (prev == next)
    {
        return;
    }
    arch_set_current(next);

    prev->arch_context->ctx = ctx;

    prev->state = TASK_READY;
    next->state = TASK_RUNNING;

    arch_switch_with_context(prev->arch_context, next->arch_context, next->kernel_stack);
}

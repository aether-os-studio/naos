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
    context->ctx->rflags = (0UL << 12) | (0b10) | (1UL << 9);
    if (user_mode)
    {
        context->ctx->cs = SELECTOR_USER_CS;
        context->ctx->ds = SELECTOR_USER_DS;
        context->ctx->es = SELECTOR_USER_DS;
        context->ctx->ss = SELECTOR_USER_DS;
    }
    else
    {
        context->ctx->cs = SELECTOR_KERNEL_CS;
        context->ctx->ds = SELECTOR_KERNEL_DS;
        context->ctx->es = SELECTOR_KERNEL_DS;
        context->ctx->ss = SELECTOR_KERNEL_DS;
    }
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack)
{
    dst->cr3 = clone_page_table(src->cr3, USER_STACK_START, USER_STACK_END);
    dst->ctx = (struct pt_regs *)stack - 1;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
    dst->ctx->rax = 0;
    dst->fpu_ctx = (fpu_context_t *)phys_to_virt(alloc_frames(1));
    memset(dst->fpu_ctx, 0, sizeof(fpu_context_t));
    memcpy(dst->fpu_ctx, src->fpu_ctx, sizeof(fpu_context_t));
}

void arch_context_free(arch_context_t *context)
{
    // free_user_page_table(context->cr3);
    if (context->fpu_ctx)
    {
        free_frames(virt_to_phys((uint64_t)context->fpu_ctx), 1);
    }
}

task_t *arch_get_current()
{
    return (task_t *)read_kgsbase();
}

void arch_set_current(task_t *current)
{
    write_kgsbase((uint64_t)current);
}

extern tss_t tss[MAX_CPU_NUM];

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next, uint64_t kernel_stack)
{
    if (prev)
    {
        __asm__ __volatile__("movq %%fs, %0\n\t" : "=r"(prev->fs));
        __asm__ __volatile__("movq %%gs, %0\n\t" : "=r"(prev->gs));

        prev->fsbase = read_fsbase();
        prev->gsbase = read_gsbase();

        __asm__ __volatile__("fxsave (%0)" ::"r"(prev->fpu_ctx));
    }

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

    prev->arch_context->ctx = ctx;
    prev->state = TASK_READY;

    next->state = TASK_RUNNING;

    arch_set_current(next);

    arch_switch_with_context(prev->arch_context, next->arch_context, next->kernel_stack);
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack)
{
    context->ctx->rip = entry;
    context->ctx->rsp = stack;
    context->ctx->rbp = stack;
    context->ctx->cs = SELECTOR_USER_CS;
    context->ctx->ds = SELECTOR_USER_DS;
    context->ctx->es = SELECTOR_USER_DS;
    context->ctx->ss = SELECTOR_USER_DS;
    context->ctx->rflags = (0UL << 12) | (0b10) | (1UL << 9);
    context->cr3 = clone_page_table(context->cr3, USER_BRK_START, USER_BRK_END);
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack)
{
    arch_context_to_user_mode(context, entry, stack);

    __asm__ __volatile__(
        "movq %0, %%rsp\n\t"
        "jmp ret_from_exception" ::"r"(context->ctx));
}

void arch_yield()
{
    __asm__ __volatile__("int %0" ::"i"(APIC_TIMER_INTERRUPT_VECTOR));
}

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

uint64_t sys_arch_prctl(uint64_t cmd, uint64_t arg)
{
    switch (cmd)
    {
    case ARCH_SET_FS:
        current_task->arch_context->fsbase = arg;
        write_fsbase(current_task->arch_context->fsbase);
        return 0;
    case ARCH_SET_GS:
        current_task->arch_context->gsbase = arg;
        write_gsbase(current_task->arch_context->gsbase);
        return 0;
    case ARCH_GET_FS:
        return current_task->arch_context->fsbase;
    case ARCH_GET_GS:
        return current_task->arch_context->gsbase;
    default:
        return (uint64_t)(-ENOSYS);
    }
}

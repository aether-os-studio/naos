#include <arch/aarch64/task/arch_context.h>
#include <mm/mm.h>

void arch_context_init(arch_context_t *context, uint64_t page_table_addr, uint64_t entry, uint64_t stack, bool user_mode)
{
    context->ctx = (struct pt_regs *)((stack - sizeof(struct pt_regs)));
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->ctx->pc = entry;

    uint32_t spsr = 0;
    if (user_mode)
    {
        // todo
        spsr |= 0;
    }
    else
    {
        spsr |= 0x800003c5;
    }
    spsr |= (0UL << 9);  // D = 0，不屏蔽调试异常
    spsr |= (0UL << 10); // A = 0，不屏蔽SError
    spsr |= (0UL << 11); // I = 0，不屏蔽IRQ
    spsr |= (0UL << 12); // F = 0，不屏蔽FIQ

    context->ctx->cpsr = spsr;

    asm volatile("mrs %0, fpcr" : "=r"(context->ctx->fpcr));
    asm volatile("mrs %0, fpsr" : "=r"(context->ctx->fpsr));
    context->usermode = user_mode;
    __asm__ __volatile__("mrs %0, TTBR0_EL1" : "=r"(context->ttbr));
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack)
{
    dst->ttbr = clone_page_table(src->ttbr, USER_BRK_START, USER_BRK_END);
    dst->usermode = src->usermode;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
}

void arch_context_free(arch_context_t *context) {}

task_t *arch_get_current()
{
    uint64_t sp_el0;
    asm volatile("mrs %0, SP_EL0" : "=r"(sp_el0));
    return (task_t *)sp_el0;
}

void arch_set_current(task_t *current)
{
    asm volatile("msr SP_EL0, %0" ::"r"(current));
}

extern void arch_context_switch_with_next(arch_context_t *next);
extern void arch_context_switch_with_prev_next(arch_context_t *prev, arch_context_t *next);

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next, uint64_t kernel_stack)
{
    arch_context_switch_with_next(next);
}

void arch_task_switch_to(struct pt_regs *ctx, task_t *prev, task_t *next)
{
    if (prev == next)
    {
        return;
    }

    prev->arch_context->ctx = ctx;

    prev->state = TASK_READY;

    // start to switch
    next->state = TASK_RUNNING;

    if (prev->arch_context->ttbr != next->arch_context->ttbr)
    {
        // 1. 更新TTBR0_EL1
        __asm__ __volatile__("msr TTBR0_EL1, %0" : : "r"(next->arch_context->ttbr));

        // 2. 刷新TLB
        __asm__ __volatile__(
            "tlbi alle1\n\t" // 刷新所有EL1 TLB条目
            "dsb sy\n\t"     // 确保刷新完成
            "isb\n\t"        // 刷新指令流水线
        );
    }

    arch_set_current(next);

    arch_switch_with_context(prev->arch_context, next->arch_context, next->kernel_stack);
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack) {}

void arch_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack) {}

void arch_yield()
{
}

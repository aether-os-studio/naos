#include <arch/aarch64/task/arch_context.h>
#include <mm/mm.h>

void arch_context_init(arch_context_t *context, uint64_t page_table_addr, uint64_t entry, uint64_t stack, bool user_mode)
{
    context->ctx = (struct pt_regs *)((stack - sizeof(struct pt_regs)));
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->ctx->pc = entry;
    context->ctx->sp_el0 = stack;

    uint32_t spsr = 0;
    if (user_mode)
    {
        // todo
        spsr = 0x800003c0;
    }
    else
    {
        spsr = 0x800003c5;
    }

    context->ctx->cpsr = spsr;

    asm volatile("mrs %0, fpcr" : "=r"(context->ctx->fpcr));
    asm volatile("mrs %0, fpsr" : "=r"(context->ctx->fpsr));
    context->usermode = user_mode;
    __asm__ __volatile__("mrs %0, TTBR0_EL1" : "=r"(context->ttbr));
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack)
{
    dst->ttbr = clone_page_table(src->ttbr, USER_STACK_START, USER_STACK_END);
    dst->usermode = src->usermode;
    dst->ctx = (struct pt_regs *)stack - 1;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
}

void arch_context_free(arch_context_t *context) {}

task_t *arch_get_current()
{
    uint64_t tpidr_el1;
    asm volatile("mrs %0, TPIDR_EL1" : "=r"(tpidr_el1));
    return (task_t *)tpidr_el1;
}

void arch_set_current(task_t *current)
{
    asm volatile("msr TPIDR_EL1, %0" ::"r"(current));
}

extern void arch_context_switch_with_next(arch_context_t *next);
extern void arch_context_switch_with_prev_next(arch_context_t *prev, arch_context_t *next);

void arch_switch_with_context(arch_context_t *prev, arch_context_t *next, uint64_t kernel_stack)
{
    arch_context_switch_with_next(next);
}

extern void task_signal();

void arch_task_switch_to(struct pt_regs *ctx, task_t *prev, task_t *next)
{
    if (prev == next)
    {
        return;
    }

    prev->arch_context->ctx = ctx;

    prev->current_state = prev->state;

    next->current_state = TASK_RUNNING;

    // 1. 更新TTBR0_EL1
    __asm__ __volatile__("msr TTBR0_EL1, %0" : : "r"(next->arch_context->ttbr));

    // 2. 刷新TLB
    __asm__ __volatile__("dsb ishst\n\t"
                         "tlbi vmalle1is\n\t"
                         "dsb ish\n\t"
                         "isb\n\t");

    task_signal();

    arch_set_current(next);

    sched_update_itimer();

    arch_switch_with_context(prev->arch_context, next->arch_context, next->kernel_stack);
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack)
{
    context->ttbr = clone_page_table(context->ttbr, USER_STACK_START, USER_STACK_END);
    context->usermode = true;
    context->ctx->pc = entry;
    context->ctx->sp_el0 = stack;
    context->ctx->cpsr = 0x800003c0;
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry, uint64_t stack)
{
    arch_disable_interrupt();

    arch_context_to_user_mode(context, entry, stack);

    // 1. 更新TTBR0_EL1
    __asm__ __volatile__("msr TTBR0_EL1, %0" : : "r"(context->ttbr));

    // 2. 刷新TLB
    __asm__ __volatile__("dsb ishst\n\t"
                         "tlbi vmalle1is\n\t"
                         "dsb ish\n\t"
                         "isb\n\t");

    arch_context_switch_with_next(context);
}

void arch_yield()
{
    arch_enable_interrupt();
    arch_pause();
}

bool arch_check_elf(const Elf64_Ehdr *ehdr)
{
    // 验证ELF魔数
    if (memcmp((void *)ehdr->e_ident, "\x7F"
                                      "ELF",
               4) != 0)
    {
        printk("Invalid ELF magic\n");
        return false;
    }

    // 检查架构和类型
    if (ehdr->e_ident[4] != 2 || // 64-bit
        ehdr->e_machine != 0xB7  // aarch64
    )
    {
        printk("Unsupported ELF format\n");
        return false;
    }

    return true;
}

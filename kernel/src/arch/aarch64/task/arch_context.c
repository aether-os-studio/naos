#include <arch/aarch64/task/arch_context.h>
#include <mm/mm.h>
#include <task/task.h>
#include <task/sched.h>

extern void kernel_thread_func();
extern void arch_context_switch_exit();

static inline uint64_t aarch64_read_tpidr_el0(void) {
    uint64_t value;
    asm volatile("mrs %0, TPIDR_EL0" : "=r"(value));
    return value;
}

static inline void aarch64_write_tpidr_el0(uint64_t value) {
    asm volatile("msr TPIDR_EL0, %0" : : "r"(value));
}

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg) {
    context->ctx = (struct pt_regs *)((stack - sizeof(struct pt_regs)));
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->tpidr_el0 = 0;

    uint32_t spsr = 0;
    if (user_mode) {
        context->pc = (uint64_t)arch_context_switch_exit;
        context->sp = (uint64_t)context->ctx;
        context->ctx->pc = entry;
        context->ctx->sp_el0 = stack;
        context->ctx->x0 = initial_arg;
        spsr = 0x800003c0;
    } else {
        context->pc = (uint64_t)kernel_thread_func;
        context->sp = (uint64_t)context->ctx;
        context->ctx->x19 = entry;
        context->ctx->x20 = initial_arg;
        spsr = 0x800003c5;
    }

    context->ctx->cpsr = spsr;

    asm volatile("mrs %0, fpcr" : "=r"(context->ctx->fpcr));
    asm volatile("mrs %0, fpsr" : "=r"(context->ctx->fpsr));
    context->usermode = user_mode;
}

extern void ret_from_fork();

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags) {
    dst->usermode = src->usermode;
    if (!src->tpidr_el0)
        src->tpidr_el0 = aarch64_read_tpidr_el0();
    dst->tpidr_el0 = src->tpidr_el0;
    dst->ctx = (struct pt_regs *)stack - 1;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
    dst->ctx->x0 = 0;
    dst->pc = (uint64_t)ret_from_fork;
    dst->sp = (uint64_t)dst->ctx;
}

void arch_context_free(arch_context_t *context) {}

task_t *arch_get_current() {
    uint64_t tpidr_el1;
    asm volatile("mrs %0, TPIDR_EL1" : "=r"(tpidr_el1));
    return (task_t *)tpidr_el1;
}

void arch_set_current(task_t *current) {
    asm volatile("msr TPIDR_EL1, %0" ::"r"(current));
}

extern void arch_context_switch_with_next(arch_context_t *next);
extern void arch_context_switch_with_prev_next(arch_context_t *prev,
                                               arch_context_t *next);

void __switch_to(task_t *prev, task_t *next) {
    prev->arch_context->tpidr_el0 = aarch64_read_tpidr_el0();
    aarch64_write_tpidr_el0(next->arch_context->tpidr_el0);

    task_mark_on_cpu(prev, false);
    task_mark_on_cpu(next, true);
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack) {
    context->tpidr_el0 = 0;
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->usermode = true;
    context->pc = (uint64_t)arch_context_switch_exit;
    context->sp = (uint64_t)context->ctx;
    context->ctx->pc = entry;
    context->ctx->sp_el0 = stack;
    context->ctx->cpsr = 0x800003c0;
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {
    arch_disable_interrupt();

    arch_context_to_user_mode(context, entry, stack);
    aarch64_write_tpidr_el0(context->tpidr_el0);

    asm volatile("dsb ishst\n\t"
                 "tlbi vmalle1is\n\t"
                 "dsb ish\n\t"
                 "isb\n\t");

    arch_context_switch_with_next(context);
}

bool arch_check_elf(const Elf64_Ehdr *ehdr) {
    // 验证ELF魔数
    if (memcmp((void *)ehdr->e_ident,
               "\x7F"
               "ELF",
               4) != 0) {
        printk("Invalid ELF magic\n");
        return false;
    }

    // 检查架构和类型
    if (ehdr->e_ident[4] != 2 || // 64-bit
        ehdr->e_machine != 0xB7  // aarch64
    ) {
        printk("Unsupported ELF format\n");
        return false;
    }

    return true;
}

#include <arch/arch.h>
#include <arch/loongarch64/cpu_local.h>
#include <task/task.h>

#ifndef EM_LOONGARCH
#define EM_LOONGARCH 258
#endif

extern void kernel_thread_func(void);
extern void ret_from_fork(void);
extern void loongarch64_trap_return(void);

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg) {
    memset(context, 0, sizeof(*context));
    context->page_table_addr = page_table_addr;
    context->ctx = (struct pt_regs *)stack - 1;
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->sp = (uint64_t)context->ctx;
    context->kernel_interrupt_enabled = false;

    if (user_mode) {
        context->ra = (uint64_t)loongarch64_trap_return;
        context->ctx->pc = entry;
        context->ctx->sp = stack;
        context->ctx->usp = stack;
        context->ctx->csr_prmd = LOONGARCH_PRMD_USER;
        context->ctx->a0 = initial_arg;
        context->ctx->syscallno = NO_SYSCALL;
    } else {
        context->ra = (uint64_t)kernel_thread_func;
        context->s0 = entry;
        context->s1 = initial_arg;
        context->ctx->syscallno = NO_SYSCALL;
    }
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags) {
    (void)clone_flags;
    memset(dst, 0, sizeof(*dst));
    dst->page_table_addr = src->page_table_addr;
    dst->kernel_interrupt_enabled = src->kernel_interrupt_enabled;
    dst->ctx = (struct pt_regs *)stack - 1;
    memcpy(dst->ctx, src->ctx, sizeof(struct pt_regs));
    dst->ctx->a0 = 0;
    dst->ctx->syscallno = src->ctx ? src->ctx->syscallno : NO_SYSCALL;
    dst->ra = (uint64_t)ret_from_fork;
    dst->sp = (uint64_t)dst->ctx;
}

void arch_context_free(arch_context_t *context) { (void)context; }

void arch_context_save_interrupt_state(arch_context_t *context, bool enabled) {
    context->kernel_interrupt_enabled = enabled;
}

task_t *arch_get_current() {
    loongarch64_cpu_local_t *local = loongarch64_get_cpu_local();
    return local ? local->task_ptr : NULL;
}

void arch_set_current(task_t *current) {
    loongarch64_cpu_local_set_current(current);
}

void __switch_to(task_t *prev, task_t *next) {
    task_mark_on_cpu(prev, false);
    if (prev->state == TASK_DIED && task_is_reaped(prev))
        task_schedule_reap();
    task_mark_on_cpu(next, true);
}

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack) {
    context->ctx = (struct pt_regs *)current_task->kernel_stack - 1;
    memset(context->ctx, 0, sizeof(struct pt_regs));
    context->ra = (uint64_t)loongarch64_trap_return;
    context->sp = (uint64_t)context->ctx;
    context->ctx->pc = entry;
    context->ctx->sp = stack;
    context->ctx->usp = stack;
    context->ctx->csr_prmd = LOONGARCH_PRMD_USER;
    context->ctx->syscallno = NO_SYSCALL;
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {
    arch_disable_interrupt();
    arch_context_to_user_mode(context, entry, stack);
    loongarch64_set_user_page_table_root(current_task->mm->page_table_addr);

    asm volatile("move $sp, %0\n\t"
                 "jr %1\n\t" ::"r"(context->ctx),
                 "r"(context->ra)
                 : "memory");
}

bool arch_check_elf(const Elf64_Ehdr *ehdr) {
    return ehdr && ehdr->e_machine == EM_LOONGARCH;
}

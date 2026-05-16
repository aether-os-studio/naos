#include <arch/arch.h>
#include <arch/loongarch64/cpu_local.h>

#ifndef EM_LOONGARCH
#define EM_LOONGARCH 258
#endif

void arch_context_init(arch_context_t *context, uint64_t page_table_addr,
                       uint64_t entry, uint64_t stack, bool user_mode,
                       uint64_t initial_arg) {
    (void)user_mode;
    (void)initial_arg;
    memset(context, 0, sizeof(*context));
    context->ra = entry;
    context->sp = stack;
    context->page_table_addr = page_table_addr;
}

void arch_context_copy(arch_context_t *dst, arch_context_t *src, uint64_t stack,
                       uint64_t clone_flags) {
    (void)clone_flags;
    memcpy(dst, src, sizeof(*dst));
    dst->sp = stack;
    dst->ctx = NULL;
    dst->fpu_ctx = NULL;
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

void arch_context_to_user_mode(arch_context_t *context, uint64_t entry,
                               uint64_t stack) {
    context->ra = entry;
    context->sp = stack;
}

void arch_to_user_mode(arch_context_t *context, uint64_t entry,
                       uint64_t stack) {
    arch_context_to_user_mode(context, entry, stack);
    while (1)
        arch_wait_for_interrupt();
}

bool arch_check_elf(const Elf64_Ehdr *ehdr) {
    return ehdr && ehdr->e_machine == EM_LOONGARCH;
}

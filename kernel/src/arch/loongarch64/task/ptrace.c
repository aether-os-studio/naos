#include <task/ptrace.h>

uint32_t arch_ptrace_audit_arch(void) { return 0; }

size_t arch_ptrace_regset_size(void) { return 0; }

void arch_ptrace_fill_syscall_info(struct ptrace_syscall_info *info,
                                   const struct pt_regs *regs,
                                   uint8_t last_stop) {
    (void)info;
    (void)regs;
    (void)last_stop;
}

uint64_t arch_ptrace_copy_regs(task_t *target, const struct pt_regs *regs,
                               void *user_buf) {
    (void)target;
    (void)regs;
    (void)user_buf;
    return (uint64_t)-ENOSYS;
}

#include <task/ptrace.h>
#include <task/task_syscall.h>

typedef struct aarch64_user_pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
} aarch64_user_pt_regs_t;

uint32_t arch_ptrace_audit_arch(void) { return AUDIT_ARCH_AARCH64; }

size_t arch_ptrace_regset_size(void) { return sizeof(aarch64_user_pt_regs_t); }

void arch_ptrace_fill_syscall_info(struct ptrace_syscall_info *info,
                                   const struct pt_regs *regs,
                                   uint8_t last_stop) {
    info->instruction_pointer = regs->pc;
    info->stack_pointer = regs->sp_el0;

    if (last_stop == PTRACE_STOP_SYSCALL_ENTER) {
        info->op = PTRACE_SYSCALL_INFO_ENTRY;
        info->entry.nr = regs->syscallno;
        info->entry.args[0] = regs->x0;
        info->entry.args[1] = regs->x1;
        info->entry.args[2] = regs->x2;
        info->entry.args[3] = regs->x3;
        info->entry.args[4] = regs->x4;
        info->entry.args[5] = regs->x5;
    } else if (last_stop == PTRACE_STOP_SYSCALL_EXIT) {
        info->op = PTRACE_SYSCALL_INFO_EXIT;
        info->exit.rval = (int64_t)regs->x0;
        info->exit.is_error = (int64_t)regs->x0 < 0;
    }
}

uint64_t arch_ptrace_copy_regs(task_t *target, const struct pt_regs *regs,
                               void *user_buf) {
    (void)target;
    aarch64_user_pt_regs_t user_regs = {
        .regs =
            {
                regs->x0,  regs->x1,  regs->x2,  regs->x3,  regs->x4,
                regs->x5,  regs->x6,  regs->x7,  regs->x8,  regs->x9,
                regs->x10, regs->x11, regs->x12, regs->x13, regs->x14,
                regs->x15, regs->x16, regs->x17, regs->x18, regs->x19,
                regs->x20, regs->x21, regs->x22, regs->x23, regs->x24,
                regs->x25, regs->x26, regs->x27, regs->x28, regs->x29,
                regs->x30,
            },
        .sp = regs->sp_el0,
        .pc = regs->pc,
        .pstate = regs->cpsr,
    };

    if (copy_to_user(user_buf, &user_regs, sizeof(user_regs)))
        return (uint64_t)-EFAULT;
    return 0;
}

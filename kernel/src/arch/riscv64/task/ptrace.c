#include <task/ptrace.h>
#include <task/task_syscall.h>

typedef struct riscv64_user_regs_struct {
    uint64_t pc;
    uint64_t ra;
    uint64_t sp;
    uint64_t gp;
    uint64_t tp;
    uint64_t t0;
    uint64_t t1;
    uint64_t t2;
    uint64_t s0;
    uint64_t s1;
    uint64_t a0;
    uint64_t a1;
    uint64_t a2;
    uint64_t a3;
    uint64_t a4;
    uint64_t a5;
    uint64_t a6;
    uint64_t a7;
    uint64_t s2;
    uint64_t s3;
    uint64_t s4;
    uint64_t s5;
    uint64_t s6;
    uint64_t s7;
    uint64_t s8;
    uint64_t s9;
    uint64_t s10;
    uint64_t s11;
    uint64_t t3;
    uint64_t t4;
    uint64_t t5;
    uint64_t t6;
} riscv64_user_regs_struct_t;

uint32_t arch_ptrace_audit_arch(void) { return AUDIT_ARCH_RISCV64; }

size_t arch_ptrace_regset_size(void) {
    return sizeof(riscv64_user_regs_struct_t);
}

void arch_ptrace_fill_syscall_info(struct ptrace_syscall_info *info,
                                   const struct pt_regs *regs,
                                   uint8_t last_stop) {
    info->instruction_pointer = regs->sepc;
    info->stack_pointer = regs->sp;

    if (last_stop == PTRACE_STOP_SYSCALL_ENTER) {
        info->op = PTRACE_SYSCALL_INFO_ENTRY;
        info->entry.nr = regs->a7;
        info->entry.args[0] = regs->a0;
        info->entry.args[1] = regs->a1;
        info->entry.args[2] = regs->a2;
        info->entry.args[3] = regs->a3;
        info->entry.args[4] = regs->a4;
        info->entry.args[5] = regs->a5;
    } else if (last_stop == PTRACE_STOP_SYSCALL_EXIT) {
        info->op = PTRACE_SYSCALL_INFO_EXIT;
        info->exit.rval = (int64_t)regs->a0;
        info->exit.is_error = (int64_t)regs->a0 < 0;
    }
}

uint64_t arch_ptrace_copy_regs(task_t *target, const struct pt_regs *regs,
                               void *user_buf) {
    (void)target;
    riscv64_user_regs_struct_t user_regs = {
        .pc = regs->sepc,
        .ra = regs->ra,
        .sp = regs->sp,
        .gp = regs->gp,
        .tp = regs->tp,
        .t0 = regs->t0,
        .t1 = regs->t1,
        .t2 = regs->t2,
        .s0 = regs->s0,
        .s1 = regs->s1,
        .a0 = regs->a0,
        .a1 = regs->a1,
        .a2 = regs->a2,
        .a3 = regs->a3,
        .a4 = regs->a4,
        .a5 = regs->a5,
        .a6 = regs->a6,
        .a7 = regs->a7,
        .s2 = regs->s2,
        .s3 = regs->s3,
        .s4 = regs->s4,
        .s5 = regs->s5,
        .s6 = regs->s6,
        .s7 = regs->s7,
        .s8 = regs->s8,
        .s9 = regs->s9,
        .s10 = regs->s10,
        .s11 = regs->s11,
        .t3 = regs->t3,
        .t4 = regs->t4,
        .t5 = regs->t5,
        .t6 = regs->t6,
    };

    if (copy_to_user(user_buf, &user_regs, sizeof(user_regs)))
        return (uint64_t)-EFAULT;
    return 0;
}

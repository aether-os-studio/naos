#include <task/ptrace.h>
#include <task/task_syscall.h>

typedef struct x64_user_regs_struct {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t rbp;
    uint64_t rbx;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t orig_rax;
    uint64_t rip;
    uint64_t cs;
    uint64_t eflags;
    uint64_t rsp;
    uint64_t ss;
    uint64_t fs_base;
    uint64_t gs_base;
    uint64_t ds;
    uint64_t es;
    uint64_t fs;
    uint64_t gs;
} x64_user_regs_struct_t;

uint32_t arch_ptrace_audit_arch(void) { return AUDIT_ARCH_X86_64; }

size_t arch_ptrace_regset_size(void) { return sizeof(x64_user_regs_struct_t); }

void arch_ptrace_fill_syscall_info(struct ptrace_syscall_info *info,
                                   const struct pt_regs *regs,
                                   uint8_t last_stop) {
    info->instruction_pointer = regs->rip;
    info->stack_pointer = regs->rsp;

    if (last_stop == PTRACE_STOP_SYSCALL_ENTER) {
        info->op = PTRACE_SYSCALL_INFO_ENTRY;
        info->entry.nr = regs->orig_rax;
        info->entry.args[0] = regs->rdi;
        info->entry.args[1] = regs->rsi;
        info->entry.args[2] = regs->rdx;
        info->entry.args[3] = regs->r10;
        info->entry.args[4] = regs->r8;
        info->entry.args[5] = regs->r9;
    } else if (last_stop == PTRACE_STOP_SYSCALL_EXIT) {
        info->op = PTRACE_SYSCALL_INFO_EXIT;
        info->exit.rval = (int64_t)regs->rax;
        info->exit.is_error = (int64_t)regs->rax < 0;
    }
}

uint64_t arch_ptrace_copy_regs(task_t *target, const struct pt_regs *regs,
                               void *user_buf) {
    x64_user_regs_struct_t user_regs = {
        .r15 = regs->r15,
        .r14 = regs->r14,
        .r13 = regs->r13,
        .r12 = regs->r12,
        .rbp = regs->rbp,
        .rbx = regs->rbx,
        .r11 = regs->r11,
        .r10 = regs->r10,
        .r9 = regs->r9,
        .r8 = regs->r8,
        .rax = regs->rax,
        .rcx = regs->rcx,
        .rdx = regs->rdx,
        .rsi = regs->rsi,
        .rdi = regs->rdi,
        .orig_rax = regs->orig_rax,
        .rip = regs->rip,
        .cs = regs->cs,
        .eflags = regs->rflags,
        .rsp = regs->rsp,
        .ss = regs->ss,
        .fs_base = target->arch_context ? target->arch_context->fsbase : 0,
        .gs_base = target->arch_context ? target->arch_context->gsbase : 0,
        .ds = 0,
        .es = 0,
        .fs = 0,
        .gs = 0,
    };

    if (copy_to_user(user_buf, &user_regs, sizeof(user_regs)))
        return (uint64_t)-EFAULT;
    return 0;
}

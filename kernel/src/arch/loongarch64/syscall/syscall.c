#include <arch/arch.h>
#include <task/ptrace.h>
#include <task/task.h>
#include <task/signal.h>

syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM] = {NULL};

void syscall_handler_init() {
    memset(syscall_handlers, 0, sizeof(syscall_handlers));
}

void loongarch64_do_syscall(struct pt_regs *frame) {
    uint64_t idx = frame->a7;
    uint64_t arg1 = frame->a0;
    uint64_t arg2 = frame->a1;
    uint64_t arg3 = frame->a2;
    uint64_t arg4 = frame->a3;
    uint64_t arg5 = frame->a4;
    uint64_t arg6 = frame->a5;

    task_t *self = current_task;

    if (!self) {
        frame->a0 = (uint64_t)-ENOSYS;
        frame->pc += 4;
        return;
    }

    frame->a0 = self->last_syscall_ret;
    frame->syscallno = idx;
    ptrace_on_syscall_enter(frame);

    if (idx >= MAX_SYSCALL_NUM || !syscall_handlers[idx]) {
        frame->a0 = (uint64_t)-ENOSYS;
        goto done;
    }

    arch_enable_user_access();

    if (idx == SYS_CLONE) {
        frame->a0 = (uint64_t)-ENOSYS; // TODO
    } else if (idx == SYS_CLONE3 || idx == SYS_RT_SIGRETURN) {
        special_syscall_handle_t handler =
            (special_syscall_handle_t)syscall_handlers[idx];
        frame->a0 = handler(frame, arg1, arg2, arg3, arg4, arg5, arg6);
    } else {
        frame->a0 = syscall_handlers[idx](arg1, arg2, arg3, arg4, arg5, arg6);
    }

    arch_disable_user_access();

done:
    self->last_syscall_ret = frame->a0;
    ptrace_on_syscall_exit(frame);
    if (idx != SYS_BRK && idx != SYS_RSEQ && frame->a0 == (uint64_t)-ENOSYS) {
        serial_fprintk("syscall %d not implemented\n", idx);
    }
    uint64_t next_pc = frame->pc + 4;
    bool restored_context = idx == SYS_RT_SIGRETURN;
    task_signal(frame);
    frame->syscallno = NO_SYSCALL;
    if (!restored_context && frame->pc == next_pc - 4) {
        frame->pc = next_pc;
    }
}

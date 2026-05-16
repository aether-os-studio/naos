#pragma once

#include <libs/klibc.h>

static bool signal_arch_setup_frame(task_t *task, struct pt_regs *regs, int sig,
                                    const sigaction_t *action,
                                    const siginfo_t *info,
                                    sigset_t restore_mask) {
    (void)task;
    (void)regs;
    (void)sig;
    (void)action;
    (void)info;
    (void)restore_mask;
    return false;
}

static uint64_t signal_arch_sigreturn(struct pt_regs *regs) {
    (void)regs;
    return (uint64_t)-ENOSYS;
}

#pragma once

#include <arch/riscv64/syscall/nr.h>

#define SIGNAL_ARCH_HAS_RESTORER_FIELD 0
#define SIGNAL_ARCH_VALIDATE_RESTORER 0
#define SIGNAL_RISCV64_RT_SIGRETURN_TRAMPOLINE_SIZE 8U
#define SIGNAL_RISCV64_SYSCALL_INS_LEN 4U
#define SIGNAL_RISCV64_USER_SSTATUS ((1UL << 18) | (1UL << 13) | (1UL << 5))
#define SIGNAL_RISCV64_FRAME_FROM_SYSCALL 1U

typedef struct signal_kernel_sigaction {
    sighandler_t handler;
    unsigned long flags;
    sigset_t mask;
    void *unused;
} signal_kernel_sigaction_t;

static inline uint64_t
signal_arch_user_sp_from_regs(const struct pt_regs *regs) {
    return regs->sp;
}

static inline bool signal_arch_user_context(const struct pt_regs *regs) {
    return regs && (regs->sstatus & (1ULL << 8)) == 0;
}

static const uint8_t signal_riscv64_rt_sigreturn_trampoline
    [SIGNAL_RISCV64_RT_SIGRETURN_TRAMPOLINE_SIZE] = {
        0x93, 0x08, 0xB0, 0x08, 0x73, 0x00, 0x00, 0x00,
};

static inline const uint8_t *
signal_arch_rt_sigreturn_trampoline(size_t *code_size) {
    if (!code_size)
        return NULL;

    *code_size = sizeof(signal_riscv64_rt_sigreturn_trampoline);
    return signal_riscv64_rt_sigreturn_trampoline;
}

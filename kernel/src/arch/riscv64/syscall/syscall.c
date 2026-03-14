#include <arch/arch.h>
#include <task/task.h>
#include <fs/vfs/fcntl.h>
#include <libs/strerror.h>
#include <arch/riscv64/syscall/nr.h>

void syscall_init() {}

// Beware the 65 character limit!
char sysname[] = "NeoAetherOS";
char nodename[] = "aether";
char release[] = BUILD_VERSION;
char version[] = BUILD_VERSION;
char machine[] = "riscv64";

syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM];

void syscall_handler_init() { memset(syscall_handlers, 0, MAX_SYSCALL_NUM); }

spinlock_t syscall_debug_lock = SPIN_INIT;

void syscall_handler(struct pt_regs *regs) {
    uint64_t idx = regs->a7 & 0xFFFFFFFF;

    uint64_t arg1 = regs->a0;
    uint64_t arg2 = regs->a1;
    uint64_t arg3 = regs->a2;
    uint64_t arg4 = regs->a3;
    uint64_t arg5 = regs->a4;
    uint64_t arg6 = regs->a5;
    uint64_t seccomp_args[6] = {arg1, arg2, arg3, arg4, arg5, arg6};

    if (idx > MAX_SYSCALL_NUM) {
        regs->a0 = (uint64_t)-ENOSYS;
        goto done;
    }

    syscall_handle_t handler = syscall_handlers[idx];
    if (!handler) {
        regs->a0 = (uint64_t)-ENOSYS;
        goto done;
    }

    regs->a0 = 0;

    csr_set(sstatus, (1UL << 18));

    if (idx == SYS_CLONE || idx == SYS_CLONE3) {
        special_syscall_handle_t h = (special_syscall_handle_t)handler;
        regs->a0 = h(regs, arg1, arg2, arg3, arg4, arg5, arg6);
    } else {
        regs->a0 = handler(arg1, arg2, arg3, arg4, arg5, arg6);
    }

    csr_clear(sstatus, (1UL << 18));

    if ((idx != SYS_BRK) && (idx != SYS_MMAP) && (idx != SYS_MREMAP) &&
        (idx != SYS_SHMAT) && (int)regs->a0 < 0 && !((int64_t)regs->a0 < 0))
        regs->a0 |= 0xffffffff00000000;

    // if ((int64_t)regs->a0 < 0) {
    //     serial_fprintk("syscall %d has error: %s\n", idx,
    //                    strerror(-(int)regs->a0));
    // }

done:
    if (idx != SYS_BRK && regs->a0 == (uint64_t)-ENOSYS) {
        serial_fprintk("syscall %d not implemented\n", idx);
    }
}

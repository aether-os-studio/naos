#include <arch/arch.h>
#include <task/task.h>
#include <task/signal.h>
#include <task/task_syscall.h>
#include <fs/vfs/fcntl.h>
#include <net/net_syscall.h>

// Beware the 65 character limit!
char sysname[] = "NeoAetherOS";
char nodename[] = "aether";
char release[] = BUILD_VERSION;
char version[] = BUILD_VERSION;
char machine[] = "aarch64";

syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM] = {NULL};

static uint64_t aarch64_sys_clone(struct pt_regs *frame, uint64_t flags,
                                  uint64_t newsp, uint64_t parent_tid,
                                  uint64_t tls, uint64_t child_tid,
                                  uint64_t unused) {
    (void)unused;
    return sys_clone(frame, flags, newsp, (int *)parent_tid, (int *)child_tid,
                     tls);
}

void aarch64_do_syscall(struct pt_regs *frame) {
    uint64_t ret = 0;

    uint64_t idx = frame->x8;
    uint64_t arg1 = frame->x0;
    uint64_t arg2 = frame->x1;
    uint64_t arg3 = frame->x2;
    uint64_t arg4 = frame->x3;
    uint64_t arg5 = frame->x4;
    uint64_t arg6 = frame->x5;

    if (idx > MAX_SYSCALL_NUM) {
        frame->x0 = (uint64_t)-ENOSYS;
        goto done;
    }

    syscall_handle_t handler = syscall_handlers[idx];
    if (!handler) {
        frame->x0 = (uint64_t)-ENOSYS;
        goto done;
    }

    if (idx == SYS_CLONE) {
        frame->x0 =
            aarch64_sys_clone(frame, arg1, arg2, arg3, arg4, arg5, arg6);
    } else if (idx == SYS_CLONE3 || idx == SYS_RT_SIGRETURN) {
        special_syscall_handle_t h = (special_syscall_handle_t)handler;
        frame->x0 = h(frame, arg1, arg2, arg3, arg4, arg5, arg6);
    } else {
        frame->x0 = handler(arg1, arg2, arg3, arg4, arg5, arg6);
    }

    if ((idx != SYS_BRK) && (idx != SYS_MMAP) && (idx != SYS_MREMAP) &&
        (idx != SYS_SHMAT) && (idx != SYS_FCNTL) && (idx != SYS_RT_SIGRETURN) &&
        (int)frame->x0 < 0 && ((frame->x0 & 0x8000000000000000) == 0))
        frame->x0 |= 0xffffffff00000000;
    else if ((int64_t)frame->x0 < 0 && ((frame->x0 & 0xffffffff) == 0))
        frame->x0 = 0;

done:
    if (idx != SYS_BRK && idx != SYS_RSEQ && frame->x0 == (uint64_t)-ENOSYS) {
        serial_fprintk("syscall %d not implemented\n", idx);
    }

    frame->origin_x0 = frame->x0;

    task_signal(frame);
}

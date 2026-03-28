#include <arch/arch.h>
#include <task/task.h>
#include <task/signal.h>
#include <fs/vfs/fcntl.h>
#include <net/net_syscall.h>

// Beware the 65 character limit!
char sysname[] = "NeoAetherOS";
char nodename[] = "aether";
char release[] = BUILD_VERSION;
char version[] = BUILD_VERSION;
char machine[] = "aarch64";

syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM];
void syscall_handlers_init() { memset(syscall_handlers, 0, MAX_SYSCALL_NUM); }

void aarch64_do_syscall(struct pt_regs *frame) {
    uint64_t ret = 0;

    uint64_t idx = frame->x8;
    uint64_t arg1 = frame->x0;
    uint64_t arg2 = frame->x1;
    uint64_t arg3 = frame->x2;
    uint64_t arg4 = frame->x3;
    uint64_t arg5 = frame->x4;
    uint64_t arg6 = frame->x5;
    uint64_t seccomp_args[6] = {arg1, arg2, arg3, arg4, arg5, arg6};

    if (idx > MAX_SYSCALL_NUM) {
        frame->x0 = (uint64_t)-ENOSYS;
        goto done;
    }

    syscall_handle_t handler = syscall_handlers[idx];
    if (!handler) {
        frame->x0 = (uint64_t)-ENOSYS;
        goto done;
    }

    if (idx == SYS_CLONE || idx == SYS_CLONE3 || idx == SYS_RT_SIGRETURN) {
        special_syscall_handle_t h = (special_syscall_handle_t)handler;
        frame->x0 = h(frame, arg1, arg2, arg3, arg4, arg5, arg6);
    } else {
        frame->x0 = handler(arg1, arg2, arg3, arg4, arg5, arg6);
    }

    if ((idx != SYS_BRK) && (idx != SYS_MMAP) && (idx != SYS_MREMAP) &&
        (idx != SYS_SHMAT) && (idx != SYS_FCNTL) && (int)frame->x0 < 0 &&
        ((frame->x0 & 0x8000000000000000) == 0))
        frame->x0 |= 0xffffffff00000000;
    else if ((int64_t)frame->x0 < 0 && ((frame->x0 & 0xffffffff) == 0))
        frame->x0 = 0;

done:
    if (frame->x0 == (uint64_t)-ENOSYS) {
        char buf[32];
        int len = sprintf(buf, "syscall %d not implemented\n", idx);
        serial_printk(buf, len);
    }

    task_signal(frame);
}

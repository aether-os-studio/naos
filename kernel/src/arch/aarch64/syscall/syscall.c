#include <arch/arch.h>
#include <task/task.h>
#include <fs/vfs/fcntl.h>
#include <net/net_syscall.h>

void syscall_init() {}

// Beware the 65 character limit!
char sysname[] = "Next Aether OS";
char nodename[] = "Aether";
char release[] = BUILD_VERSION;
char version[] = BUILD_VERSION;
char machine[] = "x86_64";

syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM];

uint64_t sys_getrandom(uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    void *buffer = (void *)arg1;
    size_t get_len = (size_t)arg2;
    uint32_t flags = (uint32_t)arg3;

    if (get_len == 0 || get_len > 1024 * 1024) {
        return (uint64_t)-EINVAL;
    }

    for (size_t i = 0; i < get_len; i++) {
        tm time;
        time_read(&time);
        uint64_t next = mktime(&time);
        next = next * 1103515245 + 12345;
        uint8_t rand_byte = ((uint8_t)(next / 65536) % 32768);
        memcpy(buffer + i, &rand_byte, 1);
    }

    return get_len;
}

uint64_t sys_clock_gettime(uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    switch (arg1) {
    case 1: // CLOCK_MONOTONIC
    case 6: // CLOCK_MONOTONIC_COARSE
    case 4: // CLOCK_MONOTONIC_RAW
    {
        if (arg2) {
            struct timespec *ts = (struct timespec *)arg2;
            uint64_t nano = nano_time();
            ts->tv_sec = nano / 1000000000ULL;
            ts->tv_nsec = nano % 1000000000ULL;
        }
        return 0;
    }
    case 7: // CLOCK_BOOTTIME
        if (arg2) {
            struct timespec *ts = (struct timespec *)arg2;
            ts->tv_sec = nano_time() / 1000000000;
            ts->tv_nsec = nano_time() % 1000000000;
        }
        return 0;
    case 0: // CLOCK_REALTIME
    {
        tm time;
        time_read(&time);
        uint64_t timestamp = mktime(&time);

        if (arg2) {
            struct timespec *ts = (struct timespec *)arg2;
            ts->tv_sec = timestamp;
            ts->tv_nsec = 0;
        }
        return 0;
    }
    default:
        printk("clock not supported, clock_id = %d\n", arg1);
        return (uint64_t)-EINVAL;
    }
}

uint64_t sys_clock_getres(uint64_t arg1, uint64_t arg2) {
    ((struct timespec *)arg2)->tv_sec = 0;
    ((struct timespec *)arg2)->tv_nsec = 1;
    return 0;
}

uint64_t sys_accept_normal(uint64_t arg1, struct sockaddr_un *arg2,
                           socklen_t *arg3) {
    return sys_accept(arg1, arg2, arg3, 0);
}

uint64_t sys_pipe_normal(uint64_t arg1) { return sys_pipe((int *)arg1, 0); }

uint64_t sys_gettimeofday(uint64_t arg1) {
    tm time_day;
    time_read(&time_day);
    uint64_t timestamp_day = mktime(&time_day);
    if (arg1) {
        struct timespec *ts = (struct timespec *)arg1;
        ts->tv_sec = timestamp_day;
        ts->tv_nsec = 0;
    }
    return 0;
}

uint64_t sys_uname(uint64_t arg1) {
    struct utsname *utsname = (struct utsname *)arg1;
    memcpy(utsname->sysname, sysname, sizeof(sysname));
    memcpy(utsname->nodename, nodename, sizeof(nodename));
    memcpy(utsname->release, release, sizeof(release));
    memcpy(utsname->version, version, sizeof(version));
    memcpy(utsname->machine, machine, sizeof(machine));
    return 0;
}

uint64_t sys_eventfd(uint64_t arg1) { return sys_eventfd2(arg1, 0); }

void syscall_handlers_init() { memset(syscall_handlers, 0, MAX_SYSCALL_NUM); }

extern uint64_t sys_pipe(int pipefd[2], uint64_t flags);

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
}

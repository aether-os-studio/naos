#pragma once

#include <drivers/logger.h>
#include <libs/klibc.h>
#include <arch/riscv64/irq/ptrace.h>
#include <arch/riscv64/syscall/nr.h>

struct timespec {
    long long tv_sec;
    long tv_nsec;
};

struct stat {
    unsigned long st_dev;
    unsigned long st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    unsigned long st_rdev;
    unsigned long __pad1;
    long st_size;
    int32_t st_blksize;
    int32_t __pad2;
    long st_blocks;
    long st_atime;
    unsigned long st_atime_nsec;
    long st_mtime;
    unsigned long st_mtime_nsec;
    long st_ctime;
    unsigned long st_ctime_nsec;
    uint32_t __unused4;
    uint32_t __unused5;
};

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

#define __NEW_UTS_LEN 64

struct new_utsname {
    char sysname[__NEW_UTS_LEN + 1];
    char nodename[__NEW_UTS_LEN + 1];
    char release[__NEW_UTS_LEN + 1];
    char version[__NEW_UTS_LEN + 1];
    char machine[__NEW_UTS_LEN + 1];
    char domainname[__NEW_UTS_LEN + 1];
};

typedef uint64_t (*syscall_handle_t)(uint64_t arg1, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4,
                                     uint64_t arg5, uint64_t arg6);
typedef uint64_t (*special_syscall_handle_t)(struct pt_regs *regs,
                                             uint64_t arg1, uint64_t arg2,
                                             uint64_t arg3, uint64_t arg4,
                                             uint64_t arg5, uint64_t arg6);

#define MAX_SYSCALL_NUM 500

extern syscall_handle_t syscall_handlers[MAX_SYSCALL_NUM];

static inline uint64_t dummy_syscall_handler() { return 0; }

void syscall_handler_init();
void riscv64_do_syscall(struct pt_regs *frame);

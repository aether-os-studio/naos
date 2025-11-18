#pragma once

#include <arch/loongarch64/syscall/nr.h>
#include <drivers/kernel_logger.h>
#include <libs/klibc.h>

struct timespec {
    long long tv_sec;
    long tv_nsec;
};

struct stat {
    long st_dev;
    unsigned long st_ino;
    unsigned long st_nlink;
    int st_mode;
    int st_uid;
    int st_gid;
    long st_rdev;
    long long st_size;
    long st_blksize;
    unsigned long int st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    char _pad[24];
};

#define __NEW_UTS_LEN 64

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

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

void syscall_init();

#define MAX_SYSCALL_NUM 500

static inline uint64_t dummy_syscall_handler() { return 0; }

void syscall_handler_init();

uint64_t sys_clock_gettime(uint64_t arg1, uint64_t arg2, uint64_t arg3);

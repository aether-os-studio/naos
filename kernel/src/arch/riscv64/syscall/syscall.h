#pragma once

#include <arch/riscv64/syscall/nr.h>
#include <drivers/kernel_logger.h>
#include <libs/klibc.h>

struct timespec {
    long long tv_sec;
    long tv_nsec;
};

struct stat {
    uint64_t st_dev;         // 设备 ID
    uint64_t st_ino;         // inode 号
    uint32_t st_mode;        // 文件类型和权限
    uint32_t st_nlink;       // 硬链接数
    uint32_t st_uid;         // 用户 ID
    uint32_t st_gid;         // 组 ID
    uint64_t st_rdev;        // 设备 ID（如果是特殊文件）
    uint64_t __pad1;         // 填充字节（保留）
    int64_t st_size;         // 文件大小（字节）
    int32_t st_blksize;      // 块大小
    int32_t __pad2;          // 填充字节（保留）
    int64_t st_blocks;       // 分配的块数
    struct timespec st_atim; // 最后访问时间
    struct timespec st_mtim; // 最后修改时间
    struct timespec st_ctim; // 最后状态改变时间
    uint32_t __unused4;      // 保留字段
    uint32_t __unused5;      // 保留字段
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

extern void syscall_exception();

void syscall_init();

#define MAX_SYSCALL_NUM 500

static inline uint64_t dummy_syscall_handler() { return 0; }

void syscall_handler_init();

uint64_t sys_clock_gettime(uint64_t arg1, uint64_t arg2, uint64_t arg3);

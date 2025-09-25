#pragma once

#include <drivers/kernel_logger.h>
#include <libs/klibc.h>
#include <arch/aarch64/syscall/nr.h>

struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

extern void syscall_exception();

void syscall_init();

#define MAX_SYSCALL_NUM 500

static inline uint64_t dummy_syscall_handler() { return 0; }

typedef uint64_t (*syscall_handle_t)(uint64_t arg1, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4,
                                     uint64_t arg5, uint64_t arg6);
typedef uint64_t (*special_syscall_handle_t)(struct pt_regs *regs,
                                             uint64_t arg1, uint64_t arg2,
                                             uint64_t arg3, uint64_t arg4,
                                             uint64_t arg5, uint64_t arg6);

uint64_t sys_clock_gettime(uint64_t arg1, uint64_t arg2, uint64_t arg3);

void aarch64_do_syscall(struct pt_regs *frame);

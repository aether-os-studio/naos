#pragma once

#include <drivers/kernel_logger.h>
#include <libs/klibc.h>
#include <arch/aarch64/syscall/nr.h>

struct utsname
{
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

extern void syscall_exception();

void syscall_init();

void aarch64_do_syscall(struct pt_regs *frame);

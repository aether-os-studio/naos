#pragma once

#include <drivers/kernel_logger.h>
#include <libs/klibc.h>
#include <arch/aarch64/syscall/nr.h>

extern void syscall_exception();

void syscall_init();

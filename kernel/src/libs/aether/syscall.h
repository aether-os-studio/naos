#pragma once

#include <arch/arch.h>

void regist_syscall_handler(uint64_t idx, syscall_handle_t handler);

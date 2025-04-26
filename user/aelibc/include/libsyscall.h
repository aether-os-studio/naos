#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <nr.h>

#include <sys/types.h>

uint64_t enter_syscall(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t idx);

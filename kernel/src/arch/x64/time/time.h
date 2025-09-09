#pragma once

#include <libs/klibc.h>

typedef struct
{
    int tm_sec;   // 秒数 [0，59]
    int tm_min;   // 分钟数 [0，59]
    int tm_hour;  // 小时数 [0，59]
    int tm_mday;  // 1 个月的天数 [0，31]
    int tm_mon;   // 1 年中月份 [0，11]
    int tm_year;  // 从 1900 年开始的年数
    int tm_isdst; // 夏令时标志
} tm;

void time_read(tm *time);
int64_t mktime(tm *time);

uint64_t sys_clock_gettime(uint64_t arg1, uint64_t arg2, uint64_t arg3);

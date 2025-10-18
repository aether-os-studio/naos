#include <libs/klibc.h>
#include <arch/aarch64/time/time.h>
#include <boot/boot.h>

uint64_t get_counter() {
    uint64_t val;
    asm volatile("mrs %0, CNTPCT_EL0" : "=r"(val));
    return val;
}

uint32_t get_freq() {
    uint32_t freq;
    asm volatile("mrs %0, CNTFRQ_EL0" : "=r"(freq));
    return freq;
}

static int is_leap_year(int year) {
    if (year % 4 != 0)
        return 0;
    if (year % 100 != 0)
        return 1;
    return (year % 400 == 0);
}

void time_read(tm *time) {
    uint64_t timestrap_at_boot = boot_get_boottime();
    uint64_t timer_value = timestrap_at_boot + get_counter() / get_freq();

    time->tm_sec = timer_value % 60;
    time->tm_min = (timer_value / 60) % 60;
    time->tm_hour = (timer_value / 3600) % 24;

    uint64_t days = timer_value / 86400;
    uint64_t remaining_days = days;

    time->tm_wday = (days + 4) % 7;

    int year = 1970;
    while (remaining_days >= (is_leap_year(year) ? 366 : 365)) {
        remaining_days -= is_leap_year(year) ? 366 : 365;
        year++;
    }
    time->tm_year = year - 1900;

    static const int month_days[2][12] = {
        {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
        {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}};

    int leap = is_leap_year(year);
    int month = 0;
    while (remaining_days >= month_days[leap][month]) {
        remaining_days -= month_days[leap][month];
        month++;
    }
    time->tm_mon = month;
    time->tm_mday = remaining_days + 1;

    // 计算一年中的天数
    time->tm_yday = 0;
    for (int i = 0; i < month; i++) {
        time->tm_yday += month_days[leap][i];
    }
    time->tm_yday += remaining_days;

    time->tm_isdst = -1;
}

#define MINUTE 60          // 每分钟的秒数
#define HOUR (60 * MINUTE) // 每小时的秒数
#define DAY (24 * HOUR)    // 每天的秒数
#define YEAR (365 * DAY)   // 每年的秒数，以 365 天算

// 每个月开始时的已经过去天数
static int month[13] = {0, // 这里占位，没有 0 月，从 1 月开始
                        0,
                        (31),
                        (31 + 29),
                        (31 + 29 + 31),
                        (31 + 29 + 31 + 30),
                        (31 + 29 + 31 + 30 + 31),
                        (31 + 29 + 31 + 30 + 31 + 30),
                        (31 + 29 + 31 + 30 + 31 + 30 + 31),
                        (31 + 29 + 31 + 30 + 31 + 30 + 31 + 31),
                        (31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30),
                        (31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31),
                        (31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30)};

int64_t mktime(tm *time) {
    int64_t res;
    int year; // 1970 年开始的年数
    // 下面从 1900 年开始的年数计算
    if (time->tm_year >= 70)
        year = time->tm_year - 70;
    else
        year = time->tm_year - 70 + 100;

    // 这些年经过的秒数时间
    res = YEAR * year;

    // 已经过去的闰年，每个加 1 天
    res += DAY * ((year + 1) / 4);

    // 已经过完的月份的时间
    res += month[time->tm_mon] * DAY;

    // 如果 2 月已经过了，并且当前不是闰年，那么减去一天
    if (time->tm_mon > 2 && ((year + 2) % 4))
        res -= DAY;

    // 这个月已经过去的天
    res += DAY * (time->tm_mday - 1);

    // 今天过去的小时
    res += HOUR * time->tm_hour;

    res += MINUTE * time->tm_min;

    // 这个分钟过去的秒
    res += time->tm_sec;

    return res;
}

uint64_t nanoTime() { return get_counter() * 1000000000 / get_freq(); }

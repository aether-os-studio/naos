#include <arch/x64/time/time.h>
#include <arch/x64/io.h>
#include <drivers/kernel_logger.h>

#define CMOS_ADDR 0x70 // CMOS 地址寄存器
#define CMOS_DATA 0x71 // CMOS 数据寄存器

// 下面是 CMOS 信息的寄存器索引
#define CMOS_SECOND 0x00  // (0 ~ 59)
#define CMOS_MINUTE 0x02  // (0 ~ 59)
#define CMOS_HOUR 0x04    // (0 ~ 23)
#define CMOS_WEEKDAY 0x06 // (1 ~ 7) 星期天 = 1，星期六 = 7
#define CMOS_DAY 0x07     // (1 ~ 31)
#define CMOS_MONTH 0x08   // (1 ~ 12)
#define CMOS_YEAR 0x09    // (0 ~ 99)
#define CMOS_CENTURY 0x32 // 可能不存在
#define CMOS_NMI 0x80

#define MINUTE 60          // 每分钟的秒数
#define HOUR (60 * MINUTE) // 每小时的秒数
#define DAY (24 * HOUR)    // 每天的秒数
#define YEAR (365 * DAY)   // 每年的秒数，以 365 天算

spinlock_t cmos_register_lock = {0};
spinlock_t cmos_gettime_lock = {0};

// 读 cmos 寄存器的值
uint8_t cmos_read(uint8_t addr)
{
    spin_lock(&cmos_register_lock);
    io_out8(CMOS_ADDR, CMOS_NMI | addr);
    uint8_t value = io_in8(CMOS_DATA);
    spin_unlock(&cmos_register_lock);
    return value;
};

// 写 cmos 寄存器的值
void cmos_write(uint8_t addr, uint8_t value)
{
    spin_lock(&cmos_register_lock);
    io_out8(CMOS_ADDR, CMOS_NMI | addr);
    io_out8(CMOS_DATA, value);
    spin_unlock(&cmos_register_lock);
}

int days_in_month[2][12] = {{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
                            {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}};

int century;

bool is_leap_year(int year)
{
    return ((year % 4 == 0) && (year % 100 != 0));
}

int64_t mktime(tm *time)
{
    int64_t seconds = 0;
    int leap;

    // Adjust year and month for Unix time (starting from 1970)
    int year = time->tm_year;
    int month = time->tm_mon - 1; // Month is 0-based in this logic
    month -= (month > 11) ? 11 : 0;
    int day = time->tm_mday - 1; // Day is 1-based in the RTC structure

    for (int y = 1970; y < year; y++)
    {
        leap = is_leap_year(y);
        seconds += (365 + leap) * 86400;
    }

    leap = is_leap_year(year);
    for (int m = 0; m < month; m++)
    {
        seconds += days_in_month[leap][m] * 86400;
    }

    seconds += day * 86400;

    seconds += time->tm_hour * 3600;
    seconds += time->tm_min * 60;
    seconds += time->tm_sec;

    return seconds;
}

void time_read_bcd(tm *time)
{
    // CMOS 的访问速度很慢。为了减小时间误差，在读取了下面循环中所有数值后，
    // 若此时 CMOS 中秒值发生了变化，那么就重新读取所有值。
    // 这样内核就能把与 CMOS 的时间误差控制在 1 秒之内。
    do
    {
        time->tm_sec = cmos_read(CMOS_SECOND);
        time->tm_min = cmos_read(CMOS_MINUTE);
        time->tm_hour = cmos_read(CMOS_HOUR);
        time->tm_mday = cmos_read(CMOS_DAY);
        time->tm_mon = cmos_read(CMOS_MONTH);
        time->tm_year = cmos_read(CMOS_YEAR);
        century = cmos_read(CMOS_CENTURY);
    } while (time->tm_sec != cmos_read(CMOS_SECOND));
}

uint8_t bcd_to_bin(uint8_t value)
{
    return (value & 0xf) + (value >> 4) * 10;
}

void time_read(tm *time)
{
    spin_lock(&cmos_gettime_lock);

    time_read_bcd(time);
    uint8_t rb = cmos_read(0x0b);
    bool need_convert = !(rb & 0x04);

    if (need_convert)
    {
        time->tm_sec = bcd_to_bin(time->tm_sec);
        time->tm_min = bcd_to_bin(time->tm_min);
        time->tm_hour = bcd_to_bin(time->tm_hour);
        time->tm_mday = bcd_to_bin(time->tm_mday);
        time->tm_mon = bcd_to_bin(time->tm_mon);
        time->tm_year = bcd_to_bin(time->tm_year);
        time->tm_isdst = -1;
        century = bcd_to_bin(century);
    }

    time->tm_year += century * 100;

    if (!(rb & 0x02) && (time->tm_hour & 0x80))
        time->tm_hour = ((time->tm_hour & 0x7F) + 12) % 24;

    spin_unlock(&cmos_gettime_lock);
}

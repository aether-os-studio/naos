#include <arch/arch.h>
#include <arch/x86_64/drivers/rtc_cmos.h>
#include <drivers/rtc.h>
#include <irq/irq_manager.h>

#define CMOS_ADDR 0x70
#define CMOS_DATA 0x71
#define CMOS_NMI_DISABLE 0x80

#define RTC_SECONDS 0x00
#define RTC_ALARM_SECONDS 0x01
#define RTC_MINUTES 0x02
#define RTC_ALARM_MINUTES 0x03
#define RTC_HOURS 0x04
#define RTC_ALARM_HOURS 0x05
#define RTC_DAY_OF_MONTH 0x07
#define RTC_MONTH 0x08
#define RTC_YEAR 0x09
#define RTC_REG_A 0x0A
#define RTC_REG_B 0x0B
#define RTC_REG_C 0x0C

#define RTC_REG_A_UIP 0x80
#define RTC_REG_B_24H 0x02
#define RTC_REG_B_DM_BINARY 0x04
#define RTC_REG_B_AIE 0x20
#define RTC_REG_B_SET 0x80
#define RTC_REG_C_AF 0x20

#define RTC_IRQ 8

static spinlock_t rtc_cmos_lock = SPIN_INIT;
static rtc_device_t rtc_cmos_device;

static uint8_t rtc_cmos_read(uint8_t reg) {
    io_out8(CMOS_ADDR, CMOS_NMI_DISABLE | reg);
    return io_in8(CMOS_DATA);
}

static void rtc_cmos_write(uint8_t reg, uint8_t value) {
    io_out8(CMOS_ADDR, CMOS_NMI_DISABLE | reg);
    io_out8(CMOS_DATA, value);
}

static uint8_t rtc_bcd_to_bin(uint8_t value) {
    return (uint8_t)((value & 0x0F) + ((value >> 4) * 10));
}

static uint8_t rtc_bin_to_bcd(uint8_t value) {
    return (uint8_t)(((value / 10) << 4) | (value % 10));
}

static uint8_t rtc_decode_value(uint8_t value, bool binary) {
    return binary ? value : rtc_bcd_to_bin(value);
}

static uint8_t rtc_encode_value(uint8_t value, bool binary) {
    return binary ? value : rtc_bin_to_bcd(value);
}

static uint8_t rtc_encode_hour(uint8_t hour, bool binary, uint8_t reg_b) {
    bool pm;

    if (reg_b & RTC_REG_B_24H)
        return rtc_encode_value(hour, binary);

    pm = hour >= 12;
    if (hour == 0)
        hour = 12;
    else if (hour > 12)
        hour -= 12;

    hour = rtc_encode_value(hour, binary);
    if (pm)
        hour |= 0x80;

    return hour;
}

static void rtc_cmos_wait_update_done(void) {
    while (rtc_cmos_read(RTC_REG_A) & RTC_REG_A_UIP)
        arch_pause();
}

static int rtc_cmos_read_time(struct rtc_device *rtc, rtc_time_t *tm) {
    uint8_t sec;
    uint8_t min;
    uint8_t hour;
    uint8_t mday;
    uint8_t mon;
    uint8_t year;
    uint8_t reg_b;
    bool binary;

    (void)rtc;

    if (!tm)
        return -EINVAL;

    spin_lock(&rtc_cmos_lock);
    rtc_cmos_wait_update_done();

    sec = rtc_cmos_read(RTC_SECONDS);
    min = rtc_cmos_read(RTC_MINUTES);
    hour = rtc_cmos_read(RTC_HOURS);
    mday = rtc_cmos_read(RTC_DAY_OF_MONTH);
    mon = rtc_cmos_read(RTC_MONTH);
    year = rtc_cmos_read(RTC_YEAR);
    reg_b = rtc_cmos_read(RTC_REG_B);
    spin_unlock(&rtc_cmos_lock);

    binary = (reg_b & RTC_REG_B_DM_BINARY) != 0;
    tm->tm_sec = rtc_decode_value(sec, binary);
    tm->tm_min = rtc_decode_value(min, binary);
    tm->tm_hour = rtc_decode_value(hour & 0x7F, binary);
    tm->tm_mday = rtc_decode_value(mday, binary);
    tm->tm_mon = rtc_decode_value(mon, binary);
    tm->tm_year = 2000 + rtc_decode_value(year, binary);
    if (tm->tm_year < 1970)
        tm->tm_year += 100;

    if (!(reg_b & RTC_REG_B_24H)) {
        bool pm = (hour & 0x80) != 0;
        if (pm && tm->tm_hour < 12)
            tm->tm_hour += 12;
        if (!pm && tm->tm_hour == 12)
            tm->tm_hour = 0;
    }

    return rtc_time_valid(tm) ? 0 : -EINVAL;
}

static int rtc_cmos_set_time(struct rtc_device *rtc, const rtc_time_t *tm) {
    uint8_t reg_b;
    uint8_t old_b;
    bool binary;

    (void)rtc;

    if (!rtc_time_valid(tm))
        return -EINVAL;

    spin_lock(&rtc_cmos_lock);
    old_b = rtc_cmos_read(RTC_REG_B);
    reg_b = old_b | RTC_REG_B_SET;
    rtc_cmos_write(RTC_REG_B, reg_b);

    binary = (old_b & RTC_REG_B_DM_BINARY) != 0;

    rtc_cmos_write(RTC_SECONDS, rtc_encode_value((uint8_t)tm->tm_sec, binary));
    rtc_cmos_write(RTC_MINUTES, rtc_encode_value((uint8_t)tm->tm_min, binary));
    rtc_cmos_write(RTC_HOURS,
                   rtc_encode_hour((uint8_t)tm->tm_hour, binary, old_b));
    rtc_cmos_write(RTC_DAY_OF_MONTH,
                   rtc_encode_value((uint8_t)tm->tm_mday, binary));
    rtc_cmos_write(RTC_MONTH, rtc_encode_value((uint8_t)tm->tm_mon, binary));
    rtc_cmos_write(RTC_YEAR,
                   rtc_encode_value((uint8_t)(tm->tm_year % 100), binary));
    rtc_cmos_write(RTC_REG_B, old_b);
    spin_unlock(&rtc_cmos_lock);

    return 0;
}

static int rtc_cmos_read_alarm(struct rtc_device *rtc, rtc_alarm_t *alarm) {
    uint8_t sec;
    uint8_t min;
    uint8_t hour;
    uint8_t reg_b;
    bool binary;

    (void)rtc;

    if (!alarm)
        return -EINVAL;

    memset(alarm, 0, sizeof(*alarm));

    spin_lock(&rtc_cmos_lock);
    sec = rtc_cmos_read(RTC_ALARM_SECONDS);
    min = rtc_cmos_read(RTC_ALARM_MINUTES);
    hour = rtc_cmos_read(RTC_ALARM_HOURS);
    reg_b = rtc_cmos_read(RTC_REG_B);
    alarm->pending = (rtc_cmos_read(RTC_REG_C) & RTC_REG_C_AF) != 0;
    spin_unlock(&rtc_cmos_lock);

    binary = (reg_b & RTC_REG_B_DM_BINARY) != 0;
    alarm->time.tm_sec = rtc_decode_value(sec, binary);
    alarm->time.tm_min = rtc_decode_value(min, binary);
    alarm->time.tm_hour = rtc_decode_value(hour & 0x7F, binary);
    if (!(reg_b & RTC_REG_B_24H)) {
        bool pm = (hour & 0x80) != 0;
        if (pm && alarm->time.tm_hour < 12)
            alarm->time.tm_hour += 12;
        if (!pm && alarm->time.tm_hour == 12)
            alarm->time.tm_hour = 0;
    }
    alarm->enabled = (reg_b & RTC_REG_B_AIE) != 0;

    return 0;
}

static int rtc_cmos_set_alarm(struct rtc_device *rtc,
                              const rtc_alarm_t *alarm) {
    uint8_t reg_b;
    bool binary;

    (void)rtc;

    if (!alarm || alarm->time.tm_hour < 0 || alarm->time.tm_hour > 23 ||
        alarm->time.tm_min < 0 || alarm->time.tm_min > 59 ||
        alarm->time.tm_sec < 0 || alarm->time.tm_sec > 59)
        return -EINVAL;

    spin_lock(&rtc_cmos_lock);
    reg_b = rtc_cmos_read(RTC_REG_B);
    binary = (reg_b & RTC_REG_B_DM_BINARY) != 0;

    rtc_cmos_write(RTC_ALARM_SECONDS,
                   rtc_encode_value((uint8_t)alarm->time.tm_sec, binary));
    rtc_cmos_write(RTC_ALARM_MINUTES,
                   rtc_encode_value((uint8_t)alarm->time.tm_min, binary));
    rtc_cmos_write(
        RTC_ALARM_HOURS,
        rtc_encode_hour((uint8_t)alarm->time.tm_hour, binary, reg_b));
    rtc_cmos_read(RTC_REG_C);
    spin_unlock(&rtc_cmos_lock);

    if (alarm->enabled)
        return rtc_cmos_device.ops->alarm_enable_irq(&rtc_cmos_device, true);

    return rtc_cmos_device.ops->alarm_enable_irq(&rtc_cmos_device, false);
}

static int rtc_cmos_alarm_enable_irq(struct rtc_device *rtc, bool enabled) {
    uint8_t reg_b;

    (void)rtc;

    spin_lock(&rtc_cmos_lock);
    reg_b = rtc_cmos_read(RTC_REG_B);
    if (enabled)
        reg_b |= RTC_REG_B_AIE;
    else
        reg_b &= (uint8_t)~RTC_REG_B_AIE;
    rtc_cmos_write(RTC_REG_B, reg_b);
    rtc_cmos_read(RTC_REG_C);
    spin_unlock(&rtc_cmos_lock);

    return 0;
}

static void rtc_cmos_irq_handler(uint64_t irq_num, void *data,
                                 struct pt_regs *regs) {
    (void)irq_num;
    (void)data;
    (void)regs;

    spin_lock(&rtc_cmos_lock);
    rtc_cmos_read(RTC_REG_C);
    spin_unlock(&rtc_cmos_lock);

    rtc_handle_alarm_irq();
}

static const rtc_class_ops_t rtc_cmos_ops = {
    .read_time = rtc_cmos_read_time,
    .set_time = rtc_cmos_set_time,
    .read_alarm = rtc_cmos_read_alarm,
    .set_alarm = rtc_cmos_set_alarm,
    .alarm_enable_irq = rtc_cmos_alarm_enable_irq,
};

static rtc_device_t rtc_cmos_device = {
    .name = "rtc_cmos",
    .ops = &rtc_cmos_ops,
};

void rtc_cmos_init(void) {
    spin_init(&rtc_cmos_lock);
    rtc_cmos_alarm_enable_irq(&rtc_cmos_device, false);
    rtc_cmos_read(RTC_REG_C);

    rtc_register_device(&rtc_cmos_device);
    irq_regist_irq(RTC_CMOS_INTERRUPT_VECTOR, rtc_cmos_irq_handler, RTC_IRQ,
                   NULL, &apic_controller, "RTC CMOS", 0);
}

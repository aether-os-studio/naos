#pragma once

#include <libs/klibc.h>

typedef struct rtc_time {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
} rtc_time_t;

typedef struct rtc_alarm {
    rtc_time_t time;
    bool enabled;
    bool pending;
} rtc_alarm_t;

struct rtc_device;

typedef struct rtc_class_ops {
    int (*read_time)(struct rtc_device *rtc, rtc_time_t *tm);
    int (*set_time)(struct rtc_device *rtc, const rtc_time_t *tm);
    int (*read_alarm)(struct rtc_device *rtc, rtc_alarm_t *alarm);
    int (*set_alarm)(struct rtc_device *rtc, const rtc_alarm_t *alarm);
    int (*alarm_enable_irq)(struct rtc_device *rtc, bool enabled);
} rtc_class_ops_t;

typedef struct rtc_device {
    const char *name;
    const rtc_class_ops_t *ops;
    void *private_data;
} rtc_device_t;

int rtc_register_device(rtc_device_t *rtc);
rtc_device_t *rtc_get_default(void);

int rtc_read_time(rtc_time_t *tm);
int rtc_set_time(const rtc_time_t *tm);
int rtc_read_alarm(rtc_alarm_t *alarm);
int rtc_set_alarm(const rtc_alarm_t *alarm);
int rtc_alarm_enable_irq(bool enabled);

bool rtc_time_valid(const rtc_time_t *tm);
uint64_t rtc_time_to_seconds(const rtc_time_t *tm);
void rtc_seconds_to_time(uint64_t seconds, rtc_time_t *tm);
void rtc_handle_alarm_irq(void);

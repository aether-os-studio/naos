#pragma once

#include <libs/klibc.h>

struct pt_regs;

typedef struct {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
} tm;

struct global_timer_state {
    uint64_t frequency;
    uint64_t next_deadline;
    uint32_t irq_num;
    bool initialized;
    bool using_sbi;
};

extern struct global_timer_state global_timer;

int timer_init(void);
void timer_init_percpu(void);
void timer_handler(uint64_t irq_num, void *parameter, struct pt_regs *regs);
void timer_set_next_tick_ns(uint64_t ns);
uint64_t get_counter();
uint64_t get_freq();
uint64_t realtime_boot_time();
uint64_t realtime_time();
uint64_t nano_time();

#pragma once

#include <libs/klibc.h>

// 定时器类型
typedef enum {
    TIMER_TYPE_PHYSICAL_NONSECURE, // EL1 物理非安全定时器
    TIMER_TYPE_VIRTUAL,            // EL1 虚拟定时器
    TIMER_TYPE_PHYSICAL_SECURE,    // EL1 物理安全定时器
    TIMER_TYPE_HYP_PHYSICAL,       // EL2 物理定时器
    TIMER_TYPE_HYP_VIRTUAL,        // EL2 虚拟定时器
} timer_type_t;

// 定时器抽象操作
typedef struct {
    uint64_t (*read_counter)();
    void (*write_tval)(uint64_t);
    void (*write_ctl)(uint64_t);
    uint64_t (*read_ctl)();
    const char *name;
} timer_ops_t;

// 全局状态
struct global_timer_state {
    timer_type_t active_type;
    const timer_ops_t *ops;
    uint64_t frequency;
    uint32_t irq_num;
    uint32_t irq_flags;
    _Bool always_on;
    _Bool initialized;
};

extern struct global_timer_state g_timer;

int timer_init();
void timer_init_percpu();
uint64_t nano_time();

// 新增接口
timer_type_t timer_get_active_type();
const char *timer_get_type_name();

void timer_set_next_tick_ns(uint64_t ns);

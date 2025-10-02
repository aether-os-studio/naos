#pragma once

#include <libs/klibc.h>
#include <arch/riscv64/sbi.h>

/* 定时器上下文 */
struct timer_context {
    uint64_t clint_base;      /* CLINT基地址 */
    uint64_t timer_freq;      /* 定时器频率 */
    uint64_t ticks_per_int;   /* 每次中断的tick数 */
    uint64_t next_tick[128];  /* 每个hart的下次中断时间 */
    uint64_t tick_count[128]; /* 每个hart的中断计数 */
    uint32_t num_harts;       /* Hart数量 */
    bool initialized;         /* 是否已初始化 */
};

extern struct timer_context g_timer_ctx;

#define TIMER_FREQ 10000000 /* CLINT时钟频率（通常是10MHz） */

static uint64_t get_timer(void) {
    uint64_t time;
    __asm__ volatile(".option push\n"
                     ".option norvc\n"
                     "rdtime %0\n"
                     ".option pop\n"
                     : "=r"(time));
    return time;
}

static inline void sbi_set_timer(uint64_t stime_value) {
    sbi_ecall(SBI_SET_TIMER, 0, stime_value, 0, 0, 0, 0, 0);
}

void timer_init_hart(uint32_t hart_id);

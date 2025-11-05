#pragma once

#include <libs/klibc.h>
#include <arch/riscv64/sbi.h>

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

extern uint64_t timer_freq;

void timer_init_hart(uint32_t hart_id);

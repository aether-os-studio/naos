#include <arch/loongarch64/time/time.h>

struct global_timer_state global_timer = {
    .frequency = 1000000000ULL,
    .next_deadline = 0,
    .irq_num = 0,
    .initialized = true,
    .using_sbi = false,
};

int timer_init(void) { return 0; }

void timer_init_percpu(void) {}

void timer_handler(uint64_t irq_num, void *parameter, struct pt_regs *regs) {
    (void)irq_num;
    (void)parameter;
    (void)regs;
}

void timer_set_next_tick_ns(uint64_t ns) { global_timer.next_deadline = ns; }

uint64_t get_counter() { return 0; }

uint64_t get_freq() { return global_timer.frequency; }

uint64_t realtime_boot_time() { return 0; }

uint64_t realtime_time() { return 0; }

uint64_t nano_time() { return 0; }

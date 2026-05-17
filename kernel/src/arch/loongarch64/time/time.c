#include <arch/loongarch64/loongarch64.h>
#include <arch/loongarch64/time/time.h>
#include <arch/loongarch64/csr.h>
#include <irq/irq_manager.h>

#define LOONGARCH_DEFAULT_TIMER_FREQ 100000000ULL

struct global_timer_state global_timer = {
    .frequency = LOONGARCH_DEFAULT_TIMER_FREQ,
    .next_deadline = 0,
    .irq_num = LOONGARCH_INT_TIMER,
    .initialized = false,
    .using_sbi = false,
};

static irq_controller_t loongarch64_timer_controller;
static uint64_t monotonic_base_cycles;
static uint64_t monotonic_base_ns;

static uint64_t loongarch64_timer_ticks_from_ns(uint64_t ns) {
    uint64_t freq = global_timer.frequency ? global_timer.frequency
                                           : LOONGARCH_DEFAULT_TIMER_FREQ;
    uint64_t ticks = (ns / 1000000000ULL) * freq;

    ticks += ((ns % 1000000000ULL) * freq) / 1000000000ULL;
    return ticks ? ticks : 1;
}

static int64_t loongarch64_timer_unmask(uint64_t irq, uint64_t flags) {
    (void)irq;
    (void)flags;
    csr_set(LOONGARCH_CSR_ECFG, LOONGARCH_ECFG_TIMER);
    return 0;
}

static int64_t loongarch64_timer_mask(uint64_t irq, uint64_t flags) {
    (void)irq;
    (void)flags;
    csr_clear(LOONGARCH_CSR_ECFG, LOONGARCH_ECFG_TIMER);
    return 0;
}

static int64_t loongarch64_timer_install(uint64_t irq, uint64_t arg,
                                         uint64_t flags) {
    (void)irq;
    (void)arg;
    (void)flags;
    return 0;
}

static int64_t loongarch64_timer_ack(uint64_t irq) {
    (void)irq;
    csr_write(LOONGARCH_CSR_TICLR, LOONGARCH_TICLR_CLR);
    return 0;
}

int timer_init(void) {
    global_timer.frequency = LOONGARCH_DEFAULT_TIMER_FREQ;
    global_timer.irq_num = LOONGARCH_INT_TIMER;
    monotonic_base_cycles = get_counter();
    monotonic_base_ns = 0;

    loongarch64_timer_controller = (irq_controller_t){
        .unmask = loongarch64_timer_unmask,
        .mask = loongarch64_timer_mask,
        .install = loongarch64_timer_install,
        .ack = loongarch64_timer_ack,
    };

    irq_regist_irq(global_timer.irq_num, timer_handler, 0, NULL,
                   &loongarch64_timer_controller, "LOONGARCH TIMER", 0);
    __atomic_store_n(&global_timer.initialized, true, __ATOMIC_RELEASE);
    return 0;
}

void timer_init_percpu(void) {
    if (!__atomic_load_n(&global_timer.initialized, __ATOMIC_ACQUIRE))
        return;

    timer_set_next_tick_ns(1000000000ULL / SCHED_HZ);
}

void timer_handler(uint64_t irq_num, void *parameter, struct pt_regs *regs) {
    (void)irq_num;
    (void)parameter;
    (void)regs;
    timer_set_next_tick_ns(1000000000ULL / SCHED_HZ);
}

void timer_set_next_tick_ns(uint64_t ns) {
    uint64_t ticks = loongarch64_timer_ticks_from_ns(ns);

    global_timer.next_deadline = get_counter() + ticks;
    csr_write(LOONGARCH_CSR_TICLR, LOONGARCH_TICLR_CLR);
    csr_write(LOONGARCH_CSR_TCFG,
              (ticks << LOONGARCH_TCFG_INITVAL_SHIFT) | LOONGARCH_TCFG_EN);
}

uint64_t get_counter() {
    uint64_t counter;
    uint64_t id;
    asm volatile("rdtime.d %0, %1" : "=r"(counter), "=r"(id));
    return counter;
}

uint64_t get_freq() { return global_timer.frequency; }

uint64_t realtime_boot_time() { return 0; }

uint64_t realtime_time() { return 0; }

uint64_t nano_time() {
    uint64_t freq = get_freq();
    uint64_t delta;

    if (!freq)
        return monotonic_base_ns;

    delta = get_counter() - monotonic_base_cycles;
    return monotonic_base_ns + (delta / freq) * 1000000000ULL +
           ((delta % freq) * 1000000000ULL) / freq;
}

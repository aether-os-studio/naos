#include <drivers/logger.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <drivers/clockevent.h>
#include <irq/irq_manager.h>
#include <uacpi/acpi.h>
#include <uacpi/tables.h>

typedef struct {
    uint64_t configurationAndCapability;
    uint64_t comparatorValue;
    uint64_t fsbInterruptRoute;
    uint64_t unused;
} __attribute__((packed)) HpetTimer;

typedef struct {
    uint64_t generalCapabilities;
    uint64_t reserved0;
    uint64_t generalConfiguration;
    uint64_t reserved1;
    uint64_t generalInterruptStatus;
    uint8_t reserved3[0xc8];
    uint64_t mainCounterValue;
    uint64_t reserved4;
    HpetTimer timers[];
} __attribute__((packed)) volatile HpetInfo;

#define CPUID_FEAT_EDX_TSC (1U << 4)
#define CPUID_FEAT_ECX_TSC_DEADLINE (1U << 24)
#define CPUID_FEAT_EDX_INVARIANT_TSC (1U << 8)

#define TSC_CALIBRATION_WINDOW_NS (50ULL * 1000ULL * 1000ULL)
#define HPET_GENERAL_ENABLE (1ULL << 0)
#define HPET_GENERAL_LEGACY_REPLACEMENT (1ULL << 1)
#define HPET_TIMER_INT_ENABLE (1ULL << 2)
#define HPET_TIMER_TYPE_PERIODIC (1ULL << 3)
#define HPET_TIMER_VALUE_SET (1ULL << 6)
#define HPET_TIMER_32BIT_MODE (1ULL << 8)
#define HPET_TIMER_INT_ROUTE_SHIFT 9
#define HPET_TIMER_FSB_ENABLE (1ULL << 14)
#define HPET_TIMER_FSB_CAPABLE (1ULL << 15)
#define HPET_TIMER_PERIODIC_CAPABLE (1ULL << 4)
#define HPET_TIMER_INT_ROUTE_MASK (0x1FULL << HPET_TIMER_INT_ROUTE_SHIFT)
#define HPET_TIMER_ROUTE_CAP_SHIFT 32
#define HPET_TIMER_ROUTE_CAP_MASK 0xFFFFFFFFULL

static HpetInfo *hpet_addr;
static uint32_t hpet_period_fs;
static bool hpet_clockevent_available;
static uint32_t hpet_clockevent_gsi;
static uint8_t hpet_clockevent_vector;
static clockevent_device_t hpet_clockevent;

static bool tsc_clocksource_enabled;
static bool tsc_deadline_supported;
static uint64_t tsc_freq_hz;
static uint64_t tsc_base_cycles;
static uint64_t tsc_base_ns;
static uint64_t tsc_ns_scale;

#define TSC_NS_SCALE_SHIFT 32U

static uint64_t hpet_main_counter(void) {
    if (hpet_addr == NULL)
        return 0;

    return hpet_addr->mainCounterValue;
}

uint64_t hpet_nano_time() {
    if (hpet_addr == NULL || hpet_period_fs == 0)
        return 0;

    return ((__uint128_t)hpet_main_counter() * hpet_period_fs) / 1000000ULL;
}

static uint64_t hpet_ns_to_ticks(uint64_t ns) {
    uint64_t ticks;

    if (hpet_period_fs == 0)
        return 0;

    ticks =
        ((__uint128_t)ns * 1000000ULL + hpet_period_fs - 1) / hpet_period_fs;
    return ticks ? ticks : 1;
}

static void tsc_calibrate_with_hpet(void) {
    uint32_t eax, ebx, ecx, edx;
    uint32_t max_basic = 0;
    uint32_t max_extended = 0;

    cpuid_count(0, 0, &max_basic, &ebx, &ecx, &edx);
    cpuid_count(0x80000000U, 0, &max_extended, &ebx, &ecx, &edx);

    if (max_basic < 1)
        return;

    cpuid_count(1, 0, &eax, &ebx, &ecx, &edx);
    if ((edx & CPUID_FEAT_EDX_TSC) == 0)
        return;

    tsc_deadline_supported = (ecx & CPUID_FEAT_ECX_TSC_DEADLINE) != 0;

    bool invariant_tsc = false;
    if (max_extended >= 0x80000007U) {
        cpuid_count(0x80000007U, 0, &eax, &ebx, &ecx, &edx);
        invariant_tsc = (edx & CPUID_FEAT_EDX_INVARIANT_TSC) != 0;
    }

    if (!invariant_tsc || hpet_addr == NULL)
        return;

    uint64_t start_ns = hpet_nano_time();
    uint64_t start_tsc = rdtsc_ordered();
    uint64_t deadline_ns = start_ns + TSC_CALIBRATION_WINDOW_NS;

    while (hpet_nano_time() < deadline_ns) {
        arch_pause();
    }

    uint64_t end_tsc = rdtsc_ordered();
    uint64_t end_ns = hpet_nano_time();
    uint64_t delta_ns = end_ns - start_ns;
    uint64_t delta_tsc = end_tsc - start_tsc;

    if (delta_ns == 0 || delta_tsc == 0)
        return;

    tsc_freq_hz = ((__uint128_t)delta_tsc * 1000000000ULL) / delta_ns;
    if (tsc_freq_hz == 0) {
        tsc_deadline_supported = false;
        return;
    }

    tsc_ns_scale =
        ((__uint128_t)1000000000ULL << TSC_NS_SCALE_SHIFT) / tsc_freq_hz;
    if (tsc_ns_scale == 0) {
        tsc_deadline_supported = false;
        return;
    }

    tsc_base_cycles = end_tsc;
    tsc_base_ns = end_ns;
    tsc_clocksource_enabled = true;
}

uint64_t nano_time() {
    if (!tsc_clocksource_enabled)
        return hpet_nano_time();

    uint64_t now = rdtsc_ordered();
    uint64_t delta = now - tsc_base_cycles;
    return tsc_base_ns +
           (((__uint128_t)delta * tsc_ns_scale) >> TSC_NS_SCALE_SHIFT);
}

bool tsc_clocksource_available() { return tsc_clocksource_enabled; }

bool tsc_deadline_mode_available() {
    return tsc_clocksource_enabled && tsc_deadline_supported;
}

uint64_t tsc_cycles_per_sec() { return tsc_freq_hz; }

void hpet_init() {
    struct uacpi_table hpet_table;
    uacpi_status status = uacpi_table_find_by_signature("HPET", &hpet_table);

    if (status != UACPI_STATUS_OK) {
        printk("HPET unavailable, nano_time will stay disabled.\n");
        return;
    }

    struct acpi_hpet *hpet = hpet_table.ptr;

    hpet_addr = (HpetInfo *)phys_to_virt(hpet->address.address);
    map_page_range(get_current_page_dir(false), (uint64_t)hpet_addr,
                   hpet->address.address, PAGE_SIZE, PT_FLAG_R | PT_FLAG_W);

    hpet_period_fs = hpet_addr->generalCapabilities >> 32;
    hpet_addr->generalConfiguration |= HPET_GENERAL_ENABLE;
    hpet_addr->mainCounterValue = 0;

    tsc_calibrate_with_hpet();
}

static int hpet_clockevent_set_next(clockevent_device_t *dev,
                                    uint64_t delta_ns) {
    uint64_t ticks;
    uint64_t comparator;

    (void)dev;

    if (!hpet_addr || !hpet_clockevent_available)
        return -ENODEV;

    ticks = hpet_ns_to_ticks(delta_ns);
    comparator = hpet_main_counter() + ticks;

    hpet_addr->timers[0].comparatorValue = comparator;
    hpet_addr->generalInterruptStatus = 1ULL;
    hpet_addr->timers[0].configurationAndCapability |= HPET_TIMER_INT_ENABLE;

    return 0;
}

static void hpet_clockevent_shutdown(clockevent_device_t *dev) {
    (void)dev;

    if (!hpet_addr)
        return;

    hpet_addr->timers[0].configurationAndCapability &= ~HPET_TIMER_INT_ENABLE;
    hpet_addr->generalInterruptStatus = 1ULL;
}

static void hpet_clockevent_irq_handler(uint64_t irq_num, void *data,
                                        struct pt_regs *regs) {
    (void)irq_num;
    (void)data;
    (void)regs;

    if (hpet_addr) {
        hpet_addr->timers[0].configurationAndCapability &=
            ~HPET_TIMER_INT_ENABLE;
        hpet_addr->generalInterruptStatus = 1ULL;
    }

    clockevent_handle_irq();
}

static const clockevent_ops_t hpet_clockevent_ops = {
    .set_next_event = hpet_clockevent_set_next,
    .shutdown = hpet_clockevent_shutdown,
};

static bool hpet_select_clockevent_route(uint64_t config, uint32_t *gsi_out) {
    uint32_t route_cap = (uint32_t)((config >> HPET_TIMER_ROUTE_CAP_SHIFT) &
                                    HPET_TIMER_ROUTE_CAP_MASK);

    for (uint32_t gsi = 16; gsi < 32; gsi++) {
        if (!(route_cap & (1U << gsi)))
            continue;
        if (!apic_gsi_available(gsi))
            continue;

        *gsi_out = gsi;
        return true;
    }

    return false;
}

void hpet_clockevent_init(void) {
    uint64_t config;
    int vector;

    if (!hpet_addr || hpet_period_fs == 0)
        return;

    config = hpet_addr->timers[0].configurationAndCapability;
    if (config & HPET_TIMER_FSB_CAPABLE)
        config &= ~HPET_TIMER_FSB_ENABLE;

    if (!hpet_select_clockevent_route(config, &hpet_clockevent_gsi)) {
        printk("HPET: no available interrupt route for timer0\n");
        return;
    }

    vector = irq_allocate_irqnum();
    if (vector < 0 || vector >= ARCH_MAX_IRQ_NUM ||
        irq_is_registered((uint64_t)vector)) {
        printk("HPET: cannot allocate interrupt vector\n");
        return;
    }
    hpet_clockevent_vector = (uint8_t)vector;

    config &= ~(HPET_TIMER_TYPE_PERIODIC | HPET_TIMER_32BIT_MODE |
                HPET_TIMER_VALUE_SET | HPET_TIMER_INT_ENABLE |
                HPET_TIMER_INT_ROUTE_MASK);
    config |= ((uint64_t)hpet_clockevent_gsi << HPET_TIMER_INT_ROUTE_SHIFT);
    hpet_addr->timers[0].configurationAndCapability = config;

    hpet_addr->generalConfiguration &= ~HPET_GENERAL_LEGACY_REPLACEMENT;
    hpet_addr->generalConfiguration |= HPET_GENERAL_ENABLE;
    hpet_addr->generalInterruptStatus = 1ULL;

    hpet_clockevent_available = true;
    hpet_clockevent.name = "hpet";
    hpet_clockevent.rating = 250;
    hpet_clockevent.min_delta_ns = 1000;
    hpet_clockevent.max_delta_ns =
        hpet_period_fs == 0 ? 0 : ((uint64_t)-1 / 1000000ULL) * hpet_period_fs;
    hpet_clockevent.ops = &hpet_clockevent_ops;

    irq_regist_irq(hpet_clockevent_vector, hpet_clockevent_irq_handler,
                   hpet_clockevent_gsi, NULL, &apic_controller, "HPET", 0);
    clockevent_register_device(&hpet_clockevent);

    printk("HPET: timer0 clockevent routed to GSI %u vector %u\n",
           hpet_clockevent_gsi, hpet_clockevent_vector);
}

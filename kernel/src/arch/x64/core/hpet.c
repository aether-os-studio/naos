#include <drivers/kernel_logger.h>
#include <mm/mm.h>
#include <arch/arch.h>
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

static HpetInfo *hpet_addr;
static uint32_t hpet_period_fs;

static bool tsc_clocksource_enabled;
static bool tsc_deadline_supported;
static uint64_t tsc_freq_hz;
static uint64_t tsc_base_cycles;
static uint64_t tsc_base_ns;

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

    tsc_base_cycles = end_tsc;
    tsc_base_ns = end_ns;
    tsc_clocksource_enabled = true;
}

uint64_t nano_time() {
    if (!tsc_clocksource_enabled)
        return hpet_nano_time();

    uint64_t now = rdtsc_ordered();
    uint64_t delta = now - tsc_base_cycles;
    return tsc_base_ns + ((__uint128_t)delta * 1000000000ULL) / tsc_freq_hz;
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
                   hpet->address.address, DEFAULT_PAGE_SIZE,
                   PT_FLAG_R | PT_FLAG_W);

    hpet_period_fs = hpet_addr->generalCapabilities >> 32;
    hpet_addr->generalConfiguration |= 1ULL;
    hpet_addr->mainCounterValue = 0;

    tsc_calibrate_with_hpet();
}

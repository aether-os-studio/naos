#include <arch/aarch64/drivers/timer.h>
#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>

struct global_timer_state g_timer = {0};

// 频率
static inline uint64_t read_cntfrq() {
    uint64_t val;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(val));
    return val;
}

// ---- EL1 虚拟定时器 ----
static inline uint64_t read_cntvct() {
    uint64_t val;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}

static inline void write_cntv_cval(uint64_t val) {
    __asm__ volatile("msr cntv_cval_el0, %0; isb" ::"r"(val) : "memory");
}

static inline void write_cntv_ctl(uint64_t val) {
    __asm__ volatile("msr cntv_ctl_el0, %0; isb" ::"r"(val) : "memory");
}

static inline uint64_t read_cntv_ctl() {
    uint64_t val;
    __asm__ volatile("mrs %0, cntv_ctl_el0" : "=r"(val));
    return val;
}

// ---- EL1 物理非安全定时器 ----
static inline uint64_t read_cntpct() {
    uint64_t val;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(val));
    return val;
}

static inline void write_cntp_cval(uint64_t val) {
    __asm__ volatile("msr cntp_cval_el0, %0; isb" ::"r"(val) : "memory");
}

static inline void write_cntp_ctl(uint64_t val) {
    __asm__ volatile("msr cntp_ctl_el0, %0; isb" ::"r"(val) : "memory");
}

static inline uint64_t read_cntp_ctl() {
    uint64_t val;
    __asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(val));
    return val;
}

// ============ 定时器操作表 ============

static const timer_ops_t timer_ops_virtual = {.read_counter = read_cntvct,
                                              .write_cval = write_cntv_cval,
                                              .write_ctl = write_cntv_ctl,
                                              .read_ctl = read_cntv_ctl,
                                              .name = "EL1 Virtual Timer"};

static const timer_ops_t timer_ops_physical = {.read_counter = read_cntpct,
                                               .write_cval = write_cntp_cval,
                                               .write_ctl = write_cntp_ctl,
                                               .read_ctl = read_cntp_ctl,
                                               .name = "EL1 Physical Timer"};

static bool timer_is_available(uint32_t gsiv) { return gsiv != 0; }

static void timer_select_best(struct acpi_gtdt *gtdt) {
    if (timer_is_available(gtdt->el1_non_secure_gsiv)) {
        g_timer.active_type = TIMER_TYPE_PHYSICAL_NONSECURE;
        g_timer.ops = &timer_ops_physical;
        g_timer.irq_num = gtdt->el1_non_secure_gsiv;
        g_timer.irq_flags = gtdt->el1_non_secure_flags;
        g_timer.always_on =
            gtdt->el1_non_secure_flags & ACPI_GTDT_ALWAYS_ON_CAPABLE;
    } else if (timer_is_available(gtdt->el1_virtual_gsiv)) {
        g_timer.active_type = TIMER_TYPE_VIRTUAL;
        g_timer.ops = &timer_ops_virtual;
        g_timer.irq_num = gtdt->el1_virtual_gsiv;
        g_timer.irq_flags = gtdt->el1_virtual_flags;
        g_timer.always_on =
            gtdt->el1_virtual_flags & ACPI_GTDT_ALWAYS_ON_CAPABLE;
    } else {
        // 最后尝试安全定时器（通常不可用）
        g_timer.active_type = TIMER_TYPE_PHYSICAL_SECURE;
        g_timer.ops = &timer_ops_physical;
        g_timer.irq_num = gtdt->el1_secure_gsiv;
        g_timer.irq_flags = gtdt->el1_secure_flags;
    }
}

int timer_init() {
    struct uacpi_table gtdt_table;
    uacpi_status status;

    status = uacpi_table_find_by_signature("GTDT", &gtdt_table);
    if (status == UACPI_STATUS_OK) {
        struct acpi_gtdt *gtdt = (struct acpi_gtdt *)gtdt_table.ptr;

        // 动态选择最佳定时器
        timer_select_best(gtdt);
    } else {
        // 使用物理定时器
        g_timer.active_type = TIMER_TYPE_PHYSICAL_NONSECURE;
        g_timer.ops = &timer_ops_physical;
        g_timer.irq_num = 30;
    }

    // 读取频率
    g_timer.frequency = read_cntfrq();
    if (g_timer.frequency == 0) {
        g_timer.frequency = 62500000; // 62.5MHz 默认值
    }

    g_timer.initialized = 1;

    return 0;
}

extern void gic_enable_irq(uint32_t irq);

void timer_init_percpu() {
    if (!g_timer.initialized || !g_timer.ops)
        return;

    gic_enable_irq(g_timer.irq_num);

    timer_set_next_tick_ns(1000000000ULL / SCHED_HZ);
}

uint64_t nanoTime() {
    uint64_t ticks = g_timer.ops->read_counter();
    __uint128_t ns = (__uint128_t)ticks * 1000000000ULL;
    return (uint64_t)(ns / g_timer.frequency);
}

void timer_set_next_tick_ns(uint64_t ns) {
    __uint128_t temp = (__uint128_t)ns * g_timer.frequency;
    uint64_t delta_ticks = (uint64_t)(temp / 1000000000ULL);

    uint64_t target = g_timer.ops->read_counter() + delta_ticks;
    g_timer.ops->write_cval(target);
    g_timer.ops->write_ctl(1); // Enable
}

timer_type_t timer_get_active_type() { return g_timer.active_type; }

const char *timer_get_type_name() {
    return g_timer.ops ? g_timer.ops->name : "None";
}

uint32_t timer_get_irq() { return g_timer.irq_num; }

bool timer_is_always_on() { return g_timer.always_on; }

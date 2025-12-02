#include <arch/aarch64/drivers/timer.h>
#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>
#include <boot/boot.h>
#include <drivers/kernel_logger.h>
#include <libs/aether/fdt.h>

struct global_timer_state g_timer = {0};

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

static inline void write_cntv_tval(uint64_t val) {
    __asm__ volatile("msr cntv_tval_el0, %0; isb" ::"r"(val) : "memory");
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

static inline void write_cntp_tval(uint64_t val) {
    __asm__ volatile("msr cntp_tval_el0, %0; isb" ::"r"(val) : "memory");
}

static inline void write_cntp_ctl(uint64_t val) {
    __asm__ volatile("msr cntp_ctl_el0, %0; isb" ::"r"(val) : "memory");
}

static inline uint64_t read_cntp_ctl() {
    uint64_t val;
    __asm__ volatile("mrs %0, cntp_ctl_el0" : "=r"(val));
    return val;
}

static const timer_ops_t timer_ops_virtual = {.read_counter = read_cntvct,
                                              .write_tval = write_cntv_tval,
                                              .write_ctl = write_cntv_ctl,
                                              .read_ctl = read_cntv_ctl,
                                              .name = "EL1 Virtual Timer"};

static const timer_ops_t timer_ops_physical = {.read_counter = read_cntpct,
                                               .write_tval = write_cntp_tval,
                                               .write_ctl = write_cntp_ctl,
                                               .read_ctl = read_cntp_ctl,
                                               .name = "EL1 Physical Timer"};

/* DTB 中断类型 */
#define IRQ_TYPE_EDGE_RISING 0x00000001
#define IRQ_TYPE_EDGE_FALLING 0x00000002
#define IRQ_TYPE_LEVEL_HIGH 0x00000004
#define IRQ_TYPE_LEVEL_LOW 0x00000008

/* ACPI GTDT 标志 */
#define ACPI_GTDT_INTERRUPT_MODE (1 << 0)     // 0=电平, 1=边沿
#define ACPI_GTDT_INTERRUPT_POLARITY (1 << 1) // 0=高/上升, 1=低/下降
#define ACPI_GTDT_ALWAYS_ON_CAPABLE (1 << 2)

/**
 * 将 DTB 中断标志转换为 ACPI 格式
 */
static uint32_t dtb_irq_flags_to_acpi(uint32_t dtb_flags) {
    uint32_t acpi_flags = 0;

    if (dtb_flags & (IRQ_TYPE_EDGE_RISING | IRQ_TYPE_EDGE_FALLING)) {
        acpi_flags |= ACPI_GTDT_INTERRUPT_MODE; // 边沿触发
    }

    if (dtb_flags & (IRQ_TYPE_LEVEL_LOW | IRQ_TYPE_EDGE_FALLING)) {
        acpi_flags |= ACPI_GTDT_INTERRUPT_POLARITY; // 低电平/下降沿
    }

    return acpi_flags;
}

static int timer_get_irq_from_dtb(void *fdt, int node_offset, int index,
                                  uint32_t *irq_num, uint32_t *irq_flags) {
    int len;
    const uint32_t *interrupts =
        fdt_getprop(fdt, node_offset, "interrupts", &len);

    if (!interrupts || len <= 0) {
        return -1;
    }

    /* 每个中断占 3 个 cells */
    int cells_per_irq = 3;
    int total_irqs = len / (sizeof(uint32_t) * cells_per_irq);

    if (index >= total_irqs) {
        return -1;
    }

    const uint32_t *entry = interrupts + (index * cells_per_irq);

    uint32_t type = fdt32_to_cpu(entry[0]); // 0=SPI, 1=PPI
    uint32_t irq = fdt32_to_cpu(entry[1]);
    uint32_t flags = fdt32_to_cpu(entry[2]);

    /*
     * GIC 中断编号:
     * SGI: 0-15
     * PPI: 16-31
     * SPI: 32+
     */
    if (type == 1) { // PPI
        *irq_num = irq + 16;
    } else { // SPI
        *irq_num = irq + 32;
    }

    /* 转换标志 */
    *irq_flags = dtb_irq_flags_to_acpi(flags);

    return 0;
}

/**
 * 从 DTB 获取频率
 */
static uint64_t timer_get_freq_from_dtb(void *fdt, int node_offset) {
    int len;
    const uint32_t *freq_prop =
        fdt_getprop(fdt, node_offset, "clock-frequency", &len);
    if (freq_prop && len == sizeof(uint32_t)) {
        return fdt32_to_cpu(*freq_prop);
    }
    return 0;
}

/**
 * 从 DTB 初始化 timer
 */
static int timer_init_from_dtb(void) {
    void *fdt = (void *)boot_get_dtb();

    if (!fdt) {
        printk("Timer: No DTB available\n");
        return -1;
    }

    /* 查找 timer 节点 */
    int timer_node = fdt_path_offset(fdt, "/timer");
    if (timer_node < 0) {
        printk("Timer: DTB timer node not found\n");
        return -1;
    }

    /* 检查 compatible */
    int len;
    const char *compatible = fdt_getprop(fdt, timer_node, "compatible", &len);
    if (!compatible) {
        printk("Timer: No compatible property\n");
        return -1;
    }

    printk("Timer: Found DTB timer node, compatible: %s\n", compatible);

    /* 检查是否是 ARM Generic Timer */
    if (!strstr(compatible, "arm,armv8-timer") &&
        !strstr(compatible, "arm,armv7-timer")) {
        printk("Timer: Not an ARM Generic Timer\n");
        return -1;
    }

    /*
     * ARM Generic Timer interrupts 顺序:
     * [0] = secure EL1 timer (PPI 13)
     * [1] = non-secure EL1 timer (PPI 14)
     * [2] = virtual timer (PPI 11)
     * [3] = hypervisor timer (PPI 10)
     */

    uint32_t irq_num, irq_flags;

    /* 优先使用 non-secure physical timer */
    if (timer_get_irq_from_dtb(fdt, timer_node, 1, &irq_num, &irq_flags) == 0) {
        g_timer.active_type = TIMER_TYPE_PHYSICAL_NONSECURE;
        g_timer.ops = &timer_ops_physical;
        g_timer.irq_num = irq_num;
        g_timer.irq_flags = irq_flags;
        printk("Timer: Using non-secure physical timer (PPI %d, IRQ %d)\n",
               irq_num - 16, irq_num);
    }
    /* 备选: virtual timer */
    else if (timer_get_irq_from_dtb(fdt, timer_node, 2, &irq_num, &irq_flags) ==
             0) {
        g_timer.active_type = TIMER_TYPE_VIRTUAL;
        g_timer.ops = &timer_ops_virtual;
        g_timer.irq_num = irq_num;
        g_timer.irq_flags = irq_flags;
        printk("Timer: Using virtual timer (PPI %d, IRQ %d)\n", irq_num - 16,
               irq_num);
    } else {
        printk("Timer: No suitable timer interrupt found in DTB\n");
        return -1;
    }

    printk("Timer: IRQ flags = 0x%x (mode=%s, polarity=%s)\n", irq_flags,
           (irq_flags & ACPI_GTDT_INTERRUPT_MODE) ? "edge" : "level",
           (irq_flags & ACPI_GTDT_INTERRUPT_POLARITY) ? "low/falling"
                                                      : "high/rising");

    const void *always_on = fdt_getprop(fdt, timer_node, "always-on", NULL);
    g_timer.always_on = (always_on != NULL);

    if (g_timer.always_on) {
        printk("Timer: Marked as always-on\n");
    }

    /* 尝试从 DTB 获取频率 */
    uint64_t dtb_freq = timer_get_freq_from_dtb(fdt, timer_node);
    if (dtb_freq > 0) {
        g_timer.frequency = dtb_freq;
        printk("Timer: Clock frequency from DTB: %llu Hz (%llu.%03llu MHz)\n",
               dtb_freq, dtb_freq / 1000000, (dtb_freq % 1000000) / 1000);
        return 0; // 成功
    }

    return 0; // 成功（频率稍后从硬件读取）
}

static bool timer_is_available(uint32_t gsiv) { return gsiv != 0; }

/**
 * 从 ACPI GTDT 选择最佳 timer
 */
static void timer_select_best_acpi(struct acpi_gtdt *gtdt) {
    if (timer_is_available(gtdt->el1_non_secure_gsiv)) {
        g_timer.active_type = TIMER_TYPE_PHYSICAL_NONSECURE;
        g_timer.ops = &timer_ops_physical;
        g_timer.irq_num = gtdt->el1_non_secure_gsiv;
        g_timer.irq_flags = gtdt->el1_non_secure_flags;
        g_timer.always_on =
            gtdt->el1_non_secure_flags & ACPI_GTDT_ALWAYS_ON_CAPABLE;
        printk("Timer: Using ACPI non-secure physical timer (GSIV %d)\n",
               gtdt->el1_non_secure_gsiv);
    } else if (timer_is_available(gtdt->el1_virtual_gsiv)) {
        g_timer.active_type = TIMER_TYPE_VIRTUAL;
        g_timer.ops = &timer_ops_virtual;
        g_timer.irq_num = gtdt->el1_virtual_gsiv;
        g_timer.irq_flags = gtdt->el1_virtual_flags;
        g_timer.always_on =
            gtdt->el1_virtual_flags & ACPI_GTDT_ALWAYS_ON_CAPABLE;
        printk("Timer: Using ACPI virtual timer (GSIV %d)\n",
               gtdt->el1_virtual_gsiv);
    } else {
        // 最后尝试安全定时器（通常不可用）
        g_timer.active_type = TIMER_TYPE_PHYSICAL_SECURE;
        g_timer.ops = &timer_ops_physical;
        g_timer.irq_num = gtdt->el1_secure_gsiv;
        g_timer.irq_flags = gtdt->el1_secure_flags;
        printk("Timer: Using ACPI secure physical timer (GSIV %d)\n",
               gtdt->el1_secure_gsiv);
    }

    printk("Timer: ACPI flags = 0x%x\n", g_timer.irq_flags);
}

static int timer_init_from_acpi(void) {
    struct uacpi_table gtdt_table;
    uacpi_status status;

    status = uacpi_table_find_by_signature("GTDT", &gtdt_table);
    if (status != UACPI_STATUS_OK) {
        printk("Timer: ACPI GTDT table not found\n");
        return -1;
    }

    struct acpi_gtdt *gtdt = (struct acpi_gtdt *)gtdt_table.ptr;
    printk("Timer: Found ACPI GTDT table\n");

    timer_select_best_acpi(gtdt);

    /* ACPI 通常不提供频率信息，需要从硬件读取 */
    return 0;
}

int timer_init(void) {
    int ret;
    bool from_acpi = false;
    bool from_dtb = false;

    /* 尝试从 ACPI 初始化 */
    ret = timer_init_from_acpi();
    if (ret == 0) {
        from_acpi = true;
        printk("Timer: Configured from ACPI\n");
    }
    /* 尝试从 DTB 初始化 */
    else {
        ret = timer_init_from_dtb();
        if (ret == 0) {
            from_dtb = true;
            printk("Timer: Configured from DTB\n");
        }
        /* 使用硬编码默认值 */
        else {
            printk("Timer: Using hardcoded defaults\n");
            g_timer.active_type = TIMER_TYPE_PHYSICAL_NONSECURE;
            g_timer.ops = &timer_ops_physical;
            g_timer.irq_num = 30;  // PPI 14 + 16
            g_timer.irq_flags = 0; // 电平触发，高电平有效
            g_timer.always_on = false;
        }
    }

    /* 读取并验证频率 */
    uint64_t hw_freq = read_cntfrq();
    printk("Timer: Hardware CNTFRQ_EL0 = %llu Hz\n", hw_freq);

    /* 如果已经从 DTB 获取了频率，优先使用 DTB 的值 */
    if (from_dtb && g_timer.frequency > 0) {
        printk("Timer: Using frequency from DTB: %llu Hz\n", g_timer.frequency);

        /* 但是检查硬件寄存器是否一致 */
        if (hw_freq > 0 && hw_freq != g_timer.frequency) {
            printk("Timer: WARNING - DTB freq (%llu) != HW freq (%llu)\n",
                   g_timer.frequency, hw_freq);
        }
    } else {
        /* 使用硬件寄存器的值 */
        if (hw_freq > 0) {
            g_timer.frequency = hw_freq;
        } else {
            /* 硬件寄存器也是 0，使用默认值 */
            printk("Timer: WARNING - CNTFRQ_EL0 is 0\n");
            g_timer.frequency = 54000000; // Raspberry Pi 400 default
        }
    }

    printk("Timer: Final configuration:\n");
    printk("  Type: %s\n", g_timer.ops->name);
    printk("  IRQ: %d\n", g_timer.irq_num);
    printk("  Flags: 0x%x\n", g_timer.irq_flags);
    printk("  Frequency: %llu Hz (%llu.%03llu MHz)\n", g_timer.frequency,
           g_timer.frequency / 1000000, (g_timer.frequency % 1000000) / 1000);
    printk("  Always-on: %s\n", g_timer.always_on ? "yes" : "no");
    printk("  Source: %s\n",
           from_acpi ? "ACPI" : (from_dtb ? "DTB" : "Hardcoded"));

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

uint64_t nano_time() {
    if (!g_timer.ops) {
        return 0;
    }

    uint64_t ticks = g_timer.ops->read_counter();

    /* 使用 128 位乘法避免溢出 */
    __uint128_t ns = (__uint128_t)ticks * 1000000000ULL;
    return (uint64_t)(ns / g_timer.frequency);
}

void timer_set_next_tick_ns(uint64_t ns) {
    if (!g_timer.ops) {
        return;
    }

    /* 计算 tick 数 */
    __uint128_t temp = (__uint128_t)ns * g_timer.frequency;
    uint64_t delta_ticks = (uint64_t)(temp / 1000000000ULL);

    g_timer.ops->write_tval(delta_ticks);
    g_timer.ops->write_ctl(1); // Enable
}

timer_type_t timer_get_active_type(void) { return g_timer.active_type; }

const char *timer_get_type_name(void) {
    return g_timer.ops ? g_timer.ops->name : "None";
}

uint32_t timer_get_irq(void) { return g_timer.irq_num; }

bool timer_is_always_on(void) { return g_timer.always_on; }

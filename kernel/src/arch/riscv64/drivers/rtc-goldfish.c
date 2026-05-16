#include <arch/riscv64/drivers/rtc-goldfish.h>
#include <boot/boot.h>
#include <drivers/logger.h>
#include <drivers/rtc.h>
#include <libs/fdt/libfdt.h>
#include <mm/mm.h>

#define GOLDFISH_RTC_TIME_LOW 0x00
#define GOLDFISH_RTC_TIME_HIGH 0x04
#define GOLDFISH_RTC_ALARM_LOW 0x08
#define GOLDFISH_RTC_ALARM_HIGH 0x0C
#define GOLDFISH_RTC_IRQ_ENABLED 0x10
#define GOLDFISH_RTC_CLEAR_ALARM 0x14

#define DT_MAX_CELLS 4

static volatile uint8_t *goldfish_rtc_base;
static rtc_device_t goldfish_rtc_device;

static uint64_t fdt_read_cells(const uint32_t **p, int cells) {
    uint64_t value = 0;

    if (cells <= 0 || cells > DT_MAX_CELLS)
        return 0;

    for (int i = 0; i < cells; i++)
        value = (value << 32) | fdt32_ld(&(*p)[i]);

    *p += cells;
    return value;
}

static uint64_t fdt_translate_address(const void *fdt, int node_offset,
                                      uint64_t addr) {
    int parent = fdt_parent_offset(fdt, node_offset);

    while (parent >= 0) {
        int len = 0;
        const uint32_t *ranges = fdt_getprop(fdt, parent, "ranges", &len);
        if (!ranges || len <= 0) {
            parent = fdt_parent_offset(fdt, parent);
            continue;
        }

        int child_addr_cells = fdt_address_cells(fdt, parent);
        int parent_parent = fdt_parent_offset(fdt, parent);
        int parent_addr_cells =
            (parent_parent >= 0) ? fdt_address_cells(fdt, parent_parent) : 2;
        int size_cells = fdt_size_cells(fdt, parent);
        int cells_per_entry = child_addr_cells + parent_addr_cells + size_cells;

        if (child_addr_cells <= 0 || child_addr_cells > DT_MAX_CELLS ||
            parent_addr_cells <= 0 || parent_addr_cells > DT_MAX_CELLS ||
            size_cells < 0 || size_cells > DT_MAX_CELLS ||
            cells_per_entry <= 0) {
            return addr;
        }

        int num_entries = (len / (int)sizeof(uint32_t)) / cells_per_entry;
        const uint32_t *p = ranges;
        for (int i = 0; i < num_entries; i++) {
            uint64_t child_addr = fdt_read_cells(&p, child_addr_cells);
            uint64_t parent_addr = fdt_read_cells(&p, parent_addr_cells);
            uint64_t range_size = fdt_read_cells(&p, size_cells);

            if (addr >= child_addr && addr < child_addr + range_size) {
                addr = parent_addr + (addr - child_addr);
                break;
            }
        }

        parent = parent_parent;
    }

    return addr;
}

static int fdt_get_reg(const void *fdt, int node_offset, uint64_t *addr,
                       uint64_t *size) {
    int len = 0;
    const uint32_t *reg = fdt_getprop(fdt, node_offset, "reg", &len);
    if (!reg || len <= 0 || !addr || !size)
        return -EINVAL;

    int parent = fdt_parent_offset(fdt, node_offset);
    int address_cells = (parent >= 0) ? fdt_address_cells(fdt, parent) : 2;
    int size_cells = (parent >= 0) ? fdt_size_cells(fdt, parent) : 2;
    if (address_cells <= 0 || address_cells > DT_MAX_CELLS || size_cells < 0 ||
        size_cells > DT_MAX_CELLS)
        return -EINVAL;

    int cells_per_entry = address_cells + size_cells;
    if (cells_per_entry <= 0 || len < cells_per_entry * (int)sizeof(uint32_t))
        return -EINVAL;

    const uint32_t *p = reg;
    *addr = fdt_translate_address(fdt, node_offset,
                                  fdt_read_cells(&p, address_cells));
    *size = fdt_read_cells(&p, size_cells);
    return 0;
}

static uint32_t goldfish_read32(uint32_t offset) {
    return *(volatile uint32_t *)(goldfish_rtc_base + offset);
}

static void goldfish_write32(uint32_t offset, uint32_t value) {
    *(volatile uint32_t *)(goldfish_rtc_base + offset) = value;
}

static uint64_t goldfish_read_time_ns(void) {
    uint32_t high;
    uint32_t low;
    uint32_t high2;

    do {
        high = goldfish_read32(GOLDFISH_RTC_TIME_HIGH);
        low = goldfish_read32(GOLDFISH_RTC_TIME_LOW);
        high2 = goldfish_read32(GOLDFISH_RTC_TIME_HIGH);
    } while (high != high2);

    return ((uint64_t)high << 32) | low;
}

static int goldfish_rtc_read_time(struct rtc_device *rtc, rtc_time_t *tm) {
    (void)rtc;

    if (!tm)
        return -EINVAL;

    rtc_seconds_to_time(goldfish_read_time_ns() / 1000000000ULL, tm);
    return 0;
}

static int goldfish_rtc_read_realtime(struct rtc_device *rtc,
                                      rtc_realtime_t *time) {
    uint64_t ns;

    (void)rtc;

    if (!time)
        return -EINVAL;

    ns = goldfish_read_time_ns();
    time->sec = ns / 1000000000ULL;
    time->nsec = (uint32_t)(ns % 1000000000ULL);
    return 0;
}

static int goldfish_rtc_set_time(struct rtc_device *rtc, const rtc_time_t *tm) {
    (void)rtc;
    (void)tm;
    return -ENOSYS;
}

static int goldfish_rtc_read_alarm(struct rtc_device *rtc, rtc_alarm_t *alarm) {
    (void)rtc;

    if (!alarm)
        return -EINVAL;

    memset(alarm, 0, sizeof(*alarm));
    return -ENOSYS;
}

static int goldfish_rtc_set_alarm(struct rtc_device *rtc,
                                  const rtc_alarm_t *alarm) {
    uint64_t alarm_ns;

    (void)rtc;

    if (!alarm)
        return -EINVAL;

    alarm_ns = rtc_time_to_seconds(&alarm->time) * 1000000000ULL;
    goldfish_write32(GOLDFISH_RTC_ALARM_LOW, (uint32_t)alarm_ns);
    goldfish_write32(GOLDFISH_RTC_ALARM_HIGH, (uint32_t)(alarm_ns >> 32));
    goldfish_write32(GOLDFISH_RTC_IRQ_ENABLED, alarm->enabled ? 1 : 0);
    return 0;
}

static int goldfish_rtc_alarm_enable_irq(struct rtc_device *rtc, bool enabled) {
    (void)rtc;

    goldfish_write32(GOLDFISH_RTC_IRQ_ENABLED, enabled ? 1 : 0);
    if (!enabled)
        goldfish_write32(GOLDFISH_RTC_CLEAR_ALARM, 1);
    return 0;
}

static const rtc_class_ops_t goldfish_rtc_ops = {
    .read_time = goldfish_rtc_read_time,
    .set_time = goldfish_rtc_set_time,
    .read_alarm = goldfish_rtc_read_alarm,
    .set_alarm = goldfish_rtc_set_alarm,
    .alarm_enable_irq = goldfish_rtc_alarm_enable_irq,
    .read_realtime = goldfish_rtc_read_realtime,
};

static rtc_device_t goldfish_rtc_device = {
    .name = "goldfish-rtc",
    .ops = &goldfish_rtc_ops,
};

void rtc_goldfish_init(void) {
    const void *fdt = (const void *)boot_get_dtb();
    if (!fdt)
        return;

    int node = -1;
    while ((node = fdt_node_offset_by_compatible(fdt, node,
                                                 "google,goldfish-rtc")) >= 0) {
        uint64_t phys = 0;
        uint64_t size = 0;
        if (fdt_get_reg(fdt, node, &phys, &size) != 0)
            continue;

        if (!size)
            size = PAGE_SIZE;

        uint64_t phys_base = PADDING_DOWN(phys, PAGE_SIZE);
        uint64_t phys_end = PADDING_UP(phys + size, PAGE_SIZE);
        uint64_t virt_base = (uint64_t)phys_to_virt(phys_base);
        if (!virt_base)
            continue;

        if (map_page_range(get_current_page_dir(false), virt_base, phys_base,
                           phys_end - phys_base,
                           PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE) != 0) {
            continue;
        }

        goldfish_rtc_base =
            (volatile uint8_t *)(virt_base + (phys - phys_base));
        rtc_register_device(&goldfish_rtc_device);
        printk("goldfish-rtc: mmio %#018lx size %#lx\n", phys, size);

#ifdef CONFIG_BOOT_SBI
        extern uint64_t sbi_boottime;
        rtc_realtime_t boottime;
        if (rtc_read_realtime(&boottime) == 0) {
            sbi_boottime = boottime.sec;
        }
#endif

        return;
    }
}

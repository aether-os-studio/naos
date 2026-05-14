#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/resources.h>
#include <acpi/uacpi/tables.h>
#include <acpi/uacpi/uacpi.h>
#include <acpi/uacpi/utilities.h>
#include <arch/riscv64/time/time.h>
#include <boot/boot.h>
#include <drivers/logger.h>
#include <irq/irq_manager.h>
#include <libs/fdt/libfdt.h>
#include <limine.h>
#include <mm/hhdm.h>
#include <mm/mm.h>

#define FDT_MAX_NCELLS 4
#define RISCV_TIMER_NS_SCALE_SHIFT 32U

#define GOLDFISH_RTC_TIME_LOW 0x00
#define GOLDFISH_RTC_TIME_HIGH 0x04

static uint64_t monotonic_base_cycles;
static uint64_t monotonic_ns_scale;

struct global_timer_state global_timer = {
    .frequency = 10000000ULL,
    .irq_num = 5,
};

static irq_controller_t riscv_sbi_timer_controller;

static inline uint64_t riscv64_sbi_ecall(uint64_t eid, uint64_t fid,
                                         uint64_t arg0, uint64_t arg1,
                                         uint64_t arg2, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5) {
    register uint64_t a0 asm("a0") = arg0;
    register uint64_t a1 asm("a1") = arg1;
    register uint64_t a2 asm("a2") = arg2;
    register uint64_t a3 asm("a3") = arg3;
    register uint64_t a4 asm("a4") = arg4;
    register uint64_t a5 asm("a5") = arg5;
    register uint64_t a6 asm("a6") = fid;
    register uint64_t a7 asm("a7") = eid;

    asm volatile("ecall"
                 : "+r"(a0), "+r"(a1)
                 : "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7)
                 : "memory");
    return a0;
}

static inline int64_t riscv64_sbi_set_timer(uint64_t stime_value) {
    return (int64_t)riscv64_sbi_ecall(0x54494D45ULL, 0, stime_value, 0, 0, 0, 0,
                                      0);
}

static uint64_t timer_frequency_from_acpi(void) {
    struct uacpi_table rhct_table;
    if (uacpi_table_find_by_signature(ACPI_RHCT_SIGNATURE, &rhct_table) !=
        UACPI_STATUS_OK) {
        return 0;
    }

    struct acpi_rhct *rhct = rhct_table.ptr;
    return rhct ? rhct->timebase_frequency : 0;
}

static uint64_t timer_frequency_from_dtb(void) {
    const void *fdt = (const void *)boot_get_dtb();
    if (!fdt)
        return 0;

    int cpus = fdt_path_offset(fdt, "/cpus");
    if (cpus < 0)
        return 0;

    int len = 0;
    const uint32_t *prop = fdt_getprop(fdt, cpus, "timebase-frequency", &len);
    if (!prop || len < (int)sizeof(uint32_t))
        return 0;

    return fdt32_ld(prop);
}

static uint64_t fdt_read_cells(const uint32_t **p, int cells) {
    uint64_t value = 0;

    if (cells <= 0 || cells > FDT_MAX_NCELLS)
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

        if (child_addr_cells < 0 || child_addr_cells > FDT_MAX_NCELLS ||
            parent_addr_cells < 0 || parent_addr_cells > FDT_MAX_NCELLS ||
            size_cells < 0 || size_cells > FDT_MAX_NCELLS ||
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

static int fdt_get_reg(const void *fdt, int node_offset, int index,
                       uint64_t *addr, uint64_t *size) {
    int len = 0;
    const uint32_t *reg = fdt_getprop(fdt, node_offset, "reg", &len);
    int parent;
    int address_cells;
    int size_cells;
    int cells_per_entry;
    int total_entries;
    const uint32_t *p;

    if (!reg || len <= 0 || !addr || !size)
        return -1;

    parent = fdt_parent_offset(fdt, node_offset);
    address_cells = (parent >= 0) ? fdt_address_cells(fdt, parent) : 2;
    size_cells = (parent >= 0) ? fdt_size_cells(fdt, parent) : 2;

    if (address_cells <= 0 || address_cells > FDT_MAX_NCELLS ||
        size_cells < 0 || size_cells > FDT_MAX_NCELLS) {
        return -1;
    }

    cells_per_entry = address_cells + size_cells;
    if (cells_per_entry <= 0)
        return -1;

    total_entries = (len / (int)sizeof(uint32_t)) / cells_per_entry;
    if (index < 0 || index >= total_entries)
        return -1;

    p = reg + index * cells_per_entry;
    *addr = fdt_translate_address(fdt, node_offset,
                                  fdt_read_cells(&p, address_cells));
    *size = fdt_read_cells(&p, size_cells);
    return 0;
}

static int64_t riscv_sbi_timer_unmask(uint64_t irq, uint64_t flags) {
    (void)irq;
    (void)flags;
    timer_set_next_tick_ns(1000000000ULL / SCHED_HZ);
    return 0;
}

static int64_t riscv_sbi_timer_mask(uint64_t irq, uint64_t flags) {
    (void)irq;
    (void)flags;
    riscv64_sbi_set_timer(UINT64_MAX);
    return 0;
}

static int64_t riscv_sbi_timer_install(uint64_t irq, uint64_t arg,
                                       uint64_t flags) {
    (void)irq;
    (void)arg;
    (void)flags;
    return 0;
}

static int64_t riscv_sbi_timer_ack(uint64_t irq) {
    (void)irq;
    timer_set_next_tick_ns(1000000000ULL / SCHED_HZ);
    return 0;
}

void timer_set_next_tick_ns(uint64_t ns) {
    if (!__atomic_load_n(&global_timer.initialized, __ATOMIC_ACQUIRE) ||
        !global_timer.frequency)
        return;

    __uint128_t ticks128 = (__uint128_t)ns * global_timer.frequency;
    uint64_t delta_ticks = (uint64_t)(ticks128 / 1000000000ULL);
    if (delta_ticks == 0)
        delta_ticks = 1;

    uint64_t next = get_counter() + delta_ticks;
    global_timer.next_deadline = next;
    riscv64_sbi_set_timer(next);
}

void timer_handler(uint64_t irq_num, void *parameter, struct pt_regs *regs) {
    (void)irq_num;
    (void)parameter;
    (void)regs;
}

int timer_init(void) {
    const char *freq_source = "default";
    // if (boot_get_firmware_type() != LIMINE_FIRMWARE_TYPE_SBI) {
    //     printk("RISC-V timer: non-SBI firmware is not supported yet\n");
    //     return -1;
    // }

    uint64_t freq = timer_frequency_from_acpi();
    if (freq) {
        freq_source = "ACPI RHCT";
    } else {
        freq = timer_frequency_from_dtb();
        if (freq)
            freq_source = "DTB";
    }

    if (freq)
        global_timer.frequency = freq;

    global_timer.using_sbi = true;
    global_timer.irq_num = 5;

    riscv_sbi_timer_controller = (irq_controller_t){
        .unmask = riscv_sbi_timer_unmask,
        .mask = riscv_sbi_timer_mask,
        .install = riscv_sbi_timer_install,
        .ack = riscv_sbi_timer_ack,
    };

    irq_regist_irq(global_timer.irq_num, timer_handler, 0, NULL,
                   &riscv_sbi_timer_controller, "SBI TIMER", 0);
    __atomic_store_n(&global_timer.initialized, true, __ATOMIC_RELEASE);
    monotonic_base_cycles = get_counter();
    monotonic_ns_scale =
        ((__uint128_t)1000000000ULL << RISCV_TIMER_NS_SCALE_SHIFT) /
        global_timer.frequency;

    if (!freq) {
        printk("RISC-V timer: timebase frequency not found, using default %llu "
               "Hz\n",
               global_timer.frequency);
    }

    printk("RISC-V timer: SBI, frequency=%llu Hz, source=%s, base=%llu\n",
           global_timer.frequency, freq_source, monotonic_base_cycles);
    return 0;
}

void timer_init_percpu(void) {
    if (!__atomic_load_n(&global_timer.initialized, __ATOMIC_ACQUIRE))
        return;

    uint64_t stie = 1UL << 5;
    asm volatile("csrs sie, %0" : : "r"(stie) : "memory");
    timer_set_next_tick_ns(1000000000ULL / SCHED_HZ);
}

uint64_t get_counter() {
    uint64_t time;
    asm volatile("rdtime %0" : "=r"(time));
    return time;
}

uint64_t get_freq() { return global_timer.frequency; }

uint64_t realtime_boot_time() { return boot_get_boottime(); }

uint64_t nano_time() {
    uint64_t delta_cycles;
    uint64_t freq = get_freq();

    if (freq == 0)
        return 0;

    delta_cycles = get_counter() - monotonic_base_cycles;
    if (monotonic_ns_scale) {
        return ((uint64_t)((__uint128_t)delta_cycles * monotonic_ns_scale >>
                           RISCV_TIMER_NS_SCALE_SHIFT));
    }

    return (uint64_t)(((__uint128_t)delta_cycles * 1000000000ULL) / freq);
}

uint64_t realtime_time() {
    return realtime_boot_time() * 1000000000ULL + nano_time();
}

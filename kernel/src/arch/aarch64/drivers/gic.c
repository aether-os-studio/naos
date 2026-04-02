#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>
#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <mm/mm.h>
#include <boot/boot.h>
#include <drivers/fdt/fdt.h>

uint64_t gicc_base_virt = 0;
uint64_t gicc_base_address = 0;
uint64_t gicd_base_virt = 0;
uint64_t gicd_base_address = 0;
uint64_t gicr_base_virt = 0;
uint64_t gicr_base_address = 0;
static uint64_t gicr_region_size = 0;
gic_version_t gic_version = GIC_VERSION_UNKNOWN;
static bool gic_ipi_initialized = false;
static uint8_t gic_v2_cpu_sgi_target_mask[MAX_CPU_NUM];
static uint32_t gic_v2_active_iar[MAX_CPU_NUM];

// 内存屏障
#define dsb(op) asm volatile("dsb " #op : : : "memory")
#define isb() asm volatile("isb" : : : "memory")
#define dmb(op) asm volatile("dmb " #op : : : "memory")

#define ICC_SRE_SRE (1UL << 0)
#define ICC_SRE_DFB (1UL << 1)
#define ICC_SRE_DIB (1UL << 2)
#define GIC_IRQ_FLAG_MODE_EDGE (1U << 0)

static inline void gic_cpu_relax(void) { asm volatile("yield" : : : "memory"); }

static inline void gicd_wait_for_rwp(void) {
    while (*(volatile uint32_t *)(gicd_base_virt + GICD_CTLR) & GICD_CTLR_RWP) {
        gic_cpu_relax();
    }
}

static inline uint32_t gic_mpidr_to_affinity(uint64_t mpidr) {
    return (uint32_t)((mpidr & 0xFF) | (((mpidr >> 8) & 0xFF) << 8) |
                      (((mpidr >> 16) & 0xFF) << 16) |
                      (((mpidr >> 32) & 0xFF) << 24));
}

static inline uint8_t gic_mpidr_aff0(uint64_t mpidr) { return mpidr & 0xFF; }

static inline uint8_t gic_mpidr_aff1(uint64_t mpidr) {
    return (mpidr >> 8) & 0xFF;
}

static inline uint8_t gic_mpidr_aff2(uint64_t mpidr) {
    return (mpidr >> 16) & 0xFF;
}

static inline uint8_t gic_mpidr_aff3(uint64_t mpidr) {
    return (mpidr >> 32) & 0xFF;
}

static void gic_configure_icfgr(uint64_t base, uint32_t icfgr_base,
                                uint32_t irq, bool edge_triggered) {
    uint32_t reg = irq / 16;
    uint32_t bit = ((irq % 16) * 2) + 1;
    volatile uint32_t *icfgr =
        (volatile uint32_t *)(base + icfgr_base + reg * sizeof(uint32_t));
    uint32_t value = *icfgr;

    value &= ~(1U << bit);
    if (edge_triggered) {
        value |= (1U << bit);
    }

    *icfgr = value;
    dsb(sy);
}

static uint64_t gicr_v3_cpu_base(void) {
    if (!gicr_base_virt) {
        return 0;
    }

    uint32_t affinity = gic_mpidr_to_affinity(current_mpidr());

    for (uint64_t offset = 0; offset + GICR_STRIDE <= gicr_region_size;
         offset += GICR_STRIDE) {
        uint64_t gicr_addr = gicr_base_virt + offset;
        uint64_t typer = *(volatile uint64_t *)(gicr_addr + GICR_TYPER);

        if ((uint32_t)(typer >> 32) == affinity) {
            return gicr_addr;
        }

        if (typer & (1ULL << 4)) {
            break;
        }
    }

    uint64_t fallback = gicr_base_virt + current_cpu_id * GICR_STRIDE;
    printk("GICv3: fallback MPIDR=0x%llx affinity=0x%x uses GICR=0x%llx\n",
           current_mpidr(), affinity, fallback);
    return fallback;
}

gic_version_t gic_detect_version(void) {
    struct uacpi_table madt_table;
    uacpi_status status = uacpi_table_find_by_signature("APIC", &madt_table);

    if (status != UACPI_STATUS_OK) {
        return GIC_VERSION_UNKNOWN;
    }

    struct acpi_madt *madt = (struct acpi_madt *)madt_table.ptr;
    gic_version_t version = GIC_VERSION_UNKNOWN;
    bool has_gicr = false;

    uint64_t current = 0;
    while (current + sizeof(struct acpi_madt) < madt->hdr.length) {
        struct acpi_entry_hdr *header =
            (struct acpi_entry_hdr *)((uint64_t)(&madt->entries) + current);

        switch (header->type) {
        case ACPI_MADT_ENTRY_TYPE_GICD: {
            struct acpi_madt_gicd *gicd = (struct acpi_madt_gicd *)header;
            version = gicd->gic_version;
            break;
        }
        case ACPI_MADT_ENTRY_TYPE_GICR:
            has_gicr = true;
            break;
        }

        current += header->length;
    }

    // 如果有GICR但版本未知，判断为v3
    if (has_gicr && version < GIC_VERSION_V3) {
        version = GIC_VERSION_V3;
    }

    return version;
}

static void gic_parse_acpi(void) {
    struct uacpi_table madt_table;
    uacpi_status status = uacpi_table_find_by_signature("APIC", &madt_table);

    if (status != UACPI_STATUS_OK) {
        return;
    }

    struct acpi_madt *madt = (struct acpi_madt *)madt_table.ptr;
    uint64_t current = 0;

    // 解析GICD
    while (current + sizeof(struct acpi_madt) - 1 < madt->hdr.length) {
        struct acpi_entry_hdr *header =
            (struct acpi_entry_hdr *)((uint64_t)(&madt->entries) + current);

        if (header->type == ACPI_MADT_ENTRY_TYPE_GICD) {
            struct acpi_madt_gicd *gicd = (struct acpi_madt_gicd *)header;
            gicd_base_address = gicd->address;
            break;
        }
        current += header->length;
    }

    // 解析GICC (GICv2) 或 GICR (GICv3)
    current = 0;
    while (current + sizeof(struct acpi_madt) < madt->hdr.length) {
        struct acpi_entry_hdr *header =
            (struct acpi_entry_hdr *)((uint64_t)(&madt->entries) + current);

        if (gic_version == GIC_VERSION_V2) {
            if (header->type == ACPI_MADT_ENTRY_TYPE_GICC) {
                struct acpi_madt_gicc *gicc = (struct acpi_madt_gicc *)header;
                if (gicc_base_address == 0) {
                    gicc_base_address = gicc->address;
                }
            }
        } else if (gic_version >= GIC_VERSION_V3) {
            if (header->type == ACPI_MADT_ENTRY_TYPE_GICR) {
                struct acpi_madt_gicr *gicr = (struct acpi_madt_gicr *)header;
                gicr_base_address = gicr->address;
                break;
            }
        }

        current += header->length;
    }

    // 映射内存
    if (gicd_base_address) {
        gicd_base_virt = (uint64_t)phys_to_virt(gicd_base_address);
        map_page_range(get_current_page_dir(false), gicd_base_virt,
                       gicd_base_address, 0x10000,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);
    }

    if (gic_version == GIC_VERSION_V2 && gicc_base_address) {
        gicc_base_virt = (uint64_t)phys_to_virt(gicc_base_address);
        map_page_range(get_current_page_dir(false), gicc_base_virt,
                       gicc_base_address, 0x2000,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);
    }

    if (gic_version >= GIC_VERSION_V3 && gicr_base_address) {
        gicr_base_virt = (uint64_t)phys_to_virt(gicr_base_address);
        gicr_region_size = GICR_STRIDE * cpu_count;
        map_page_range(get_current_page_dir(false), gicr_base_virt,
                       gicr_base_address, gicr_region_size,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);
    }
}

static uint64_t fdt_read_cells(const uint32_t **p, int cells) {
    uint64_t value = 0;

    if (cells == 1) {
        value = fdt32_to_cpu(**p);
        (*p)++;
    } else if (cells == 2) {
        uint64_t high = fdt32_to_cpu((*p)[0]);
        uint64_t low = fdt32_to_cpu((*p)[1]);
        value = (high << 32) | low;
        (*p) += 2;
    }

    return value;
}

static uint64_t fdt_translate_address(void *fdt, int node_offset,
                                      uint64_t addr) {
    int parent = fdt_parent_offset(fdt, node_offset);

    printk("Translating address 0x%llx for node %d\n", addr, node_offset);

    while (parent >= 0) {
        int len;
        const uint32_t *ranges = fdt_getprop(fdt, parent, "ranges", &len);

        if (!ranges) {
            // 如果没有 ranges 属性，说明这个总线不进行地址转换
            // 继续向上查找
            int grandparent = fdt_parent_offset(fdt, parent);
            if (grandparent < 0) {
                break; // 到达根节点
            }
            parent = grandparent;
            continue;
        }

        // 空的 ranges 表示 1:1 映射
        if (len == 0) {
            printk("  1:1 mapping at parent %d\n", parent);
            parent = fdt_parent_offset(fdt, parent);
            continue;
        }

        // 获取 cells 信息
        int child_addr_cells = fdt_address_cells(fdt, parent);
        int parent_parent = fdt_parent_offset(fdt, parent);
        int parent_addr_cells =
            (parent_parent >= 0) ? fdt_address_cells(fdt, parent_parent) : 2;
        int size_cells = fdt_size_cells(fdt, parent);

        printk("  Checking ranges at parent %d:\n", parent);
        printk("    child_addr_cells=%d, parent_addr_cells=%d, size_cells=%d\n",
               child_addr_cells, parent_addr_cells, size_cells);

        // 遍历所有 ranges 条目
        const uint32_t *p = ranges;
        int cells_per_entry = child_addr_cells + parent_addr_cells + size_cells;
        int num_entries = (len / sizeof(uint32_t)) / cells_per_entry;

        bool found = false;
        for (int i = 0; i < num_entries; i++) {
            uint64_t child_addr = fdt_read_cells(&p, child_addr_cells);
            uint64_t parent_addr = fdt_read_cells(&p, parent_addr_cells);
            uint64_t range_size = fdt_read_cells(&p, size_cells);

            printk(
                "    range[%d]: child=0x%llx -> parent=0x%llx (size=0x%llx)\n",
                i, child_addr, parent_addr, range_size);

            // 检查地址是否在这个范围内
            if (addr >= child_addr && addr < child_addr + range_size) {
                uint64_t offset = addr - child_addr;
                addr = parent_addr + offset;
                printk("    MATCH! Translated to 0x%llx\n", addr);
                found = true;
                break;
            }
        }

        if (!found) {
            printk("    No matching range found!\n");
        }

        parent = parent_parent;
    }

    printk("Final translated address: 0x%llx\n", addr);
    return addr;
}

/**
 * 获取 reg 并进行地址转换
 */
static int fdt_get_reg(void *fdt, int node_offset, int index, uint64_t *addr,
                       uint64_t *size) {
    int len;
    const uint32_t *reg = fdt_getprop(fdt, node_offset, "reg", &len);

    if (!reg || len <= 0) {
        return -1;
    }

    int parent = fdt_parent_offset(fdt, node_offset);
    int address_cells = (parent >= 0) ? fdt_address_cells(fdt, parent) : 2;
    int size_cells = (parent >= 0) ? fdt_size_cells(fdt, parent) : 2;

    printk("fdt_get_reg: address_cells=%d, size_cells=%d, len=%d\n",
           address_cells, size_cells, len);

    int cells_per_entry = address_cells + size_cells;
    int total_cells = len / sizeof(uint32_t);
    int total_entries = total_cells / cells_per_entry;

    if (index >= total_entries) {
        return -1;
    }

    const uint32_t *entry = reg + (index * cells_per_entry);

    /* 解析地址 */
    const uint32_t *p = entry;
    *addr = fdt_read_cells(&p, address_cells);
    *size = fdt_read_cells(&p, size_cells);

    printk("fdt_get_reg: bus address=0x%llx, size=0x%llx\n", *addr, *size);

    /* 进行地址转换 */
    *addr = fdt_translate_address(fdt, node_offset, *addr);

    printk("fdt_get_reg: physical address=0x%llx, size=0x%llx\n", *addr, *size);

    return 0;
}

static void gic_parse_dtb() {
    void *fdt = (void *)boot_get_dtb();

    if (fdt) {
        int node;
        int node_offset = -1;

        for (node = fdt_next_node(fdt, -1, NULL); node >= 0;
             node = fdt_next_node(fdt, node, NULL)) {

            const char *compatible = fdt_getprop(fdt, node, "compatible", NULL);
            if (!compatible)
                continue;
            if (strstr(compatible, "gic-400")) {
                gic_version = GIC_VERSION_V2;
                node_offset = node;
                break;
            }
            if (strstr(compatible, "cortex-a15-gic")) {
                gic_version = GIC_VERSION_V2;
                node_offset = node;
                break;
            }
            if (strstr(compatible, "cortex-a9-gic")) {
                gic_version = GIC_VERSION_V2;
                node_offset = node;
                break;
            }
            if (strstr(compatible, "cortex-a7-gic")) {
                gic_version = GIC_VERSION_V2;
                node_offset = node;
                break;
            }
            if (strstr(compatible, "arm,gic-v2")) {
                gic_version = GIC_VERSION_V2;
                node_offset = node;
                break;
            }
            if (strstr(compatible, "arm,gic-v3")) {
                gic_version = GIC_VERSION_V3;
                node_offset = node;
                break;
            }
            if (strstr(compatible, "gic-v3")) {
                gic_version = GIC_VERSION_V3;
                node_offset = node;
                break;
            }
            if (strstr(compatible, "gic-v4")) {
                gic_version = GIC_VERSION_V3;
                node_offset = node;
                break;
            }
        }

        if (node_offset < 0)
            return;

        uint64_t gicd_base_size = 0;
        if (fdt_get_reg(fdt, node_offset, 0, &gicd_base_address,
                        &gicd_base_size) != 0) {
            printk("GIC: Failed to get GICD address\n");
            return;
        }

        uint64_t gicc_base_size = 0;
        uint64_t gicr_base_size = 0;
        if (gic_version == GIC_VERSION_V2) {
            if (fdt_get_reg(fdt, node_offset, 1, &gicc_base_address,
                            &gicc_base_size) != 0) {
                printk("GIC: Failed to get GICC address\n");
                return;
            }
        } else {
            if (fdt_get_reg(fdt, node_offset, 1, &gicr_base_address,
                            &gicr_base_size) != 0) {
                printk("GIC: Failed to get GICR address\n");
                return;
            }
        }

        // 映射内存
        if (gicd_base_address) {
            gicd_base_virt = (uint64_t)phys_to_virt(gicd_base_address);
            map_page_range(get_current_page_dir(false), gicd_base_virt,
                           gicd_base_address, gicd_base_size,
                           PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);
        }

        if (gic_version == GIC_VERSION_V2 && gicc_base_address) {
            gicc_base_virt = (uint64_t)phys_to_virt(gicc_base_address);
            map_page_range(get_current_page_dir(false), gicc_base_virt,
                           gicc_base_address, gicc_base_size,
                           PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);
        }

        if (gic_version >= GIC_VERSION_V3 && gicr_base_address) {
            gicr_base_virt = (uint64_t)phys_to_virt(gicr_base_address);
            gicr_region_size = gicr_base_size;
            map_page_range(get_current_page_dir(false), gicr_base_virt,
                           gicr_base_address, gicr_region_size,
                           PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE);
        }
    }
}

static void gicd_v2_init(void) {
    uint32_t typer, max_irq;

    // 禁用distributor
    *(volatile uint32_t *)(gicd_base_virt + GICD_CTLR) = 0;
    dsb(sy);

    // 读取支持的中断数量
    typer = *(volatile uint32_t *)(gicd_base_virt + GICD_TYPER);
    max_irq = ((typer & 0x1F) + 1) * 32;
    if (max_irq > 1020)
        max_irq = 1020;

    // 配置所有中断为Group0（与GICC_CTLR一致）
    for (int i = 0; i < (max_irq / 32); i++) {
        *(volatile uint32_t *)(gicd_base_virt + GICD_IGROUPR + i * 4) = 0x0;
    }

    // 配置所有中断优先级
    for (int i = 0; i < (max_irq / 4); i++) {
        *(volatile uint32_t *)(gicd_base_virt + GICD_IPRIORITYR + i * 4) =
            0xA0A0A0A0;
    }

    // 配置所有SPI目标CPU（SPI从32开始）
    for (int i = 32 / 4; i < (max_irq / 4); i++) {
        *(volatile uint32_t *)(gicd_base_virt + GICD_ITARGETSR + i * 4) =
            0x01010101;
    }

    // 只禁用SPI，不要禁用PPI（让每个CPU自己管理）
    for (int i = 1; i < (max_irq / 32); i++) { // 从1开始，跳过PPI/SGI
        *(volatile uint32_t *)(gicd_base_virt + GICD_ICENABLER + i * 4) =
            0xFFFFFFFF;
    }

    // 清除所有pending状态
    for (int i = 0; i < (max_irq / 32); i++) {
        *(volatile uint32_t *)(gicd_base_virt + GICD_ICPENDR + i * 4) =
            0xFFFFFFFF;
    }

    // 启用Group0
    *(volatile uint32_t *)(gicd_base_virt + GICD_CTLR) = GICD_CTLR_EN_GRP0;
    dsb(sy);
}

static void gicc_v2_init(void) {
    // 先禁用本CPU的PPI（清理状态）
    *(volatile uint32_t *)(gicd_base_virt + GICD_ICENABLER) = 0xFFFFFFFF;

    // 清除PPI的pending状态
    *(volatile uint32_t *)(gicd_base_virt + GICD_ICPENDR) = 0xFFFFFFFF;

    // 设置优先级掩码
    *(volatile uint32_t *)(gicc_base_virt + GICC_PMR) = 0xF0;

    // 设置Binary Point为0（使用全部8位优先级）
    *(volatile uint32_t *)(gicc_base_virt + GICC_BPR) = 0;

    // 清除任何pending的中断
    uint32_t iar = *(volatile uint32_t *)(gicc_base_virt + GICC_IAR);
    if ((iar & 0x3FF) < 1020) {
        *(volatile uint32_t *)(gicc_base_virt + GICC_EOIR) = iar;
    }

    // Non-secure 视图下 bit0 为 EnableGrp1
    *(volatile uint32_t *)(gicc_base_virt + GICC_CTLR) = 0x1;
    dsb(sy);

    uint32_t local_target =
        *(volatile uint32_t *)(gicd_base_virt + GICD_ITARGETSR) & 0xFF;
    if (!local_target) {
        local_target = 1U << current_cpu_id;
    }

    gic_v2_cpu_sgi_target_mask[current_cpu_id] = (uint8_t)local_target;
}

static void gic_v2_enable_irq(uint32_t irq) {
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;

    // 所有中断都通过GICD使能（GICv2特性）
    *(volatile uint32_t *)(gicd_base_virt + GICD_ISENABLER + reg * 4) =
        (1U << bit);
    dsb(sy);
}

static void gic_v2_disable_irq(uint32_t irq) {
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;

    *(volatile uint32_t *)(gicd_base_virt + GICD_ICENABLER + reg * 4) =
        (1U << bit);
    dsb(sy);
}

static uint64_t gic_v2_get_irq(void) {
    uint32_t iar = *(volatile uint32_t *)(gicc_base_virt + GICC_IAR);
    dsb(sy);

    uint32_t irq = iar & 0x3FF;

    if (current_cpu_id < MAX_CPU_NUM) {
        gic_v2_active_iar[current_cpu_id] = iar;
    }

    if (irq >= 1020) {
        if (current_cpu_id < MAX_CPU_NUM) {
            gic_v2_active_iar[current_cpu_id] = 0xFFFFFFFF;
        }
        return 1023; // 返回特殊值表示无效中断
    }

    return irq;
}

static void gic_v2_send_eoi(uint32_t irq) {
    if (irq >= 1020) {
        return;
    }

    uint32_t eoir = irq;
    if (current_cpu_id < MAX_CPU_NUM) {
        uint32_t iar = gic_v2_active_iar[current_cpu_id];
        if (iar != 0xFFFFFFFF && (iar & 0x3FF) == irq) {
            eoir = iar;
        }
        gic_v2_active_iar[current_cpu_id] = 0xFFFFFFFF;
    }

    *(volatile uint32_t *)(gicc_base_virt + GICC_EOIR) = eoir;
    dsb(sy);
}

static void gic_v2_send_ipi(uint32_t cpu_id, uint64_t irq_num) {
    if (cpu_id >= cpu_count || cpu_id == current_cpu_id ||
        irq_num >= PPI_INTR_BASE) {
        return;
    }

    uint32_t target_mask = gic_v2_cpu_sgi_target_mask[cpu_id];
    if (!target_mask) {
        if (cpu_id >= 8) {
            printk("GICv2: cannot send SGI %lu to cpu %u without target mask\n",
                   irq_num, cpu_id);
            return;
        }
        target_mask = 1U << cpu_id;
    }

    dsb(ishst);
    *(volatile uint32_t *)(gicd_base_virt + GICD_SGIR) =
        ((target_mask & 0xFF) << 16) | (uint32_t)(irq_num & 0xF);
    dsb(ishst);
}

static void gicd_v3_init(void) {
    uint32_t typer = *(volatile uint32_t *)(gicd_base_virt + GICD_TYPER);
    uint32_t max_irq = ((typer & 0x1F) + 1) * 32;

    if (max_irq > 1020) {
        max_irq = 1020;
    }

    // 禁用GICD
    *(volatile uint32_t *)(gicd_base_virt + GICD_CTLR) = 0;
    dsb(sy);
    gicd_wait_for_rwp();

    for (uint32_t i = 1; i < (max_irq / 32); i++) {
        *(volatile uint32_t *)(gicd_base_virt + GICD_IGROUPR + i * 4) =
            0xFFFFFFFF;
        *(volatile uint32_t *)(gicd_base_virt + GICD_IGRPMODR + i * 4) = 0;
        *(volatile uint32_t *)(gicd_base_virt + GICD_ICENABLER + i * 4) =
            0xFFFFFFFF;
        *(volatile uint32_t *)(gicd_base_virt + GICD_ICPENDR + i * 4) =
            0xFFFFFFFF;
        *(volatile uint32_t *)(gicd_base_virt + GICD_ICACTIVER + i * 4) =
            0xFFFFFFFF;
    }
    gicd_wait_for_rwp();

    // 配置SPI中断路由（Affinity routing）
    for (uint32_t intr = SPI_INTR_BASE; intr < max_irq; intr++) {
        volatile uint64_t *route_reg =
            (uint64_t *)(gicd_base_virt + GICD_IROUTER + intr * 8);
        *route_reg = 0; // 路由到CPU0（可根据需要修改）
    }

    // 设置所有SPI中断优先级
    for (uint32_t i = 8; i < (max_irq / 4); i++) {
        *(volatile uint32_t *)(gicd_base_virt + GICD_IPRIORITYR + i * 4) =
            0xA0A0A0A0;
    }

    // 启用GICD（Affinity Routing + Group1）
    *(volatile uint32_t *)(gicd_base_virt + GICD_CTLR) =
        GICD_CTLR_ARE_NS | GICD_CTLR_EN_GRP1NS;
    dsb(sy);
    gicd_wait_for_rwp();
}

static void gicr_v3_init(void) {
    uint64_t gicr_addr = gicr_v3_cpu_base();

    // 唤醒Redistributor
    volatile uint32_t *waker = (uint32_t *)(gicr_addr + GICR_WAKER);
    *waker &= ~(1 << 1);
    while (*waker & (1 << 2)) {
        asm volatile("nop");
    }

    // 禁用所有PPI/SGI
    *(volatile uint32_t *)(gicr_addr + GICR_ICENABLER0) = 0xFFFFFFFF;

    // 清除pending状态
    *(volatile uint32_t *)(gicr_addr + GICR_ICPENDR0) = 0xFFFFFFFF;

    // 清除active状态，避免继承到旧的虚拟CPU状态
    *(volatile uint32_t *)(gicr_addr + GICR_ICACTIVER0) = 0xFFFFFFFF;

    // 配置PPI/SGI中断组为Group1 NS
    *(volatile uint32_t *)(gicr_addr + GICR_IGROUPR0) = 0xFFFFFFFF;
    *(volatile uint32_t *)(gicr_addr + GICR_IGRPMODR0) = 0;

    // PPI 默认使用电平触发，architected timer 依赖这个行为
    *(volatile uint32_t *)(gicr_addr + GICR_ICFGR1) = 0;

    // 设置PPI优先级
    for (int i = 0; i < 8; i++) {
        *(volatile uint32_t *)(gicr_addr + GICR_IPRIORITYR + i * 4) =
            0xA0A0A0A0;
    }

    dsb(sy);
}

static void cpu_interface_v3_init(void) {
    uint64_t sre = 0;

    // GICv3 的 CPU interface 通过 ICC_* system registers 访问；从 EL2
    // 跳到 EL1 后，需要显式打开 SRE，否则在 KVM 下这些寄存器写入不会生效。
    asm volatile("mrs %0, ICC_SRE_EL1" : "=r"(sre));
    sre |= ICC_SRE_SRE | ICC_SRE_DFB | ICC_SRE_DIB;
    asm volatile("msr ICC_SRE_EL1, %0" : : "r"(sre));
    isb();

    asm volatile("msr ICC_BPR1_EL1, %0" : : "r"((uint64_t)0));

    // 设置优先级掩码
    asm volatile("msr ICC_PMR_EL1, %0" : : "r"((uint64_t)0xFF));

    // 启用Group1中断
    asm volatile("msr ICC_IGRPEN1_EL1, %0" : : "r"((uint64_t)1));
    isb();
}

static void gic_v3_enable_irq(uint32_t irq) {
    if (irq < 32) {
        // PPI/SGI
        uint64_t reg = gicr_v3_cpu_base() + GICR_ISENABLER0;
        *(volatile uint32_t *)reg = (1U << irq);
    } else {
        // SPI
        uint32_t reg_idx = irq / 32;
        uint32_t bit = irq % 32;
        *(volatile uint32_t *)(gicd_base_virt + GICD_ISENABLER + reg_idx * 4) =
            (1U << bit);
    }
    dsb(sy);
}

static void gic_v3_disable_irq(uint32_t irq) {
    if (irq < 32) {
        uint64_t reg = gicr_v3_cpu_base() + GICR_ICENABLER0;
        *(volatile uint32_t *)reg = (1U << irq);
    } else {
        uint32_t reg_idx = irq / 32;
        uint32_t bit = irq % 32;
        *(volatile uint32_t *)(gicd_base_virt + GICD_ICENABLER + reg_idx * 4) =
            (1U << bit);
    }
    dsb(sy);
}

static uint64_t gic_v3_get_irq(void) {
    uint64_t irq_num = 0;
    asm volatile("mrs %0, ICC_IAR1_EL1" : "=r"(irq_num));
    return irq_num & 0xFFFFFF;
}

static void gic_v3_send_eoi(uint32_t irq) {
    asm volatile("msr ICC_EOIR1_EL1, %0" : : "r"((uint64_t)irq));
    asm volatile("msr ICC_DIR_EL1, %0" : : "r"((uint64_t)irq));
    isb();
}

static void gic_v3_send_ipi(uint32_t cpu_id, uint64_t irq_num) {
    if (cpu_id >= cpu_count || cpu_id == current_cpu_id ||
        irq_num >= PPI_INTR_BASE) {
        return;
    }

    uint64_t mpidr = cpuid_to_mpidr[cpu_id];
    uint64_t aff0 = gic_mpidr_aff0(mpidr);

    if (aff0 >= 16) {
        printk("GICv3: cannot send SGI %lu to cpu %u with aff0=%lu\n", irq_num,
               cpu_id, aff0);
        return;
    }

    uint64_t sgi1r = ((uint64_t)gic_mpidr_aff3(mpidr) << 48) |
                     ((uint64_t)gic_mpidr_aff2(mpidr) << 32) |
                     ((uint64_t)(irq_num & 0xF) << 24) |
                     ((uint64_t)gic_mpidr_aff1(mpidr) << 16) | (1ULL << aff0);

    dsb(ishst);
    asm volatile("msr ICC_SGI1R_EL1, %0" : : "r"(sgi1r) : "memory");
    isb();
}

void gic_configure_irq(uint32_t irq, uint32_t flags) {
    bool edge_triggered = (flags & GIC_IRQ_FLAG_MODE_EDGE) != 0;

    // SGI 固定为边沿触发，不需要软件配置。
    if (irq < PPI_INTR_BASE) {
        return;
    }

    if (gic_version == GIC_VERSION_V2) {
        gic_configure_icfgr(gicd_base_virt, GICD_ICFGR, irq, edge_triggered);
        return;
    }

    if (irq < SPI_INTR_BASE) {
        uint64_t gicr_addr = gicr_v3_cpu_base();
        if (!gicr_addr) {
            return;
        }

        gic_configure_icfgr(gicr_addr, GICR_ICFGR0, irq, edge_triggered);
    } else {
        gic_configure_icfgr(gicd_base_virt, GICD_ICFGR, irq, edge_triggered);
    }
}

static void gic_send_ipi(uint32_t cpu_id, uint64_t irq_num) {
    if (gic_version == GIC_VERSION_V2) {
        gic_v2_send_ipi(cpu_id, irq_num);
    } else {
        gic_v3_send_ipi(cpu_id, irq_num);
    }
}

static void gic_resched_ipi_handler(uint64_t irq_num, void *data,
                                    struct pt_regs *regs) {
    (void)irq_num;
    (void)data;
    (void)regs;
}

void gic_init(void) {
    gic_parse_dtb();

    if (gic_version == GIC_VERSION_UNKNOWN) {
        // 检测版本
        gic_version = gic_detect_version();

        if (gic_version == GIC_VERSION_UNKNOWN) {
            // 默认尝试GICv2
            gic_version = GIC_VERSION_V2;
        }

        printk("Detected GIC version: %s\n",
               gic_version == GIC_VERSION_V2 ? "GICv2" : "GICv3");

        // 解析ACPI
        gic_parse_acpi();
    }

    if (gicd_base_virt) {
        uint32_t gicd_typer =
            *(volatile uint32_t *)(gicd_base_virt + GICD_TYPER);
        printk("GICD_TYPER = 0x%x\n", gicd_typer);

        if (gicd_typer == 0 || gicd_typer == 0xffffffff) {
            printk("ERROR: GICD address invalid! Cannot read GICD_TYPER\n");
            printk("  This means the physical address 0x%llx is wrong\n",
                   gicd_base_address);
            return;
        }

        uint32_t max_irq = ((gicd_typer & 0x1f) + 1) * 32;
        printk("GIC supports %d interrupts\n", max_irq);
    }

    // 根据版本初始化
    if (gic_version == GIC_VERSION_V2) {
        printk("GICC base: phys=0x%llx virt=0x%llx\n", gicc_base_address,
               gicc_base_virt);
        gicd_v2_init();
        gicc_v2_init();
    } else {
        printk("GICR base: phys=0x%llx virt=0x%llx\n", gicr_base_address,
               gicr_base_virt);
        gicd_v3_init();
        gicr_v3_init();
        cpu_interface_v3_init();
    }
}

void gic_init_percpu(void) {
    if (gic_version == GIC_VERSION_V2) {
        gicc_v2_init();
    } else {
        gicr_v3_init();
        cpu_interface_v3_init();
    }

    if (gic_ipi_initialized) {
        gic_enable_irq(GIC_RESCHED_SGI);
    }
}

void gic_enable_irq(uint32_t irq) {
    if (gic_version == GIC_VERSION_V2) {
        gic_v2_enable_irq(irq);
    } else {
        gic_v3_enable_irq(irq);
    }
}

void gic_disable_irq(uint32_t irq) {
    if (gic_version == GIC_VERSION_V2) {
        gic_v2_disable_irq(irq);
    } else {
        gic_v3_disable_irq(irq);
    }
}

uint64_t gic_get_current_irq(void) {
    if (gic_version == GIC_VERSION_V2) {
        return gic_v2_get_irq();
    } else {
        return gic_v3_get_irq();
    }
}

void gic_send_eoi(uint32_t irq) {
    if (gic_version == GIC_VERSION_V2) {
        gic_v2_send_eoi(irq);
    } else {
        gic_v3_send_eoi(irq);
    }
}

int64_t gic_unmask(uint64_t irq, uint64_t flags) {
    gic_enable_irq(irq);
    return 0;
}

int64_t gic_mask(uint64_t irq, uint64_t flags) {
    gic_disable_irq(irq);
    return 0;
}

int64_t gic_ack(uint64_t irq) {
    gic_send_eoi(irq);
    return 0;
}

int64_t gic_install(uint64_t irq, uint64_t arg, uint64_t flags) {
    (void)arg;
    gic_configure_irq((uint32_t)irq, (uint32_t)flags);
    return 0;
}

irq_controller_t gic_controller = {
    .unmask = gic_unmask,
    .mask = gic_mask,
    .install = gic_install,
    .ack = gic_ack,
};

void gic_ipi_init(void) {
    for (uint32_t cpu = 0; cpu < MAX_CPU_NUM; cpu++) {
        gic_v2_active_iar[cpu] = 0xFFFFFFFF;
    }

    irq_regist_ipi(GIC_RESCHED_SGI, gic_resched_ipi_handler, 0, NULL,
                   &gic_controller, "RESCHED_IPI", 0, gic_send_ipi);
    irq_set_sched_ipi(GIC_RESCHED_SGI);
    gic_ipi_initialized = true;
}

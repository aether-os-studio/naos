#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>
#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <mm/mm.h>

struct acpi_madt_gicc *giccs[MAX_CPU_NUM] = {0};
uint64_t gicc_base_virts[MAX_CPU_NUM] = {0};
uint64_t gicd_base_virt = 0;
uint64_t gicd_base_address = 0;
uint64_t gicr_base_virt = 0;
uint64_t gicr_base_address = 0;
gic_version_t gic_version = GIC_VERSION_UNKNOWN;

// 内存屏障
#define dsb(op) asm volatile("dsb " #op : : : "memory")
#define isb() asm volatile("isb" : : : "memory")
#define dmb(op) asm volatile("dmb " #op : : : "memory")

/* ==================== 版本检测 ==================== */

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
    while (current + sizeof(struct acpi_madt) - 1 < madt->hdr.length) {
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
    while (current + sizeof(struct acpi_madt) - 1 < madt->hdr.length) {
        struct acpi_entry_hdr *header =
            (struct acpi_entry_hdr *)((uint64_t)(&madt->entries) + current);

        if (gic_version == GIC_VERSION_V2) {
            if (header->type == ACPI_MADT_ENTRY_TYPE_GICC) {
                struct acpi_madt_gicc *gicc = (struct acpi_madt_gicc *)header;
                uint64_t cpuid = get_cpuid_by_mpidr(gicc->mpidr);
                giccs[cpuid] = gicc;
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
        gicd_base_virt = phys_to_virt(gicd_base_address);
        map_page_range(get_current_page_dir(false), gicd_base_virt,
                       gicd_base_address, 0x10000, PT_FLAG_R | PT_FLAG_W);
    }

    if (gic_version == GIC_VERSION_V2) {
        for (uint64_t cpu = 0; cpu < cpu_count; cpu++) {
            uint64_t gicc_base_virt = phys_to_virt(giccs[cpu]->address);
            map_page_range(get_current_page_dir(false), gicc_base_virt,
                           giccs[cpu]->address, DEFAULT_PAGE_SIZE,
                           PT_FLAG_R | PT_FLAG_W);
            gicc_base_virts[cpu] = gicc_base_virt;
        }
    }

    if (gic_version >= GIC_VERSION_V3 && gicr_base_address) {
        gicr_base_virt = phys_to_virt(gicr_base_address);
        map_page_range(get_current_page_dir(false), gicr_base_virt,
                       gicr_base_address, GICR_STRIDE * cpu_count,
                       PT_FLAG_R | PT_FLAG_W);
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
    uint64_t gicc_base = gicc_base_virts[current_cpu_id];

    // 1. 先禁用CPU接口
    *(volatile uint32_t *)(gicc_base + GICC_CTLR) = 0;
    dsb(sy);

    // 2. 清除PPI的pending状态（只清除PPI部分，保留SGI）
    //    对于GICv2，每个CPU访问GICD_ICPENDR[0]会操作自己的banked寄存器
    *(volatile uint32_t *)(gicd_base_virt + GICD_ICPENDR) = 0xFFFF0000;
    dsb(sy);

    // 3. 设置优先级掩码（0xFF = 最低优先级，允许所有中断）
    *(volatile uint32_t *)(gicc_base + GICC_PMR) = 0xFF;
    dsb(sy);

    // 4. 设置Binary Point为0（不分组抢占）
    *(volatile uint32_t *)(gicc_base + GICC_BPR) = 0;
    dsb(sy);

    // 5. 启用CPU接口（Group0）
    *(volatile uint32_t *)(gicc_base + GICC_CTLR) = 0x1;
    dsb(sy);
}

static void gic_v2_enable_irq(uint32_t irq) {
    uint32_t reg = irq / 32;
    uint32_t bit = irq % 32;

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
    uint32_t iar =
        *(volatile uint32_t *)(gicc_base_virts[current_cpu_id] + GICC_IAR);
    dsb(sy);

    uint32_t irq = iar & 0x3FF;

    if (irq >= 1020) {
        return 1023; // 返回特殊值表示无效中断
    }

    return irq;
}

static void gic_v2_send_eoi(uint32_t irq) {
    if (irq >= 1020) {
        return;
    }

    *(volatile uint32_t *)(gicc_base_virts[current_cpu_id] + GICC_EOIR) = irq;
    dsb(sy);
}

static void gicd_v3_init(void) {
    // 禁用GICD
    *(volatile uint32_t *)(gicd_base_virt + GICD_CTLR) = 0;
    dsb(sy);

    // 配置SPI中断路由（Affinity routing）
    for (int intr = SPI_INTR_BASE; intr < 1020; intr++) {
        volatile uint64_t *route_reg =
            (uint64_t *)(gicd_base_virt + GICD_IROUTER + intr * 8);
        *route_reg = 0; // 路由到CPU0（可根据需要修改）
    }

    // 设置所有SPI中断优先级
    for (int i = 8; i < 256; i++) {
        *(volatile uint32_t *)(gicd_base_virt + GICD_IPRIORITYR + i * 4) =
            0xA0A0A0A0;
    }

    // 启用GICD（Affinity Routing + Group1）
    *(volatile uint32_t *)(gicd_base_virt + GICD_CTLR) =
        GICD_CTLR_ARE | GICD_CTLR_EN_GRP1NS | GICD_CTLR_DS;
    dsb(sy);
}

static void gicr_v3_init(uint32_t cpu_id) {
    uint64_t gicr_addr = gicr_base_virt + cpu_id * GICR_STRIDE;

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

    // 配置PPI/SGI中断组为Group1 NS
    *(volatile uint32_t *)(gicr_addr + GICR_IGROUPR0) = 0xFFFFFFFF;

    // 设置PPI优先级
    for (int i = 0; i < 8; i++) {
        *(volatile uint32_t *)(gicr_addr + GICR_IPRIORITYR + i * 4) =
            0xA0A0A0A0;
    }
}

static void cpu_interface_v3_init(void) {
    // 设置优先级掩码
    asm volatile("msr ICC_PMR_EL1, %0" : : "r"((uint64_t)0xF0));

    // 启用Group1中断
    asm volatile("msr ICC_IGRPEN1_EL1, %0" : : "r"((uint64_t)1));
    isb();
}

static void gic_v3_enable_irq(uint32_t irq) {
    if (irq < 32) {
        // PPI/SGI
        uint64_t reg =
            gicr_base_virt + current_cpu_id * GICR_STRIDE + GICR_ISENABLER0;
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
        uint64_t reg =
            gicr_base_virt + current_cpu_id * GICR_STRIDE + GICR_ICENABLER0;
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
    isb();
}

void gic_init(void) {
    // 检测版本
    gic_version = gic_detect_version();

    if (gic_version == GIC_VERSION_UNKNOWN) {
        // 默认尝试GICv2
        gic_version = GIC_VERSION_V2;
    }

    // 解析ACPI
    gic_parse_acpi();

    // 根据版本初始化
    if (gic_version == GIC_VERSION_V2) {
        gicd_v2_init();
        gicc_v2_init();
    } else {
        gicd_v3_init();
        gicr_v3_init(current_cpu_id);
        cpu_interface_v3_init();
    }
}

void gic_init_percpu(void) {
    if (gic_version == GIC_VERSION_V2) {
        gicc_v2_init();
    } else {
        gicr_v3_init(current_cpu_id);
        cpu_interface_v3_init();
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

irq_controller_t gic_controller = {
    .unmask = gic_unmask,
    .mask = gic_mask,
    .ack = gic_ack,
};

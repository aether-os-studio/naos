#include <arch/arch.h>
#include <boot/boot.h>
#include <libs/aether/fdt.h>
#include <drivers/bus/pci.h>

static inline void mmio_write8(uint64_t addr, uint8_t data) {
    *(volatile uint8_t *)addr = data;
}

static inline uint8_t mmio_read8(uint64_t addr) {
    return *(volatile uint8_t *)addr;
}

static inline void mmio_write16(uint64_t addr, uint16_t data) {
    *(volatile uint16_t *)addr = data;
}

static inline uint16_t mmio_read16(uint64_t addr) {
    return *(volatile uint16_t *)addr;
}

static inline void mmio_write32(uint64_t addr, uint32_t data) {
    *(volatile uint32_t *)addr = data;
}

static inline uint32_t mmio_read32(uint64_t addr) {
    return *(volatile uint32_t *)addr;
}

pcie_brcmstb_config_t brcmstb_pcie = {0};

static int fdt_get_reg_index_by_name(void *fdt, int node_offset,
                                     const char *name) {
    int len;
    const char *reg_names = fdt_getprop(fdt, node_offset, "reg-names", &len);

    if (!reg_names || len <= 0) {
        return -1; // 没有 reg-names，使用默认索引
    }

    int index = 0;
    const char *p = reg_names;

    while (p < reg_names + len) {
        if (strcmp(p, name) == 0) {
            return index;
        }
        p += strlen(p) + 1;
        index++;
    }

    return -1;
}

/**
 * 读取多 cell 的地址/大小值
 */
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

/**
 * 通过 ranges 转换地址
 */
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

pcie_brcmstb_context_t brcmstb_pcie_context = {0};

static void delay(uint64_t ns) {
    uint64_t start = nanoTime();
    while (nanoTime() - start < ns) {
        asm volatile("nop");
    }
}

static void delay_us(uint64_t us) { delay(us * 1000ULL); }

/**
 * 编码 BAR 大小
 */
static uint32_t rc_bar_encode_size(uint64_t size) {
    if (size == 0)
        return 0;

    int n = 63 - __builtin_clzll(size);

    if (n >= 12 && n <= 15)
        return (n - 12) + 0x1c;
    else if (n >= 16 && n <= 35)
        return n - 15;

    return 0;
}

/**
 * MDIO 读取
 */
static uint32_t mdio_read(uint64_t base, uint8_t port, uint8_t reg) {
    uint32_t cmd = (1 << MDIO_PKT_CMD_SHIFT) | (port << MDIO_PKT_PORT_SHIFT) |
                   (reg << MDIO_PKT_REG_SHIFT);

    mmio_write32(base + PCIE_RC_DL_MDIO_ADDR, cmd);
    mmio_read32(base + PCIE_RC_DL_MDIO_ADDR); // Flush

    for (int i = 0; i < 10; i++) {
        uint32_t data = mmio_read32(base + PCIE_RC_DL_MDIO_RD_DATA);
        if (data & MDIO_DATA_DONE) {
            return data & MDIO_DATA_MASK;
        }
        delay_us(10000); // 10ms
    }

    printk("PCIe: MDIO read timeout\n");
    return 0;
}

/**
 * MDIO 写入
 */
static void mdio_write(uint64_t base, uint8_t port, uint8_t reg, uint16_t val) {
    uint32_t cmd = (0 << MDIO_PKT_CMD_SHIFT) | (port << MDIO_PKT_PORT_SHIFT) |
                   (reg << MDIO_PKT_REG_SHIFT);

    mmio_write32(base + PCIE_RC_DL_MDIO_ADDR, cmd);
    mmio_read32(base + PCIE_RC_DL_MDIO_ADDR); // Flush

    mmio_write32(base + PCIE_RC_DL_MDIO_WR_DATA, MDIO_DATA_DONE | val);

    for (int i = 0; i < 10; i++) {
        uint32_t data = mmio_read32(base + PCIE_RC_DL_MDIO_WR_DATA);
        if (!(data & MDIO_DATA_DONE)) {
            return;
        }
        delay_us(10000); // 10ms
    }

    printk("PCIe: MDIO write timeout\n");
}

/**
 * 启用 SSC (Spread Spectrum Clocking)
 */
static void enable_ssc(uint64_t base) {
    printk("PCIe: Enabling SSC\n");

    mdio_write(base, 0, 0x1f, 0x1100);

    uint32_t ctl = mdio_read(base, 0, 0x0002);
    ctl |= 0x8000; // Enable SSC
    ctl |= 0x4000; // Enable down-spreading
    mdio_write(base, 0, 0x0002, ctl);

    delay_us(2000); // 2ms

    uint32_t status = mdio_read(base, 0, 0x0001);
    if ((status & 0x400) && (status & 0x800)) {
        printk("PCIe: SSC enabled successfully\n");
    } else {
        printk("PCIe: SSC enable check failed (status=0x%x)\n", status);
    }
}

/**
 * 配置 outbound window
 */
static void set_outbound_window(uint64_t base, int n, uint64_t cpu_addr,
                                uint64_t pcie_addr, uint64_t size) {
    printk("PCIe: Setting outbound window %d: CPU 0x%llx -> PCIe 0x%llx (size "
           "0x%llx)\n",
           n, cpu_addr, pcie_addr, size);

    /* 设置 PCIe 侧地址 */
    mmio_write32(base + PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LO + n * 8,
                 (uint32_t)pcie_addr);
    mmio_write32(base + PCIE_MISC_CPU_2_PCIE_MEM_WIN0_HI + n * 8,
                 (uint32_t)(pcie_addr >> 32));

    /* 设置 CPU 侧地址范围 */
    uint64_t base_mb = cpu_addr / 0x100000;
    uint64_t limit_mb = (cpu_addr + size - 1) / 0x100000;

    uint32_t base_limit = ((limit_mb & 0xfff) << 20) | ((base_mb & 0xfff) << 4);
    mmio_write32(base + PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_LIMIT + n * 4,
                 base_limit);

    /* 设置高位 */
    mmio_write32(base + PCIE_MISC_CPU_2_PCIE_MEM_WIN0_BASE_HI + n * 8,
                 (base_mb >> 12) & 0xff);
    mmio_write32(base + PCIE_MISC_CPU_2_PCIE_MEM_WIN0_LIMIT_HI + n * 8,
                 (limit_mb >> 12) & 0xff);
}

/**
 * 软复位
 */
static void brcmstb_pcie_reset(uint64_t base) {
    printk("PCIe: Performing software reset\n");

    /* Assert reset */
    uint32_t val = mmio_read32(base + PCIE_RGR1_SW_INIT_1);
    val |= PCIE_RGR1_SW_INIT_1_INIT;
    mmio_write32(base + PCIE_RGR1_SW_INIT_1, val);

    delay_us(200); // 200us

    /* De-assert reset */
    val &= ~PCIE_RGR1_SW_INIT_1_INIT;
    mmio_write32(base + PCIE_RGR1_SW_INIT_1, val);

    delay_us(200); // 200us

    /* Disable SERDES IDDQ */
    val = mmio_read32(base + PCIE_MISC_HARD_PCIE_HARD_DEBUG);
    val &= ~PCIE_HARD_DEBUG_SERDES_IDDQ;
    mmio_write32(base + PCIE_MISC_HARD_PCIE_HARD_DEBUG, val);

    delay_us(100); // 100us
}

/**
 * 使能控制器
 */
static void brcmstb_pcie_enable(uint64_t base) {
    printk("PCIe: Enabling controller\n");

    /* De-assert PERST# */
    uint32_t val = mmio_read32(base + PCIE_MISC_PCIE_CTRL);
    val |= PCIE_MISC_PCIE_CTRL_PCIE_PERSTB;
    mmio_write32(base + PCIE_MISC_PCIE_CTRL, val);

    delay_us(100); // 100us (PCIe spec 要求 100ms，但这里先用 100us)
}

/**
 * 检查链路状态
 */
static bool brcmstb_pcie_link_up(uint64_t base) {
    uint32_t status = mmio_read32(base + PCIE_MISC_PCIE_STATUS);

    return (status & PCIE_MISC_PCIE_STATUS_PCIE_PHYLINKUP) &&
           (status & PCIE_MISC_PCIE_STATUS_PCIE_DL_ACTIVE);
}

static int pcie_parse_ranges(void *fdt, int node, pcie_range_t *ranges,
                             int max_ranges) {
    int len;
    const uint32_t *prop = fdt_getprop(fdt, node, "ranges", &len);
    if (!prop || len <= 0) {
        printk("PCIe: No ranges property found\n");
        return 0;
    }

    int parent = fdt_parent_offset(fdt, node);
    int na = 3;                               // PCI address cells 固定为3
    int pna = fdt_address_cells(fdt, parent); // Parent address cells
    int ns = fdt_size_cells(fdt, node);

    printk("PCIe: Parsing ranges (na=%d, pna=%d, ns=%d, len=%d)\n", na, pna, ns,
           len);

    const uint32_t *p = prop;
    const uint32_t *end = prop + (len / sizeof(uint32_t));
    int count = 0;

    while (p < end && count < max_ranges) {
        // Read PCI address (3 cells: flags, addr_high, addr_low)
        uint32_t flags = fdt32_to_cpu(*p++);
        uint32_t pci_addr_hi = fdt32_to_cpu(*p++);
        uint32_t pci_addr_lo = fdt32_to_cpu(*p++);
        uint64_t pci_addr = ((uint64_t)pci_addr_hi << 32) | pci_addr_lo;

        // Read CPU address
        uint64_t cpu_addr = fdt_read_cells(&p, pna);

        // Read size
        uint64_t size = fdt_read_cells(&p, ns);

        // Decode space code
        uint32_t space_code = (flags >> 24) & 0x03;
        bool prefetchable = (flags >> 30) & 0x01;

        const char *type_str;
        switch (space_code) {
        case 0x00:
            type_str = "Config";
            break;
        case 0x01:
            type_str = "I/O";
            break;
        case 0x02:
            type_str = "MEM32";
            break;
        case 0x03:
            type_str = "MEM64";
            break;
        default:
            type_str = "Unknown";
            break;
        }

        ranges[count].flags = flags;
        ranges[count].pci_addr = pci_addr;
        ranges[count].cpu_addr = cpu_addr;
        ranges[count].size = size;

        printk("  Range[%d]: %s%s PCI 0x%llx -> CPU 0x%llx (size 0x%llx)\n",
               count, type_str, prefetchable ? "-Pref" : "", pci_addr, cpu_addr,
               size);

        count++;
    }

    return count;
}

int pcie_brcmstb_init(uint64_t base_virt, uint64_t base_phys, uint64_t size) {
    uint32_t val;

    printk("PCIe BRCMSTB: Base: phys=0x%llx virt=0x%llx size=0x%llx\n",
           base_phys, base_virt, size);

    brcmstb_pcie_context.pcie_base_phys = base_phys;
    brcmstb_pcie_context.pcie_base_virt = base_virt;
    brcmstb_pcie_context.pcie_size = size;

    /* 复位 */
    brcmstb_pcie_reset(base_virt);

    /* 读取版本 */
    uint32_t revision = mmio_read32(base_virt + PCIE_MISC_REVISION) & 0xFFFF;
    printk("PCIe: Hardware revision = 0x%04x\n", revision);

    if (revision == 0 || revision == 0xffff) {
        printk("PCIe: ERROR - Cannot read revision register\n");
        printk(
            "  Firmware may not have enabled PCIe (missing dtparam=pciex1)\n");
        return -1;
    }

    /* 配置 MISC_CTRL */
    val = mmio_read32(base_virt + PCIE_MISC_MISC_CTRL);
    val |= PCIE_MISC_MISC_CTRL_SCB_ACCESS_EN;
    val |= PCIE_MISC_MISC_CTRL_CFG_READ_UR_MODE;
    val |= PCIE_MISC_MISC_CTRL_BURST_ALIGN;
    val &= ~(0x3 << PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_SHIFT);
    val |= (PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_128
            << PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_SHIFT);
    mmio_write32(base_virt + PCIE_MISC_MISC_CTRL, val);

    /* 配置 RC BAR2 (用于 inbound DMA) */
    uint64_t rc_bar_size = 0x200000000ULL; // 8 GB (从 DT 读取)
    mmio_write32(base_virt + PCIE_MISC_RC_BAR2_CONFIG_LO,
                 rc_bar_encode_size(rc_bar_size));
    mmio_write32(base_virt + PCIE_MISC_RC_BAR2_CONFIG_HI, 0);

    /* 配置 SCB 大小 */
    val = mmio_read32(base_virt + PCIE_MISC_MISC_CTRL);
    val &= ~(0x1f << PCIE_MISC_MISC_CTRL_SCB_SIZE_0_SHIFT);
    val |= ((63 - __builtin_clzll(rc_bar_size) - 15)
            << PCIE_MISC_MISC_CTRL_SCB_SIZE_0_SHIFT);
    mmio_write32(base_virt + PCIE_MISC_MISC_CTRL, val);

    /* 禁用 RC BAR1 和 BAR3 */
    val = mmio_read32(base_virt + PCIE_MISC_RC_BAR1_CONFIG_LO);
    val &= ~PCIE_MISC_RC_BAR_CONFIG_LO_SIZE_MASK;
    mmio_write32(base_virt + PCIE_MISC_RC_BAR1_CONFIG_LO, val);

    val = mmio_read32(base_virt + PCIE_MISC_RC_BAR3_CONFIG_LO);
    val &= ~PCIE_MISC_RC_BAR_CONFIG_LO_SIZE_MASK;
    mmio_write32(base_virt + PCIE_MISC_RC_BAR3_CONFIG_LO, val);

    /* 使能控制器 */
    brcmstb_pcie_enable(base_virt);

    /* 等待链路 */
    printk("PCIe: Waiting for link up...\n");

    int timeout = 100; // 100 * 5ms = 500ms
    bool link_up = false;

    while (timeout-- > 0) {
        if (brcmstb_pcie_link_up(base_virt)) {
            link_up = true;
            break;
        }

        if (timeout % 20 == 0) {
            uint32_t status = mmio_read32(base_virt + PCIE_MISC_PCIE_STATUS);
            printk("  [%d] Status=0x%08x\n", timeout, status);
        }

        delay_us(5000); // 5ms
    }

    if (!link_up) {
        printk("PCIe: Link failed to come up\n");
        return -1;
    }

    printk("PCIe: Link up! (took %d ms)\n", (100 - timeout) * 5);

    /* 检查 RC 模式 */
    val = mmio_read32(base_virt + PCIE_MISC_PCIE_STATUS);
    if (!(val & PCIE_MISC_PCIE_STATUS_RC_MODE)) {
        printk("PCIe: ERROR - Controller is in EP mode!\n");
        return -1;
    }

    /* === 解析 ranges 并配置 outbound windows === */
    void *fdt = (void *)boot_get_dtb();
    int node = brcmstb_pcie_context.fdt_node; // 使用保存的节点

    pcie_range_t ranges[8];
    int range_count = pcie_parse_ranges(fdt, node, ranges, 8);

    if (range_count == 0) {
        printk("PCIe: ERROR - No valid ranges found\n");
        return -1;
    }

    int window_idx = 0;
    for (int i = 0; i < range_count && window_idx < 4; i++) {
        uint32_t space_code = (ranges[i].flags >> 24) & 0x03;

        // 0x01 = I/O space, 0x02 = 32-bit Memory, 0x03 = 64-bit Memory
        if (space_code == 0x02 || space_code == 0x03) {
            set_outbound_window(base_virt, window_idx, ranges[i].cpu_addr,
                                ranges[i].pci_addr, ranges[i].size);

            // 保存第一个memory range用于BAR分配
            if (window_idx == 0) {
                brcmstb_pcie_context.mem_pci_base = ranges[i].pci_addr;
                brcmstb_pcie_context.mem_cpu_base = ranges[i].cpu_addr;
                brcmstb_pcie_context.mem_size = ranges[i].size;
                brcmstb_pcie_context.mem_current = ranges[i].pci_addr;

                printk("PCIe: BAR allocation pool: PCI 0x%llx, size 0x%llx\n",
                       brcmstb_pcie_context.mem_pci_base,
                       brcmstb_pcie_context.mem_size);
            }

            window_idx++;
        }
    }

    /* 配置链路能力 */
    val = mmio_read32(base_virt + PCIE_RC_CFG_PRIV1_LINK_CAPABILITY);
    val |= PRIV1_LINK_CAPABILITY_L1_L0S_MASK; // 启用 L1 & L0s
    mmio_write32(base_virt + PCIE_RC_CFG_PRIV1_LINK_CAPABILITY, val);

    /* 设置设备类代码为 PCI-PCI Bridge */
    mmio_write32(base_virt + PCIE_RC_CFG_PRIV1_ID_VAL3, 0x060400);

    /* 启用 SSC */
    enable_ssc(base_virt);

    /* 读取链路状态 */
    uint16_t link_status = mmio_read16(base_virt + PCIE_RC_CFG_LINK_STATUS);
    uint8_t link_speed = link_status & 0xf;
    uint8_t link_width = (link_status >> 4) & 0x3f;

    const char *speed_str;
    switch (link_speed) {
    case 1:
        speed_str = "2.5 GT/s";
        break;
    case 2:
        speed_str = "5.0 GT/s";
        break;
    case 4:
        speed_str = "8.0 GT/s";
        break;
    default:
        speed_str = "unknown";
        break;
    }

    printk("PCIe: Link speed %s, x%d\n", speed_str, link_width);

    /* 配置字节序 */
    val = mmio_read32(base_virt + PCIE_RC_CFG_VENDOR_VENDOR_SPECIFIC_REG1);
    val &= ~VENDOR_SPECIFIC_REG1_ENDIAN_MODE_MASK;
    val |= (0 << VENDOR_SPECIFIC_REG1_ENDIAN_MODE_SHIFT); // Little endian
    mmio_write32(base_virt + PCIE_RC_CFG_VENDOR_VENDOR_SPECIFIC_REG1, val);

    /* 启用 CLKREQ# */
    val = mmio_read32(base_virt + PCIE_MISC_HARD_PCIE_HARD_DEBUG);
    val |= PCIE_HARD_DEBUG_CLKREQ_ENABLE;
    mmio_write32(base_virt + PCIE_MISC_HARD_PCIE_HARD_DEBUG, val);

    /* === 配置 RC Bridge === */
    printk("PCIe: Configuring RC Bridge\n");

    // 配置 Bus Numbers: Primary=0, Secondary=1, Subordinate=255
    mmio_write32(base_virt + 0x18, 0x00FF0100);
    printk("  Bus numbers: Primary=0, Secondary=1, Subordinate=255\n");

    // 配置 Memory Base/Limit
    if (brcmstb_pcie_context.mem_size > 0) {
        uint32_t mem_base = (brcmstb_pcie_context.mem_pci_base >> 16) & 0xFFF0;
        uint64_t mem_end = brcmstb_pcie_context.mem_pci_base +
                           brcmstb_pcie_context.mem_size - 1;
        uint32_t mem_limit = (mem_end >> 16) & 0xFFF0;

        uint32_t mem_reg = (mem_limit << 16) | mem_base;
        mmio_write32(base_virt + 0x20, mem_reg);

        printk("  Memory window: 0x%llx - 0x%llx\n",
               brcmstb_pcie_context.mem_pci_base, mem_end);
        printk("  Memory Base/Limit register: 0x%08x\n", mem_reg);
    }

    // 禁用 Prefetchable Memory
    mmio_write32(base_virt + 0x24, 0x0000FFF0);
    mmio_write32(base_virt + 0x28, 0x00000000);
    mmio_write32(base_virt + 0x2C, 0x00000000);

    // 禁用 I/O Space
    mmio_write16(base_virt + 0x1C, 0x00F0);
    mmio_write32(base_virt + 0x30, 0x00000000);

    // 使能 Command register
    uint32_t cmd = mmio_read32(base_virt + 0x04);
    cmd |= 0x07; // I/O Space | Memory Space | Bus Master
    mmio_write32(base_virt + 0x04, cmd);
    printk("  Command register: 0x%04x\n", cmd);

    // 验证配置
    uint32_t buses_verify = mmio_read32(base_virt + 0x18);
    uint32_t mem_verify = mmio_read32(base_virt + 0x20);
    printk("  Verify - Buses: 0x%08x, Memory: 0x%08x\n", buses_verify,
           mem_verify);

    brcmstb_pcie_context.initialized = true;

    return 0;
}

static uint32_t brcmstb_make_cfg_addr(uint8_t bus, uint8_t slot, uint8_t func,
                                      uint16_t offset) {
    return ((bus & 0xFF) << 20) | ((slot & 0x1F) << 15) |
           ((func & 0x07) << 12) | (offset & 0xFFC);
}

static uint8_t brcmstb_cfg_read8(uint32_t bus, uint32_t slot, uint32_t func,
                                 uint32_t segment, uint32_t offset) {
    uint64_t base = brcmstb_pcie_context.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return 0xFF;
    }

    /* Bus 0 访问 RC 配置空间 */
    if (bus == 0) {
        if (slot != 0 || func != 0)
            return 0xFF;
        return mmio_read8(base + offset);
    }

    /* 其他 bus 通过索引/数据寄存器 */
    uint32_t cfg_addr = brcmstb_make_cfg_addr(bus, slot, func, offset);
    mmio_write32(base + PCIE_EXT_CFG_INDEX, cfg_addr);
    return mmio_read8(base + PCIE_EXT_CFG_DATA);
}

static void brcmstb_cfg_write8(uint32_t bus, uint32_t slot, uint32_t func,
                               uint32_t segment, uint32_t offset,
                               uint8_t value) {
    uint64_t base = brcmstb_pcie_context.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return;
    }

    /* Bus 0 访问 RC 配置空间 */
    if (bus == 0) {
        if (slot != 0 || func != 0)
            return;
        mmio_write8(base + offset, value);
    }

    /* 其他 bus 通过索引/数据寄存器 */
    uint32_t cfg_addr = brcmstb_make_cfg_addr(bus, slot, func, offset);
    mmio_write32(base + PCIE_EXT_CFG_INDEX, cfg_addr);
    mmio_write8(base + PCIE_EXT_CFG_DATA, value);
}

static uint16_t brcmstb_cfg_read16(uint32_t bus, uint32_t slot, uint32_t func,
                                   uint32_t segment, uint32_t offset) {
    uint64_t base = brcmstb_pcie_context.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return 0xFFFF;
    }

    /* Bus 0 访问 RC 配置空间 */
    if (bus == 0) {
        if (slot != 0 || func != 0)
            return 0xFFFF;
        return mmio_read16(base + offset);
    }

    /* 其他 bus 通过索引/数据寄存器 */
    uint32_t cfg_addr = brcmstb_make_cfg_addr(bus, slot, func, offset);
    mmio_write32(base + PCIE_EXT_CFG_INDEX, cfg_addr);
    return mmio_read16(base + PCIE_EXT_CFG_DATA);
}

static void brcmstb_cfg_write16(uint32_t bus, uint32_t slot, uint32_t func,
                                uint32_t segment, uint32_t offset,
                                uint16_t value) {
    uint64_t base = brcmstb_pcie_context.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return;
    }

    /* Bus 0 访问 RC 配置空间 */
    if (bus == 0) {
        if (slot != 0 || func != 0)
            return;
        mmio_write16(base + offset, value);
    }

    /* 其他 bus 通过索引/数据寄存器 */
    uint32_t cfg_addr = brcmstb_make_cfg_addr(bus, slot, func, offset);
    mmio_write32(base + PCIE_EXT_CFG_INDEX, cfg_addr);
    mmio_write16(base + PCIE_EXT_CFG_DATA, value);
}

static uint32_t brcmstb_cfg_read32(uint32_t bus, uint32_t slot, uint32_t func,
                                   uint32_t segment, uint32_t offset) {
    uint64_t base = brcmstb_pcie_context.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return 0xFFFFFFFF;
    }

    /* Bus 0 访问 RC 配置空间 */
    if (bus == 0) {
        if (slot != 0 || func != 0)
            return 0xFFFFFFFF;
        return mmio_read32(base + offset);
    }

    /* 其他 bus 通过索引/数据寄存器 */
    uint32_t cfg_addr = brcmstb_make_cfg_addr(bus, slot, func, offset);
    mmio_write32(base + PCIE_EXT_CFG_INDEX, cfg_addr);
    return mmio_read32(base + PCIE_EXT_CFG_DATA);
}

static void brcmstb_cfg_write32(uint32_t bus, uint32_t slot, uint32_t func,
                                uint32_t segment, uint32_t offset,
                                uint32_t value) {
    uint64_t base = brcmstb_pcie_context.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return;
    }

    /* Bus 0 访问 RC 配置空间 */
    if (bus == 0) {
        if (slot != 0 || func != 0)
            return;
        mmio_write32(base + offset, value);
    }

    /* 其他 bus 通过索引/数据寄存器 */
    uint32_t cfg_addr = brcmstb_make_cfg_addr(bus, slot, func, offset);
    mmio_write32(base + PCIE_EXT_CFG_INDEX, cfg_addr);
    mmio_write32(base + PCIE_EXT_CFG_DATA, value);
}

pci_device_op_t pcie_brcmstb_device_op = {
    .read8 = brcmstb_cfg_read8,
    .write8 = brcmstb_cfg_write8,
    .read16 = brcmstb_cfg_read16,
    .write16 = brcmstb_cfg_write16,
    .read32 = brcmstb_cfg_read32,
    .write32 = brcmstb_cfg_write32,
};

/**
 * 分配BAR地址
 */
static uint64_t pcie_allocate_bar(uint64_t size, bool is_64bit) {
    if (size == 0) {
        return 0;
    }

    // 确保size是2的幂
    if ((size & (size - 1)) != 0) {
        printk("PCIe: WARNING - BAR size 0x%llx is not power of 2\n", size);
        // 向上对齐到2的幂
        size = 1ULL << (64 - __builtin_clzll(size));
    }

    // 对齐到size
    uint64_t align_mask = size - 1;
    uint64_t addr =
        (brcmstb_pcie_context.mem_current + align_mask) & ~align_mask;

    // 检查是否超出范围
    uint64_t end =
        brcmstb_pcie_context.mem_pci_base + brcmstb_pcie_context.mem_size;
    if (addr + size > end) {
        printk("PCIe: Out of memory space (need 0x%llx, have 0x%llx)\n",
               addr + size, end);
        return 0;
    }

    brcmstb_pcie_context.mem_current = addr + size;

    printk("    Allocated: 0x%llx - 0x%llx (size 0x%llx)\n", addr,
           addr + size - 1, size);
    return addr;
}

void pcie_brcmstb_scan_bus(uint16_t segment, uint8_t bus);

/**
 * BRCMSTB 扫描单个功能
 */
void pcie_brcmstb_scan_function(uint16_t segment, uint8_t bus, uint8_t device,
                                uint8_t function) {
    // 读取 vendor ID
    uint16_t vendor_id =
        pcie_brcmstb_device_op.read16(bus, device, function, segment, 0x00);

    if (vendor_id == 0xFFFF || vendor_id == 0x0000) {
        return; // 设备不存在
    }

    uint16_t device_id =
        pcie_brcmstb_device_op.read16(bus, device, function, segment, 0x02);

    printk("PCIe: Found device at %02x:%02x.%x - %04x:%04x\n", bus, device,
           function, vendor_id, device_id);

    // 读取类代码
    uint32_t class_rev =
        pcie_brcmstb_device_op.read32(bus, device, function, segment, 0x08);
    uint8_t revision = class_rev & 0xFF;
    uint32_t class_code = class_rev >> 8;

    // 读取 header type
    uint8_t header_type =
        pcie_brcmstb_device_op.read8(bus, device, function, segment, 0x0E);
    header_type &= 0x7F; // 清除多功能位

    // 创建设备结构
    pci_device_t *pci_device = (pci_device_t *)malloc(sizeof(pci_device_t));
    memset(pci_device, 0, sizeof(pci_device_t));

    pci_device->header_type = header_type;
    pci_device->op = &pcie_brcmstb_device_op;
    pci_device->revision_id = revision;
    pci_device->segment = segment;
    pci_device->bus = bus;
    pci_device->slot = device;
    pci_device->func = function;
    pci_device->vendor_id = vendor_id;
    pci_device->device_id = device_id;
    pci_device->class_code = class_code;
    pci_device->name = pci_classname(class_code);

    switch (header_type) {
    case 0x00: { // Endpoint
        printk("PCIe: Endpoint device: %s (class 0x%06x)\n", pci_device->name,
               class_code);

        // 读取 subsystem IDs
        uint32_t subsys =
            pci_device->op->read32(bus, device, function, segment, 0x2C);
        pci_device->subsystem_vendor_id = subsys & 0xFFFF;
        pci_device->subsystem_device_id = subsys >> 16;

        // 读取中断信息
        uint32_t interrupt =
            pci_device->op->read32(bus, device, function, segment, 0x3C);
        pci_device->irq_line = interrupt & 0xFF;
        pci_device->irq_pin = (interrupt >> 8) & 0xFF;

        // 读取 capability pointer
        pci_device->capability_point =
            pci_device->op->read8(bus, device, function, segment, 0x34);

        // === 扫描并分配 BARs ===
        printk("  Scanning and allocating BARs:\n");

        for (int i = 0; i < 6; i++) {
            uint32_t bar_offset = 0x10 + i * 4;

            // 读取原始值
            uint32_t bar_orig = pci_device->op->read32(bus, device, function,
                                                       segment, bar_offset);

            // 写入全1探测大小
            pci_device->op->write32(bus, device, function, segment, bar_offset,
                                    0xFFFFFFFF);

            // 读回获取size mask
            uint32_t bar_mask = pci_device->op->read32(bus, device, function,
                                                       segment, bar_offset);

            // 如果读回0或0xFFFFFFFF，说明BAR未实现
            if (bar_mask == 0 || bar_mask == 0xFFFFFFFF) {
                // 恢复原值
                pci_device->op->write32(bus, device, function, segment,
                                        bar_offset, bar_orig);
                continue;
            }

            if (bar_mask & 0x1) {
                // I/O BAR - 跳过
                printk("  BAR%d: I/O space (skipping)\n", i);
                pci_device->op->write32(bus, device, function, segment,
                                        bar_offset, bar_orig);
                pci_device->bars[i].mmio = false;
                continue;
            }

            // Memory BAR
            uint32_t type = (bar_mask >> 1) & 0x3;

            if (type == 0x00) { // 32-bit Memory BAR
                uint64_t size = ~(bar_mask & 0xFFFFFFF0) + 1;

                if (size == 0) {
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset, bar_orig);
                    continue;
                }

                printk("  BAR%d: 32-bit Memory, size=0x%llx\n", i, size);

                uint64_t addr = pcie_allocate_bar(size, false);
                if (addr) {
                    // 写入分配的地址
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset, (uint32_t)addr);

                    // 验证写入
                    uint32_t verify = pci_device->op->read32(
                        bus, device, function, segment, bar_offset);

                    // 保存信息
                    pci_device->bars[i].address = addr;
                    pci_device->bars[i].size = size;
                    pci_device->bars[i].mmio = true;

                    printk("    Wrote 0x%llx, verified 0x%08x\n", addr, verify);
                } else {
                    // 分配失败，恢复原值
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset, bar_orig);
                }

            } else if (type == 0x02) { // 64-bit Memory BAR
                // 读取高32位的size mask
                uint32_t bar_orig_hi = pci_device->op->read32(
                    bus, device, function, segment, bar_offset + 4);

                pci_device->op->write32(bus, device, function, segment,
                                        bar_offset + 4, 0xFFFFFFFF);
                uint32_t bar_mask_hi = pci_device->op->read32(
                    bus, device, function, segment, bar_offset + 4);

                uint64_t size_mask =
                    ((uint64_t)bar_mask_hi << 32) | (bar_mask & 0xFFFFFFF0);
                uint64_t size = ~size_mask + 1;

                if (size == 0) {
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset, bar_orig);
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset + 4, bar_orig_hi);
                    i++; // 跳过下一个BAR
                    continue;
                }

                printk("  BAR%d: 64-bit Memory, size=0x%llx\n", i, size);

                uint64_t addr = pcie_allocate_bar(size, true);
                if (addr) {
                    // 写入分配的地址（分两次写）
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset, (uint32_t)addr);
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset + 4,
                                            (uint32_t)(addr >> 32));

                    // 验证写入
                    uint32_t verify_lo = pci_device->op->read32(
                        bus, device, function, segment, bar_offset);
                    uint32_t verify_hi = pci_device->op->read32(
                        bus, device, function, segment, bar_offset + 4);

                    // 保存信息
                    pci_device->bars[i].address = addr;
                    pci_device->bars[i].size = size;
                    pci_device->bars[i].mmio = true;

                    printk("    Wrote 0x%llx, verified 0x%08x%08x\n", addr,
                           verify_hi, verify_lo);
                } else {
                    // 分配失败，恢复原值
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset, bar_orig);
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset + 4, bar_orig_hi);
                }

                i++; // 64-bit BAR 占用两个槽位

            } else {
                printk("  BAR%d: Reserved type 0x%x\n", i, type);
                pci_device->op->write32(bus, device, function, segment,
                                        bar_offset, bar_orig);
            }
        }

        // BARs 配置完成后，使能设备
        printk("  Enabling device...\n");
        uint32_t cmd =
            pci_device->op->read32(bus, device, function, segment, 0x04);
        printk("    Command register before: 0x%04x\n", cmd);
        cmd |= 0x06; // Memory Space Enable | Bus Master Enable
        pci_device->op->write32(bus, device, function, segment, 0x04, cmd);
        cmd = pci_device->op->read32(bus, device, function, segment, 0x04);
        printk("    Command register after: 0x%04x\n", cmd);

        // 添加到设备列表
        pci_devices[pci_device_number++] = pci_device;
        break;
    }

    case 0x01: { // PCI-PCI Bridge
        printk("PCIe: Bridge device at %02x:%02x.%x\n", bus, device, function);

        // 读取总线配置
        uint32_t buses =
            pci_device->op->read32(bus, device, function, segment, 0x18);
        uint8_t primary_bus = buses & 0xFF;
        uint8_t secondary_bus = (buses >> 8) & 0xFF;
        uint8_t subordinate_bus = (buses >> 16) & 0xFF;

        printk("  Primary: %d, Secondary: %d, Subordinate: %d\n", primary_bus,
               secondary_bus, subordinate_bus);

        // 验证总线号合法性
        if (secondary_bus == 0 || secondary_bus == 0xFF) {
            printk("  WARNING: Invalid secondary bus number\n");
            free(pci_device);
            break;
        }

        // 检查循环引用
        if (secondary_bus <= bus) {
            printk("  WARNING: Possible bus loop detected (sec %d <= cur %d)\n",
                   secondary_bus, bus);
            free(pci_device);
            break;
        }

        // 使能桥设备
        uint32_t cmd =
            pci_device->op->read32(bus, device, function, segment, 0x04);
        cmd |= 0x07; // I/O, Memory, Bus Master
        pci_device->op->write32(bus, device, function, segment, 0x04, cmd);

        // 递归扫描子总线（只扫描secondary bus）
        pcie_brcmstb_scan_bus(segment, secondary_bus);

        free(pci_device);
        break;
    }

    default:
        printk("PCIe: Unknown header type 0x%02x\n", header_type);
        free(pci_device);
        break;
    }
}

/**
 * BRCMSTB 扫描总线
 */
void pcie_brcmstb_scan_bus(uint16_t segment, uint8_t bus) {
    printk("PCIe: Scanning bus %d\n", bus);

    for (uint8_t device = 0; device < 32; device++) {
        // 先扫描功能 0
        uint16_t vendor_id =
            pcie_brcmstb_device_op.read16(bus, device, 0, segment, 0x00);

        if (vendor_id == 0xFFFF || vendor_id == 0x0000) {
            continue; // 设备不存在
        }

        // 扫描功能 0
        pcie_brcmstb_scan_function(segment, bus, device, 0);

        // 检查是否是多功能设备
        uint8_t header_type =
            pcie_brcmstb_device_op.read8(bus, device, 0, segment, 0x0E);

        if (header_type & 0x80) { // 多功能设备
            for (uint8_t func = 1; func < 8; func++) {
                pcie_brcmstb_scan_function(segment, bus, device, func);
            }
        }
    }
}

/**
 * BRCMSTB 扫描 segment
 */
void pcie_brcmstb_scan_segment(uint16_t segment) {
    if (!brcmstb_pcie_context.initialized) {
        printk("PCIe BRCMSTB: Not initialized\n");
        return;
    }

    printk("PCIe BRCMSTB: Scanning segment %d\n", segment);

    // 从 bus 0 开始扫描
    pcie_brcmstb_scan_bus(segment, 0);

    // 如果 bus 0, device 0, function 0 是多功能设备，扫描其他功能作为其他总线
    uint8_t header_type = pcie_brcmstb_device_op.read8(0, 0, 0, segment, 0x0E);

    if (header_type & 0x80) {
        for (uint8_t func = 1; func < 8; func++) {
            uint16_t vendor_id =
                pcie_brcmstb_device_op.read16(0, 0, func, segment, 0x00);
            if (vendor_id != 0xFFFF && vendor_id != 0x0000) {
                pcie_brcmstb_scan_bus(segment, func);
            }
        }
    }
}

static int pcie_brcmstb_probe(fdt_device_t *dev, const char *compatible) {
    void *fdt = (void *)boot_get_dtb();

    printk("PCIe: Probing brcmstb PCIe controller\n");
    printk("PCIe: Compatible: %s\n", compatible);
    printk("PCIe: Node offset: %d\n", dev->node);

    // 保存 node offset（重要！）
    brcmstb_pcie_context.fdt_node = dev->node;

    uint64_t pcie_base, pcie_size;
    uint64_t msi_base, msi_size;

    // 通过 reg-names 查找索引
    int pcie_idx = fdt_get_reg_index_by_name(fdt, dev->node, "pcie");
    int msi_idx = fdt_get_reg_index_by_name(fdt, dev->node, "msi");

    if (pcie_idx < 0) {
        pcie_idx = 0; // 默认第一个
        msi_idx = 1;  // 默认第二个
    }

    // 获取 PCIe 寄存器
    if (fdt_get_reg(fdt, dev->node, pcie_idx, &pcie_base, &pcie_size) != 0) {
        printk("PCIe: Failed to get base address\n");
        return -1;
    }

    printk("PCIe: Base = 0x%016llx, Size = 0x%llx\n", pcie_base, pcie_size);

    // 获取 MSI 寄存器（可选）
    if (msi_idx >= 0) {
        if (fdt_get_reg(fdt, dev->node, msi_idx, &msi_base, &msi_size) == 0) {
            printk("PCIe: MSI Base = 0x%016llx, Size = 0x%llx\n", msi_base,
                   msi_size);
        }
    }

    // 保存配置
    brcmstb_pcie.pcie_base = pcie_base;
    brcmstb_pcie.pcie_size = pcie_size;
    brcmstb_pcie.msi_base = msi_base;
    brcmstb_pcie.msi_size = msi_size;
    brcmstb_pcie.found = true;

    // 映射内存
    uint64_t pcie_base_virt = phys_to_virt(brcmstb_pcie.pcie_base);
    map_page_range(get_current_page_dir(false), pcie_base_virt,
                   brcmstb_pcie.pcie_base, brcmstb_pcie.pcie_size,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE |
                       PT_FLAG_DEVICE);

    // 初始化控制器
    if (pcie_brcmstb_init(pcie_base_virt, brcmstb_pcie.pcie_base,
                          brcmstb_pcie.pcie_size) != 0) {
        printk("PCIe BRCMSTB: Initialization failed\n");
        return -1;
    }

    pcie_brcmstb_scan_segment(0);

    return 0;
}

/* PCIe 驱动注册 */
static const char *pcie_brcmstb_compatible[] = {
    "brcm,bcm2711-pcie",
    "brcm,bcm7445-pcie",
    "brcm,bcm2712-pcie",
    "brcm,pcie-brcmstb",
    NULL,
};

static fdt_driver_t pcie_brcmstb_driver = {
    .name = "pcie-brcmstb",
    .compatible = pcie_brcmstb_compatible,
    .probe = pcie_brcmstb_probe,
};

void pci_brcmstb_init() { regist_fdt_driver(&pcie_brcmstb_driver); }

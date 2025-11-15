#include <arch/arch.h>
#include <boot/boot.h>
#include <libs/aether/fdt.h>
#include <drivers/bus/pci.h>

static pcie_brcmstb_context_t brcmstb_ctx = {0};

static inline void mmio_write32(uint64_t addr, uint32_t data) {
    *(volatile uint32_t *)addr = data;
}

static inline uint32_t mmio_read32(uint64_t addr) {
    return *(volatile uint32_t *)addr;
}

static inline void mmio_write16(uint64_t addr, uint16_t data) {
    *(volatile uint16_t *)addr = data;
}

static inline uint16_t mmio_read16(uint64_t addr) {
    return *(volatile uint16_t *)addr;
}

static inline void mmio_write8(uint64_t addr, uint8_t data) {
    *(volatile uint8_t *)addr = data;
}

static inline uint8_t mmio_read8(uint64_t addr) {
    return *(volatile uint8_t *)addr;
}

static void delay_us(uint64_t us) {
    uint64_t start = nanoTime();
    while ((nanoTime() - start) < us * 1000ULL) {
        asm volatile("nop");
    }
}

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

static uint32_t mdio_read(uint64_t base, uint8_t port, uint8_t reg) {
    uint32_t cmd = (1 << MDIO_PKT_CMD_SHIFT) | (port << MDIO_PKT_PORT_SHIFT) |
                   (reg << MDIO_PKT_REG_SHIFT);

    mmio_write32(base + PCIE_MDIO_ADDR, cmd);
    mmio_read32(base + PCIE_MDIO_ADDR); // Flush

    for (int i = 0; i < 10; i++) {
        uint32_t data = mmio_read32(base + PCIE_MDIO_RD_DATA);
        if (data & MDIO_DATA_DONE) {
            return data & MDIO_DATA_MASK;
        }
        delay_us(10000);
    }

    printk("PCIe: MDIO read timeout\n");
    return 0;
}

static void mdio_write(uint64_t base, uint8_t port, uint8_t reg, uint16_t val) {
    uint32_t cmd = (0 << MDIO_PKT_CMD_SHIFT) | (port << MDIO_PKT_PORT_SHIFT) |
                   (reg << MDIO_PKT_REG_SHIFT);

    mmio_write32(base + PCIE_MDIO_ADDR, cmd);
    mmio_read32(base + PCIE_MDIO_ADDR); // Flush

    mmio_write32(base + PCIE_MDIO_WR_DATA, MDIO_DATA_DONE | val);

    for (int i = 0; i < 10; i++) {
        uint32_t data = mmio_read32(base + PCIE_MDIO_WR_DATA);
        if (!(data & MDIO_DATA_DONE)) {
            return;
        }
        delay_us(10000);
    }

    printk("PCIe: MDIO write timeout\n");
}

static void enable_ssc(uint64_t base) {
    mdio_write(base, 0, 0x1f, 0x1100);

    uint32_t ctl = mdio_read(base, 0, 0x0002);
    ctl |= 0x8000; // SSC enable
    ctl |= 0x4000; // SSC mode
    mdio_write(base, 0, 0x0002, ctl);

    delay_us(2000);

    uint32_t status = mdio_read(base, 0, 0x0001);
    if (!((status & 0x400) && (status & 0x800))) {
        printk("PCIe: SSC enable verification failed (status=0x%x)\n", status);
    }
}

static void brcmstb_pcie_reset(uint64_t base) {
    uint32_t val;

    // 设置 SW_INIT
    val = mmio_read32(base + PCIE_BRIDGE_CTL);
    val |= BRIDGE_CTL_SW_INIT;
    mmio_write32(base + PCIE_BRIDGE_CTL, val);

    delay_us(200);

    // 清除 SW_INIT
    val = mmio_read32(base + PCIE_BRIDGE_CTL);
    val &= ~BRIDGE_CTL_SW_INIT;
    mmio_write32(base + PCIE_BRIDGE_CTL, val);

    delay_us(200);

    // 清除 SERDES_DISABLE
    val = mmio_read32(base + PCIE_HARD_DEBUG);
    val &= ~HARD_DEBUG_SERDES_DISABLE;
    mmio_write32(base + PCIE_HARD_DEBUG, val);

    delay_us(100);
}

static void brcmstb_pcie_enable(uint64_t base) {
    // 清除 RESET 位
    uint32_t val = mmio_read32(base + PCIE_BRIDGE_CTL);
    val &= ~BRIDGE_CTL_RESET;
    mmio_write32(base + PCIE_BRIDGE_CTL, val);

    delay_us(100);
}

static bool brcmstb_pcie_link_up(uint64_t base) {
    uint32_t state = mmio_read32(base + PCIE_BRIDGE_STATE);
    return (state & BRIDGE_STATE_DL_ACTIVE) &&
           (state & BRIDGE_STATE_PHY_ACTIVE);
}

static void set_outbound_window(uint64_t base, int n, uint64_t cpu_addr,
                                uint64_t pcie_addr, uint64_t size) {
    // 设置 PCIe 地址
    mmio_write32(base + PCIE_OUTBOUND_WIN_PCIE_LO(n), (uint32_t)pcie_addr);
    mmio_write32(base + PCIE_OUTBOUND_WIN_PCIE_HI(n),
                 (uint32_t)(pcie_addr >> 32));

    // 设置 CPU 地址范围
    uint64_t base_mb = cpu_addr / 0x100000;
    uint64_t limit_mb = (cpu_addr + size - 1) / 0x100000;

    uint32_t base_limit = ((limit_mb & 0xFFF) << 20) | ((base_mb & 0xFFF) << 4);
    mmio_write32(base + PCIE_OUTBOUND_WIN_BASE_LIMIT(n), base_limit);

    // 设置高位
    mmio_write32(base + PCIE_OUTBOUND_WIN_BASE_HI(n), (base_mb >> 12) & 0xFF);
    mmio_write32(base + PCIE_OUTBOUND_WIN_LIMIT_HI(n), (limit_mb >> 12) & 0xFF);

    printk("  Window %d: CPU 0x%llx -> PCIe 0x%llx (size 0x%llx)\n", n,
           cpu_addr, pcie_addr, size);
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

static uint64_t fdt_translate_address(void *fdt, int node, uint64_t addr) {
    int parent = fdt_parent_offset(fdt, node);
    while (parent >= 0) {
        int len;
        const uint32_t *ranges = fdt_getprop(fdt, parent, "ranges", &len);
        if (!ranges) {
            parent = fdt_parent_offset(fdt, parent);
            if (parent < 0)
                break;
            continue;
        }
        if (len == 0) {
            parent = fdt_parent_offset(fdt, parent);
            continue;
        }

        int child_addr_cells = fdt_address_cells(fdt, parent);
        int parent_parent = fdt_parent_offset(fdt, parent);
        int parent_addr_cells =
            (parent_parent >= 0) ? fdt_address_cells(fdt, parent_parent) : 2;
        int size_cells = fdt_size_cells(fdt, parent);

        const uint32_t *p = ranges;
        int cells_per_entry = child_addr_cells + parent_addr_cells + size_cells;
        int num_entries = (len / sizeof(uint32_t)) / cells_per_entry;

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

static int pcie_parse_ranges(void *fdt, int node, pcie_range_t *ranges,
                             int max_ranges) {
    int len;
    const uint32_t *prop = fdt_getprop(fdt, node, "ranges", &len);
    if (!prop || len <= 0)
        return 0;

    int parent = fdt_parent_offset(fdt, node);
    int na = 3; // PCI地址cells
    int pna = fdt_address_cells(fdt, parent);
    int ns = fdt_size_cells(fdt, node);

    const uint32_t *p = prop;
    const uint32_t *end = prop + (len / sizeof(uint32_t));
    int count = 0;

    while (p < end && count < max_ranges) {
        uint32_t flags = fdt32_to_cpu(*p++);
        uint32_t pci_addr_hi = fdt32_to_cpu(*p++);
        uint32_t pci_addr_lo = fdt32_to_cpu(*p++);
        uint64_t pci_addr = ((uint64_t)pci_addr_hi << 32) | pci_addr_lo;

        uint64_t cpu_addr = fdt_read_cells(&p, pna);
        uint64_t size = fdt_read_cells(&p, ns);

        ranges[count].flags = flags;
        ranges[count].pci_addr = pci_addr;
        ranges[count].cpu_addr = fdt_translate_address(fdt, node, cpu_addr);
        ranges[count].size = size;

        count++;
    }

    return count;
}

static int pcie_brcmstb_init(uint64_t base, uint64_t phys, uint64_t size) {
    uint32_t val;

    printk("PCIe BRCMSTB: Initializing controller\n");

    // 复位控制器
    brcmstb_pcie_reset(base);

    // 读取硬件版本
    uint32_t rev = mmio_read32(base + PCIE_HW_REV) & 0xFFFF;
    printk("PCIe: Hardware revision 0x%04x\n", rev);

    if (rev == 0 || rev == 0xFFFF) {
        printk("PCIe: ERROR - Invalid revision\n");
        return -1;
    }

    // 配置 MISC_CTRL
    val = mmio_read32(base + PCIE_MISC_CTRL);
    val |= MISC_CTRL_ACCESS_ENABLE;
    val |= MISC_CTRL_READ_UR_MODE;
    val &= ~MISC_CTRL_MAX_BURST_MASK;
    val |= (0 << MISC_CTRL_MAX_BURST_SHIFT); // 128 bytes
    mmio_write32(base + PCIE_MISC_CTRL, val);

    // 配置 RC BAR2
    uint64_t rc_bar_size = 0x200000000ULL; // 8GB
    mmio_write32(base + PCIE_RC_BAR2_LO, rc_bar_encode_size(rc_bar_size));
    mmio_write32(base + PCIE_RC_BAR2_HI, 0);

    // 设置 SCB_SIZE_0
    val = mmio_read32(base + PCIE_MISC_CTRL);
    val &= ~MISC_CTRL_SCB_SIZE_0_MASK;
    val |= ((63 - __builtin_clzll(rc_bar_size) - 15)
            << MISC_CTRL_SCB_SIZE_0_SHIFT);
    mmio_write32(base + PCIE_MISC_CTRL, val);

    // 禁用 BAR1 和 BAR3
    val = mmio_read32(base + PCIE_RC_BAR1_LO);
    val &= ~RC_BAR_SIZE_MASK;
    mmio_write32(base + PCIE_RC_BAR1_LO, val);

    val = mmio_read32(base + PCIE_RC_BAR3_LO);
    val &= ~RC_BAR_SIZE_MASK;
    mmio_write32(base + PCIE_RC_BAR3_LO, val);

    // 启用控制器
    brcmstb_pcie_enable(base);

    // 等待链路建立
    printk("PCIe: Waiting for link up...\n");
    int timeout = 100;
    bool link_up = false;

    for (int i = 0; i < timeout; i++) {
        if (brcmstb_pcie_link_up(base)) {
            link_up = true;
            break;
        }
        delay_us(5000);
    }

    if (!link_up) {
        printk("PCIe: Link failed to come up\n");
        return -1;
    }

    // 检查 RC 模式
    val = mmio_read32(base + PCIE_BRIDGE_STATE);
    if (!(val & BRIDGE_STATE_RC_MODE)) {
        printk("PCIe: ERROR - Controller in EP mode\n");
        return -1;
    }

    // 解析和配置 outbound windows
    void *fdt = (void *)boot_get_dtb();
    pcie_range_t ranges[8];
    int range_count = pcie_parse_ranges(fdt, brcmstb_ctx.fdt_node, ranges, 8);

    int window_idx = 0;
    for (int i = 0; i < range_count && window_idx < 4; i++) {
        uint32_t space_code = (ranges[i].flags >> 24) & 0x03;
        if (space_code == 0x02 || space_code == 0x03) { // Memory space
            set_outbound_window(base, window_idx, ranges[i].cpu_addr,
                                ranges[i].pci_addr, ranges[i].size);

            if (window_idx == 0) {
                brcmstb_ctx.mem_pci_base = ranges[i].pci_addr;
                brcmstb_ctx.mem_cpu_base = ranges[i].cpu_addr;
                brcmstb_ctx.mem_size = ranges[i].size;
                brcmstb_ctx.mem_current = ranges[i].pci_addr;
            }
            window_idx++;
        }
    }

    // 配置链路能力 (L0s & L1)
    val = mmio_read32(base + PCIE_PRIV1_LINK_CAP);
    val &= ~PRIV1_LINK_CAP_MASK;
    val |= (0x3 << PRIV1_LINK_CAP_SHIFT); // Enable L0s & L1
    mmio_write32(base + PCIE_PRIV1_LINK_CAP, val);

    // 设置设备 ID
    val = mmio_read32(base + PCIE_PRIV1_ID_VAL3);
    val = (val & ~PRIV1_ID_MASK) | 0x060400; // PCI-PCI Bridge
    mmio_write32(base + PCIE_PRIV1_ID_VAL3, val);

    // 启用 SSC
    enable_ssc(base);

    // 读取链路状态
    uint16_t lnksta = mmio_read16(base + PCIE_LNKSTA);
    uint8_t speed = lnksta & LNKSTA_LINK_SPEED_MASK;
    uint8_t width =
        (lnksta >> LNKSTA_LINK_WIDTH_SHIFT) & LNKSTA_LINK_WIDTH_MASK;

    const char *speed_str;
    switch (speed) {
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
    printk("PCIe: Link speed %s, x%d\n", speed_str, width);

    // 配置字节序
    val = mmio_read32(base + PCIE_VENDOR_REG1);
    val &= ~VENDOR_REG1_ENDIAN_MODE_MASK;
    val |= (0 << VENDOR_REG1_ENDIAN_MODE_SHIFT); // Little endian
    mmio_write32(base + PCIE_VENDOR_REG1, val);

    // 启用 CLKREQ
    val = mmio_read32(base + PCIE_HARD_DEBUG);
    val |= HARD_DEBUG_CLKREQ_ENABLE;
    mmio_write32(base + PCIE_HARD_DEBUG, val);

    brcmstb_ctx.initialized = true;
    return 0;
}

static uint32_t make_cfg_index(uint8_t bus, uint8_t slot, uint8_t func) {
    return ((bus << CFG_INDEX_BUS_SHIFT) & CFG_INDEX_BUS_MASK) |
           ((slot << CFG_INDEX_SLOT_SHIFT) & CFG_INDEX_SLOT_MASK) |
           ((func << CFG_INDEX_FUNC_SHIFT) & CFG_INDEX_FUNC_MASK);
}

static uint8_t brcmstb_cfg_read8(uint32_t bus, uint32_t slot, uint32_t func,
                                 uint32_t segment, uint32_t offset) {
    uint64_t base = brcmstb_ctx.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return 0xFF;
    }

    // Bus 0 (root bus) 直接访问控制器寄存器
    if (bus == brcmstb_ctx.bus_start) {
        if (slot != 0 || func != 0)
            return 0xFF;
        return mmio_read8(base + offset);
    }

    // 其他总线使用配置空间索引
    mmio_write32(base + PCIE_CFG_INDEX, make_cfg_index(bus, slot, func));
    return mmio_read8(base + PCIE_CFG_DATA + offset);
}

static void brcmstb_cfg_write8(uint32_t bus, uint32_t slot, uint32_t func,
                               uint32_t segment, uint32_t offset,
                               uint8_t value) {
    uint64_t base = brcmstb_ctx.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return;
    }

    if (bus == brcmstb_ctx.bus_start) {
        if (slot != 0 || func != 0)
            return;
        mmio_write8(base + offset, value);
        return;
    }

    mmio_write32(base + PCIE_CFG_INDEX, make_cfg_index(bus, slot, func));
    mmio_write8(base + PCIE_CFG_DATA + offset, value);
}

static uint16_t brcmstb_cfg_read16(uint32_t bus, uint32_t slot, uint32_t func,
                                   uint32_t segment, uint32_t offset) {
    uint64_t base = brcmstb_ctx.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return 0xFFFF;
    }

    if (bus == brcmstb_ctx.bus_start) {
        if (slot != 0 || func != 0)
            return 0xFFFF;
        return mmio_read16(base + offset);
    }

    mmio_write32(base + PCIE_CFG_INDEX, make_cfg_index(bus, slot, func));
    return mmio_read16(base + PCIE_CFG_DATA + offset);
}

static void brcmstb_cfg_write16(uint32_t bus, uint32_t slot, uint32_t func,
                                uint32_t segment, uint32_t offset,
                                uint16_t value) {
    uint64_t base = brcmstb_ctx.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return;
    }

    if (bus == brcmstb_ctx.bus_start) {
        if (slot != 0 || func != 0)
            return;
        mmio_write16(base + offset, value);
        return;
    }

    mmio_write32(base + PCIE_CFG_INDEX, make_cfg_index(bus, slot, func));
    mmio_write16(base + PCIE_CFG_DATA + offset, value);
}

static uint32_t brcmstb_cfg_read32(uint32_t bus, uint32_t slot, uint32_t func,
                                   uint32_t segment, uint32_t offset) {
    uint64_t base = brcmstb_ctx.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return 0xFFFFFFFF;
    }

    if (bus == brcmstb_ctx.bus_start) {
        if (slot != 0 || func != 0)
            return 0xFFFFFFFF;
        return mmio_read32(base + offset);
    }

    mmio_write32(base + PCIE_CFG_INDEX, make_cfg_index(bus, slot, func));
    return mmio_read32(base + PCIE_CFG_DATA + offset);
}

static void brcmstb_cfg_write32(uint32_t bus, uint32_t slot, uint32_t func,
                                uint32_t segment, uint32_t offset,
                                uint32_t value) {
    uint64_t base = brcmstb_ctx.pcie_base_virt;

    if (!brcmstb_pcie_link_up(base)) {
        return;
    }

    if (bus == brcmstb_ctx.bus_start) {
        if (slot != 0 || func != 0)
            return;
        mmio_write32(base + offset, value);
        return;
    }

    mmio_write32(base + PCIE_CFG_INDEX, make_cfg_index(bus, slot, func));
    mmio_write32(base + PCIE_CFG_DATA + offset, value);
}

pci_device_op_t pcie_brcmstb_device_op = {
    .read8 = brcmstb_cfg_read8,
    .write8 = brcmstb_cfg_write8,
    .read16 = brcmstb_cfg_read16,
    .write16 = brcmstb_cfg_write16,
    .read32 = brcmstb_cfg_read32,
    .write32 = brcmstb_cfg_write32,
};

static int pcie_brcmstb_probe(fdt_device_t *dev, const char *compatible) {
    void *fdt = (void *)boot_get_dtb();
    int node = dev->node;

    printk("PCIe BRCMSTB: Probing controller\n");

    brcmstb_ctx.fdt_node = node;

    // 解析 bus-range
    int len;
    const uint32_t *bus_range = fdt_getprop(fdt, node, "bus-range", &len);
    if (bus_range && len == 8) {
        brcmstb_ctx.bus_start = fdt32_to_cpu(bus_range[0]);
        brcmstb_ctx.bus_end = fdt32_to_cpu(bus_range[1]);
    } else {
        brcmstb_ctx.bus_start = 0;
        brcmstb_ctx.bus_end = 0xFF;
    }

    // 获取寄存器基地址
    int parent = fdt_parent_offset(fdt, node);
    int address_cells = (parent >= 0) ? fdt_address_cells(fdt, parent) : 2;
    int size_cells = (parent >= 0) ? fdt_size_cells(fdt, parent) : 2;

    const uint32_t *reg = fdt_getprop(fdt, node, "reg", &len);
    if (!reg || len < (address_cells + size_cells) * 4) {
        printk("PCIe: Failed to get reg property\n");
        return -1;
    }

    const uint32_t *p = reg;
    uint64_t pcie_base = fdt_read_cells(&p, address_cells);
    uint64_t pcie_size = fdt_read_cells(&p, size_cells);

    pcie_base = fdt_translate_address(fdt, node, pcie_base);

    printk("PCIe: Base 0x%llx, Size 0x%llx\n", pcie_base, pcie_size);
    printk("PCIe: Bus range %d-%d\n", brcmstb_ctx.bus_start,
           brcmstb_ctx.bus_end);

    // 映射寄存器空间
    uint64_t pcie_base_virt = phys_to_virt(pcie_base);
    map_page_range(
        get_current_page_dir(false), pcie_base_virt, pcie_base, pcie_size,
        PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE | PT_FLAG_DEVICE);

    brcmstb_ctx.pcie_base_phys = pcie_base;
    brcmstb_ctx.pcie_base_virt = pcie_base_virt;
    brcmstb_ctx.pcie_size = pcie_size;

    // 初始化控制器
    if (pcie_brcmstb_init(pcie_base_virt, pcie_base, pcie_size) != 0) {
        printk("PCIe BRCMSTB: Initialization failed\n");
        return -1;
    }

    pci_scan_bus(&pcie_brcmstb_device_op, 0, brcmstb_ctx.bus_start);

    printk("PCIe BRCMSTB: Initialization successful\n");
    return 0;
}

static const char *pcie_brcmstb_compatible[] = {
    "brcm,bcm2711-pcie",
    "brcm,bcm2712-pcie",
    NULL,
};

static fdt_driver_t pcie_brcmstb_driver = {
    .name = "pcie-brcmstb",
    .compatible = pcie_brcmstb_compatible,
    .probe = pcie_brcmstb_probe,
};

void pci_brcmstb_init(void) { regist_fdt_driver(&pcie_brcmstb_driver); }

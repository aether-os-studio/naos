#include <arch/arch.h>
#include <boot/boot.h>
#include <libs/aether/fdt.h>
#include <drivers/bus/pci.h>

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

/**
 * 计算配置空间地址
 * BRCMSTB 使用特殊的地址格式
 */
static inline uint32_t brcmstb_make_cfg_addr(uint8_t bus, uint8_t slot,
                                             uint8_t func, uint16_t offset) {
    return ((bus & 0xFF) << 20) | ((slot & 0x1F) << 15) |
           ((func & 0x07) << 12) | (offset & 0xFFF);
}

/**
 * 通过索引/数据寄存器访问配置空间 (间接访问)
 */
static uint32_t brcmstb_indirect_cfg_read32(uint8_t bus, uint8_t slot,
                                            uint8_t func, uint16_t offset) {
    uint64_t base = brcmstb_pcie_context.pcie_base_virt;

    // 构造配置地址
    uint32_t cfg_addr = brcmstb_make_cfg_addr(bus, slot, func, offset & ~0x3);

    // 写入索引寄存器
    *(volatile uint32_t *)(base + PCIE_EXT_CFG_INDEX) = cfg_addr;

    // 从数据寄存器读取
    return *(volatile uint32_t *)(base + PCIE_EXT_CFG_DATA);
}

static void brcmstb_indirect_cfg_write32(uint8_t bus, uint8_t slot,
                                         uint8_t func, uint16_t offset,
                                         uint32_t value) {
    uint64_t base = brcmstb_pcie_context.pcie_base_virt;

    uint32_t cfg_addr = brcmstb_make_cfg_addr(bus, slot, func, offset & ~0x3);

    *(volatile uint32_t *)(base + PCIE_EXT_CFG_INDEX) = cfg_addr;
    *(volatile uint32_t *)(base + PCIE_EXT_CFG_DATA) = value;
}

/**
 * 直接通过 ECAM 窗口访问 (如果支持)
 */
static uint32_t brcmstb_direct_cfg_read32(uint8_t bus, uint8_t slot,
                                          uint8_t func, uint16_t offset) {
    // 计算在配置空间窗口中的偏移
    uint32_t cfg_offset = brcmstb_make_cfg_addr(bus, slot, func, offset & ~0x3);
    uint64_t addr = brcmstb_pcie_context.config_base_virt + cfg_offset;

    return *(volatile uint32_t *)(addr);
}

static void brcmstb_direct_cfg_write32(uint8_t bus, uint8_t slot, uint8_t func,
                                       uint16_t offset, uint32_t value) {
    uint32_t cfg_offset = brcmstb_make_cfg_addr(bus, slot, func, offset & ~0x3);
    uint64_t addr = brcmstb_pcie_context.config_base_virt + cfg_offset;

    *(volatile uint32_t *)(addr) = value;
}

static bool brcmstb_link_up(void) {
    if (!brcmstb_pcie_context.pcie_base_virt) {
        return false;
    }

    uint32_t status =
        *(volatile uint32_t *)(brcmstb_pcie_context.pcie_base_virt +
                               PCIE_MISC_PCIE_STATUS);

    // 需要同时检查 PHYLINKUP 和 DL_ACTIVE
    return (status & PCIE_MISC_PCIE_STATUS_PCIE_PHYLINKUP) &&
           (status & PCIE_MISC_PCIE_STATUS_PCIE_DL_ACTIVE);
}

/**
 * 读取 8 位配置空间
 */
static uint8_t brcmstb_cfg_read8(uint32_t bus, uint32_t slot, uint32_t func,
                                 uint32_t segment, uint32_t offset) {
    if (!brcmstb_link_up()) {
        return 0xFF;
    }

    // 读取 32 位，然后提取字节
    uint32_t val = brcmstb_indirect_cfg_read32(bus, slot, func, offset & ~0x3);

    // 提取对应字节
    uint8_t byte_offset = offset & 0x3;
    return (val >> (byte_offset * 8)) & 0xFF;
}

/**
 * 写入 8 位配置空间
 */
static void brcmstb_cfg_write8(uint32_t bus, uint32_t slot, uint32_t func,
                               uint32_t segment, uint32_t offset,
                               uint8_t value) {
    if (!brcmstb_link_up()) {
        return;
    }

    // 读取 32 位
    uint32_t val = brcmstb_indirect_cfg_read32(bus, slot, func, offset & ~0x3);

    // 修改对应字节
    uint8_t byte_offset = offset & 0x3;
    uint32_t mask = 0xFF << (byte_offset * 8);
    val = (val & ~mask) | ((uint32_t)value << (byte_offset * 8));

    // 写回
    brcmstb_indirect_cfg_write32(bus, slot, func, offset & ~0x3, val);
}

/**
 * 读取 16 位配置空间
 */
static uint16_t brcmstb_cfg_read16(uint32_t bus, uint32_t slot, uint32_t func,
                                   uint32_t segment, uint32_t offset) {
    if (!brcmstb_link_up()) {
        return 0xFFFF;
    }

    uint32_t val = brcmstb_indirect_cfg_read32(bus, slot, func, offset & ~0x3);

    uint8_t word_offset = (offset & 0x2) >> 1;
    return (val >> (word_offset * 16)) & 0xFFFF;
}

/**
 * 写入 16 位配置空间
 */
static void brcmstb_cfg_write16(uint32_t bus, uint32_t slot, uint32_t func,
                                uint32_t segment, uint32_t offset,
                                uint16_t value) {
    if (!brcmstb_link_up()) {
        return;
    }

    uint32_t val = brcmstb_indirect_cfg_read32(bus, slot, func, offset & ~0x3);

    uint8_t word_offset = (offset & 0x2) >> 1;
    uint32_t mask = 0xFFFF << (word_offset * 16);
    val = (val & ~mask) | ((uint32_t)value << (word_offset * 16));

    brcmstb_indirect_cfg_write32(bus, slot, func, offset & ~0x3, val);
}

/**
 * 读取 32 位配置空间
 */
static uint32_t brcmstb_cfg_read32(uint32_t bus, uint32_t slot, uint32_t func,
                                   uint32_t segment, uint32_t offset) {
    if (!brcmstb_link_up()) {
        return 0xFFFFFFFF;
    }

    return brcmstb_indirect_cfg_read32(bus, slot, func, offset);
}

/**
 * 写入 32 位配置空间
 */
static void brcmstb_cfg_write32(uint32_t bus, uint32_t slot, uint32_t func,
                                uint32_t segment, uint32_t offset,
                                uint32_t value) {
    if (!brcmstb_link_up()) {
        return;
    }

    brcmstb_indirect_cfg_write32(bus, slot, func, offset, value);
}

/**
 * 设备操作表
 */
pci_device_op_t pcie_brcmstb_device_op = {
    .read8 = brcmstb_cfg_read8,
    .write8 = brcmstb_cfg_write8,
    .read16 = brcmstb_cfg_read16,
    .write16 = brcmstb_cfg_write16,
    .read32 = brcmstb_cfg_read32,
    .write32 = brcmstb_cfg_write32,
};

static void delay(uint64_t ns) {
    uint64_t start = nanoTime();
    while (nanoTime() - start < ns) {
        asm volatile("nop");
    }
}

static void brcmstb_pcie_perst_set(uint64_t base, bool assert_reset) {
    uint32_t val = *(volatile uint32_t *)(base + PCIE_MISC_PCIE_CTRL);

    if (assert_reset) {
        val &= ~PCIE_MISC_PCIE_CTRL_PCIE_PERSTB; // Assert PERST#
    } else {
        val |= PCIE_MISC_PCIE_CTRL_PCIE_PERSTB; // De-assert PERST#
    }

    *(volatile uint32_t *)(base + PCIE_MISC_PCIE_CTRL) = val;
}

static int brcmstb_pcie_setup_bridge(uint64_t base) {
    uint32_t val;

    printk("PCIe BRCMSTB: Setting up bridge\n");

    /* 禁用所有 RC BARs */
    *(volatile uint32_t *)(base + PCIE_MISC_RC_BAR1_CONFIG_LO) = 0;
    *(volatile uint32_t *)(base + PCIE_MISC_RC_BAR2_CONFIG_LO) = 0;
    *(volatile uint32_t *)(base + PCIE_MISC_RC_BAR2_CONFIG_HI) = 0;
    *(volatile uint32_t *)(base + PCIE_MISC_RC_BAR3_CONFIG_LO) = 0;

    /* 配置 MISC_CTRL */
    val = *(volatile uint32_t *)(base + PCIE_MISC_MISC_CTRL);
    val |= PCIE_MISC_MISC_CTRL_SCB_ACCESS_EN;
    val |= PCIE_MISC_MISC_CTRL_CFG_READ_UR_MODE;
    val |= PCIE_MISC_MISC_CTRL_BURST_ALIGN;
    val &= ~PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_MASK;
    val |= PCIE_MISC_MISC_CTRL_MAX_BURST_SIZE_128;
    *(volatile uint32_t *)(base + PCIE_MISC_MISC_CTRL) = val;

    printk("  MISC_CTRL = 0x%08x\n", val);

    return 0;
}

int pcie_brcmstb_init(uint64_t base_virt, uint64_t base_phys, uint64_t size) {
    uint32_t val;

    printk("PCIe BRCMSTB: Initializing BCM2711 controller\n");
    printk("  Base: phys=0x%llx virt=0x%llx size=0x%llx\n", base_phys,
           base_virt, size);

    brcmstb_pcie_context.pcie_base_phys = base_phys;
    brcmstb_pcie_context.pcie_base_virt = base_virt;
    brcmstb_pcie_context.pcie_size = size;

    /* 读取版本 */
    uint32_t revision = *(volatile uint32_t *)(base_virt + PCIE_MISC_REVISION);
    printk("PCIe BRCMSTB: Revision = 0x%08x\n", revision);

    val = *(volatile uint32_t *)(base_virt + PCIE_RGR1_SW_INIT_1);
    val |= PCIE_RGR1_SW_INIT_1_INIT; // Assert reset
    *(volatile uint32_t *)(base_virt + PCIE_RGR1_SW_INIT_1) = val;

    delay(100ULL * 1000ULL); // 100us

    val &= ~PCIE_RGR1_SW_INIT_1_INIT; // De-assert reset
    *(volatile uint32_t *)(base_virt + PCIE_RGR1_SW_INIT_1) = val;

    delay(100ULL * 1000ULL);

    brcmstb_pcie_perst_set(base_virt, true);
    delay(100ULL * 1000ULL); // 100us

    if (brcmstb_pcie_setup_bridge(base_virt) != 0) {
        printk("PCIe BRCMSTB: Failed to setup bridge\n");
        return -1;
    }

    brcmstb_pcie_perst_set(base_virt, false);

    /* PCIe 规范要求等待 100ms */
    printk("PCIe BRCMSTB: Waiting 100ms for PERST# to settle...\n");
    delay(100ULL * 1000000ULL); // 100ms

    printk("PCIe BRCMSTB: Waiting for link up...\n");

    int timeout = 100; // 100 * 10ms = 1秒
    bool link_up = false;

    while (timeout-- > 0) {
        if (brcmstb_link_up()) {
            link_up = true;
            break;
        }

        /* 每 100ms 打印一次状态 */
        if (timeout % 10 == 0) {
            uint32_t status =
                *(volatile uint32_t *)(base_virt + PCIE_MISC_PCIE_STATUS);
            printk("  [%d] Status=0x%08x PHY=%d DL=%d\n", timeout, status,
                   !!(status & PCIE_MISC_PCIE_STATUS_PCIE_PHYLINKUP),
                   !!(status & PCIE_MISC_PCIE_STATUS_PCIE_DL_ACTIVE));
        }

        delay(10ULL * 1000000ULL); // 10ms
    }

    if (!link_up) {
        printk("PCIe BRCMSTB: WARNING - Link failed to come up\n");
        printk("  This usually means:\n");
        printk("  1. No PCIe device is connected\n");
        printk("  2. PCIe is disabled in firmware (check config.txt)\n");
        printk("  3. Hardware issue\n");
        printk("  Continuing anyway (device scanning will be skipped)\n");
    } else {
        printk("PCIe BRCMSTB: Link up! (took %d ms)\n", (100 - timeout) * 10);

        /* 读取 RC 信息 */
        uint32_t vendor_dev =
            *(volatile uint32_t *)(base_virt + PCIE_EXT_CFG_PCIE_EXT_CFG_DATA);
        printk("PCIe BRCMSTB: RC Vendor:Device = 0x%04x:0x%04x\n",
               vendor_dev & 0xFFFF, vendor_dev >> 16);
    }

    brcmstb_pcie_context.initialized = true;
    return 0;
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

        // 使能 Bus Master, Memory Space, I/O Space
        uint32_t cmd =
            pci_device->op->read32(bus, device, function, segment, 0x04);
        cmd |= (1 << 2) | (1 << 1) | (1 << 0);
        pci_device->op->write32(bus, device, function, segment, 0x04, cmd);

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

        // 解析 BARs
        for (int i = 0; i < 6; i++) {
            uint32_t bar_offset = 0x10 + i * 4;
            uint32_t bar = pci_device->op->read32(bus, device, function,
                                                  segment, bar_offset);

            if (bar == 0) {
                continue;
            }

            if (bar & 0x1) {
                // I/O BAR
                pci_device->bars[i].address = bar & 0xFFFFFFFC;
                pci_device->bars[i].mmio = false;
            } else {
                // Memory BAR
                uint32_t type = (bar >> 1) & 0x3;

                if (type == 0x00) { // 32-bit
                    pci_device->bars[i].address = bar & 0xFFFFFFF0;
                    pci_device->bars[i].mmio = true;

                    // 读取大小
                    uint32_t orig = bar;
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset, 0xFFFFFFFF);
                    uint32_t size_mask = pci_device->op->read32(
                        bus, device, function, segment, bar_offset);
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset, orig);

                    pci_device->bars[i].size = ~(size_mask & 0xFFFFFFF0) + 1;

                } else if (type == 0x02) { // 64-bit
                    uint32_t bar_high = pci_device->op->read32(
                        bus, device, function, segment, bar_offset + 4);
                    uint64_t addr =
                        ((uint64_t)bar_high << 32) | (bar & 0xFFFFFFF0);
                    pci_device->bars[i].address = addr;
                    pci_device->bars[i].mmio = true;

                    // 读取大小
                    uint32_t orig_low = bar;
                    uint32_t orig_high = bar_high;

                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset, 0xFFFFFFFF);
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset + 4, 0xFFFFFFFF);

                    uint32_t size_low = pci_device->op->read32(
                        bus, device, function, segment, bar_offset);
                    uint32_t size_high = pci_device->op->read32(
                        bus, device, function, segment, bar_offset + 4);

                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset, orig_low);
                    pci_device->op->write32(bus, device, function, segment,
                                            bar_offset + 4, orig_high);

                    uint64_t size_mask =
                        ((uint64_t)size_high << 32) | (size_low & 0xFFFFFFF0);
                    pci_device->bars[i].size = ~size_mask + 1;

                    i++; // 64-bit BAR 占用两个 BAR 槽位
                }

                printk("  BAR%d: addr=0x%llx size=0x%llx %s\n", i,
                       pci_device->bars[i].address, pci_device->bars[i].size,
                       pci_device->bars[i].mmio ? "MEM" : "I/O");
            }
        }

        // 添加到设备列表
        pci_devices[pci_device_number++] = pci_device;
        break;
    }

    case 0x01: { // PCI-PCI Bridge
        printk("PCIe: Bridge device\n");

        uint32_t buses =
            pci_device->op->read32(bus, device, function, segment, 0x18);
        uint8_t secondary_bus = (buses >> 8) & 0xFF;
        uint8_t subordinate_bus = (buses >> 16) & 0xFF;

        printk("  Secondary bus: %d, Subordinate bus: %d\n", secondary_bus,
               subordinate_bus);

        // 递归扫描子总线
        for (uint8_t sub_bus = secondary_bus; sub_bus <= subordinate_bus;
             sub_bus++) {
            pcie_brcmstb_scan_bus(segment, sub_bus);
        }

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

    if (!brcmstb_link_up()) {
        printk("PCIe BRCMSTB: Link is down, no devices to scan\n");
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

    uint64_t pcie_base, pcie_size;
    uint64_t msi_base, msi_size;

    // 方法 1：通过 reg-names
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

    // 映射内存
    uint64_t pcie_virt = phys_to_virt(pcie_base);
    map_page_range(get_current_page_dir(false), pcie_virt, pcie_base, pcie_size,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE);

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
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE);

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

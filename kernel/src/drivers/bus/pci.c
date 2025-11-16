#include <mm/mm.h>
#include <drivers/kernel_logger.h>
#include <drivers/bus/pci.h>
#include <drivers/bus/pcie.h>
#include <libs/aether/pci.h>
#include <uacpi/acpi.h>
#include <uacpi/tables.h>

#if defined(__x86_64__) || defined(__aarch64__) || defined(__riscv__) ||       \
    defined(__loongarch64)
struct acpi_mcfg_allocation *mcfg_entries[PCI_MCFG_MAX_ENTRIES_LEN];
uint64_t mcfg_entries_len = 0;

void mcfg_addr_to_entries(struct acpi_mcfg *mcfg,
                          struct acpi_mcfg_allocation **entries,
                          uint64_t *num) {
    struct acpi_mcfg_allocation *entry =
        (struct acpi_mcfg_allocation *)((uint64_t)mcfg +
                                        sizeof(struct acpi_mcfg));
    int length = mcfg->hdr.length - sizeof(struct acpi_mcfg);
    *num = length / sizeof(struct acpi_mcfg_allocation);
    for (uint64_t i = 0; i < *num; i++) {
        entries[i] = entry + i;
    }
}

uint64_t get_device_mmio_physical_address(uint16_t segment_group, uint8_t bus,
                                          uint8_t device, uint8_t function) {
    for (uint64_t i = 0; i < mcfg_entries_len; i++) {
        if (mcfg_entries[i]->segment == segment_group) {
            return mcfg_entries[i]->address +
                   (((uint64_t)bus - (uint64_t)mcfg_entries[i]->start_bus)
                    << 20) +
                   ((uint64_t)device << 15) + ((uint64_t)function << 12);
        }
    }
    return 0;
}

uint64_t get_mmio_address(uint32_t pci_address, uint16_t offset) {
    uint16_t segment = (pci_address >> 16) & 0xFFFF;
    uint8_t bus = (pci_address >> 8) & 0xFF;
    uint8_t device = (pci_address >> 3) & 0x1F;
    uint8_t function = pci_address & 0x07;

    uint64_t phys =
        get_device_mmio_physical_address(segment, bus, device, function);
    if (phys == 0) {
        return 0;
    }
    uint64_t virt = phys_to_virt(phys);
    map_page_range(get_current_page_dir(false), virt, phys,
                   DEFAULT_PAGE_SIZE * 4, PT_FLAG_R | PT_FLAG_W);

    return virt + offset;
}

#else

uint64_t get_mmio_address(uint32_t pci_address, uint16_t offset) { return 0; }

#endif

uint32_t segment_bus_device_functon_to_pci_address(uint16_t segment,
                                                   uint8_t bus, uint8_t device,
                                                   uint8_t function) {
    return ((uint32_t)(segment & 0xFFFF) << 16) |
           ((uint32_t)(bus & 0xFF) << 8) | ((uint32_t)(device & 0x3F) << 3) |
           (uint32_t)(function & 0xF);
}

uint8_t pci_read8(uint32_t b, uint32_t d, uint32_t f, uint32_t s,
                  uint32_t offset) {
    uint32_t pci_address =
        segment_bus_device_functon_to_pci_address(s, b, d, f);
    uint64_t mmio_address = get_mmio_address(pci_address, offset);
    if (mmio_address == 0) {
        printk("Cannot read pci: failed to get mmio address\n");
    }
    return *(volatile uint8_t *)mmio_address;
}

void pci_write8(uint32_t b, uint32_t d, uint32_t f, uint32_t s, uint32_t offset,
                uint8_t value) {
    uint32_t pci_address =
        segment_bus_device_functon_to_pci_address(s, b, d, f);
    uint64_t mmio_address = get_mmio_address(pci_address, offset);
    if (mmio_address == 0) {
        printk("Cannot write pci: failed to get mmio address\n");
    }
    *(volatile uint8_t *)mmio_address = value;
}

uint16_t pci_read16(uint32_t b, uint32_t d, uint32_t f, uint32_t s,
                    uint32_t offset) {
    uint32_t pci_address =
        segment_bus_device_functon_to_pci_address(s, b, d, f);
    uint64_t mmio_address = get_mmio_address(pci_address, offset);
    if (mmio_address == 0) {
        printk("Cannot read pci: failed to get mmio address\n");
    }
    return *(volatile uint16_t *)mmio_address;
}

void pci_write16(uint32_t b, uint32_t d, uint32_t f, uint32_t s,
                 uint32_t offset, uint16_t value) {
    uint32_t pci_address =
        segment_bus_device_functon_to_pci_address(s, b, d, f);
    uint64_t mmio_address = get_mmio_address(pci_address, offset);
    if (mmio_address == 0) {
        printk("Cannot write pci: failed to get mmio address\n");
    }
    *(volatile uint16_t *)mmio_address = value;
}

uint32_t pci_read32(uint32_t b, uint32_t d, uint32_t f, uint32_t s,
                    uint32_t offset) {
    uint32_t pci_address =
        segment_bus_device_functon_to_pci_address(s, b, d, f);
    uint64_t mmio_address = get_mmio_address(pci_address, offset);
    if (mmio_address == 0) {
        printk("Cannot read pci: failed to get mmio address\n");
    }
    return *(volatile uint32_t *)mmio_address;
}

void pci_write32(uint32_t b, uint32_t d, uint32_t f, uint32_t s,
                 uint32_t offset, uint32_t value) {
    uint32_t pci_address =
        segment_bus_device_functon_to_pci_address(s, b, d, f);
    uint64_t mmio_address = get_mmio_address(pci_address, offset);
    if (mmio_address == 0) {
        printk("Cannot write pci: failed to get mmio address\n");
    }
    *(volatile uint32_t *)mmio_address = value;
}

uint32_t pci_enumerate_capability_list(pci_device_t *pci_dev,
                                       uint32_t cap_type) {
    uint32_t cap_offset;
    switch (pci_dev->header_type) {
    case 0x00:
        cap_offset = pci_dev->capability_point;
        break;
    case 0x10:
        cap_offset = pci_dev->capability_point;
        break;
    default:
        // 不支持
        return 0;
    }
    uint32_t tmp;
    while (1) {
        tmp = pci_dev->op->read32(pci_dev->bus, pci_dev->slot, pci_dev->func,
                                  pci_dev->segment, cap_offset);
        if ((tmp & 0xff) != cap_type) {
            if (((tmp & 0xff00) >> 8)) {
                cap_offset = (tmp & 0xff00) >> 8;
                continue;
            } else
                return 0;
        }

        return cap_offset;
    }
}

pci_device_op_t pcie_device_op = {
    .convert_bar_address = NULL,
    .read8 = pci_read8,
    .write8 = pci_write8,
    .read16 = pci_read16,
    .write16 = pci_write16,
    .read32 = pci_read32,
    .write32 = pci_write32,
};

struct {
    uint32_t classcode;
    const char *name;
} pci_classnames[] = {{0x000000, "Non-VGA-Compatible Unclassified Device"},
                      {0x000100, "VGA-Compatible Unclassified Device"},

                      {0x010000, "SCSI Bus Controller"},
                      {0x010100, "IDE Controller"},
                      {0x010200, "Floppy Disk Controller"},
                      {0x010300, "IPI Bus Controller"},
                      {0x010400, "RAID Controller"},
                      {0x010500, "ATA Controller"},
                      {0x010600, "Serial ATA Controller"},
                      {0x010700, "Serial Attached SCSI Controller"},
                      {0x010802, "NVM Express Controller"},
                      {0x018000, "Other Mass Storage Controller"},

                      {0x020000, "Ethernet Controller"},
                      {0x020100, "Token Ring Controller"},
                      {0x020200, "FDDI Controller"},
                      {0x020300, "ATM Controller"},
                      {0x020400, "ISDN Controller"},
                      {0x020500, "WorldFip Controller"},
                      {0x020600, "PICMG 2.14 Multi Computing Controller"},
                      {0x020700, "Infiniband Controller"},
                      {0x020800, "Fabric Controller"},
                      {0x028000, "Other Network Controller"},

                      {0x030000, "VGA Compatible Controller"},
                      {0x030100, "XGA Controller"},
                      {0x030200, "3D Controller (Not VGA-Compatible)"},
                      {0x038000, "Other Display Controller"},

                      {0x040000, "Multimedia Video Controller"},
                      {0x040100, "Multimedia Audio Controller"},
                      {0x040200, "Computer Telephony Device"},
                      {0x040300, "Audio Device"},
                      {0x048000, "Other Multimedia Controller"},

                      {0x050000, "RAM Controller"},
                      {0x050100, "Flash Controller"},
                      {0x058000, "Other Memory Controller"},

                      {0x060000, "Host Bridge"},
                      {0x060100, "ISA Bridge"},
                      {0x060200, "EISA Bridge"},
                      {0x060300, "MCA Bridge"},
                      {0x060400, "PCI-to-PCI Bridge"},
                      {0x060500, "PCMCIA Bridge"},
                      {0x060600, "NuBus Bridge"},
                      {0x060700, "CardBus Bridge"},
                      {0x060800, "RACEway Bridge"},
                      {0x060900, "PCI-to-PCI Bridge"},
                      {0x060A00, "InfiniBand-to-PCI Host Bridge"},
                      {0x068000, "Other Bridge"},

                      {0x070000, "Serial Controller"},
                      {0x070100, "Parallel Controller"},
                      {0x070200, "Multiport Serial Controller"},
                      {0x070300, "Modem"},
                      {0x070400, "IEEE 488.1/2 (GPIB) Controller"},
                      {0x070500, "Smart Card Controller"},
                      {0x078000, "Other Simple Communication Controller"},

                      {0x080000, "PIC"},
                      {0x080100, "DMA Controller"},
                      {0x080200, "Timer"},
                      {0x080300, "RTC Controller"},
                      {0x080400, "PCI Hot-Plug Controller"},
                      {0x080500, "SD Host controller"},
                      {0x080600, "IOMMU"},
                      {0x088000, "Other Base System Peripheral"},

                      {0x090000, "Keyboard Controller"},
                      {0x090100, "Digitizer Pen"},
                      {0x090200, "Mouse Controller"},
                      {0x090300, "Scanner Controller"},
                      {0x090400, "Gameport Controller"},
                      {0x098000, "Other Input Device Controller"},

                      {0x0A0000, "Generic"},
                      {0x0A8000, "Other Docking Station"},

                      {0x0B0000, "386"},
                      {0x0B0100, "486"},
                      {0x0B0200, "Pentium"},
                      {0x0B0300, "Pentium Pro"},
                      {0x0B1000, "Alpha"},
                      {0x0B2000, "PowerPC"},
                      {0x0B3000, "MIPS"},
                      {0x0B4000, "Co-Processor"},
                      {0x0B8000, "Other Processor"},

                      {0x0C0000, "FireWire (IEEE 1394) Controller"},
                      {0x0C0100, "ACCESS Bus Controller"},
                      {0x0C0200, "SSA"},
                      {0x0C0300, "USB Controller"},
                      {0x0C0400, "Fibre Channel"},
                      {0x0C0500, "SMBus Controller"},
                      {0x0C0600, "InfiniBand Controller"},
                      {0x0C0700, "IPMI Interface"},
                      {0x0C0800, "SERCOS Interface (IEC 61491)"},
                      {0x0C0900, "CANbus Controller"},
                      {0x0C8000, "Other Serial Bus Controller"},

                      {0x0D0000, "iRDA Compatible Controlle"},
                      {0x0D0100, "Consumer IR Controller"},
                      {0x0D1000, "RF Controller"},
                      {0x0D1100, "Bluetooth Controller"},
                      {0x0D1200, "Broadband Controller"},
                      {0x0D2000, "Ethernet Controller (802.1a)"},
                      {0x0D2100, "Ethernet Controller (802.1b)"},
                      {0x0D8000, "Other Wireless Controller"},

                      {0x0E0000, "I20"},

                      {0x0F0000, "Satellite TV Controller"},
                      {0x0F0100, "Satellite Audio Controller"},
                      {0x0F0300, "Satellite Voice Controller"},
                      {0x0F0400, "Satellite Data Controller"},

                      {0x100000, "Network and Computing Encrpytion/Decryption"},
                      {0x101000, "Entertainment Encryption/Decryption"},
                      {0x108000, "Other Encryption Controller"},

                      {0x110000, "DPIO Modules"},
                      {0x110100, "Performance Counters"},
                      {0x111000, "Communication Synchronizer"},
                      {0x112000, "Signal Processing Management"},
                      {0x118000, "Other Signal Processing Controller"},
                      {0x000000, (char *)NULL}};

pci_device_t *pci_devices[PCI_DEVICE_MAX];
uint32_t pci_device_number = 0;

const char *pci_classname(uint32_t classcode) {
    for (size_t i = 0; pci_classnames[i].name != NULL; i++) {
        if (pci_classnames[i].classcode == classcode) {
            return pci_classnames[i].name;
        }
        if (pci_classnames[i].classcode == (classcode & 0xFFFF00)) {
            return pci_classnames[i].name;
        }
    }
    return "Unknown device";
}

void pci_find_vid(pci_device_t **result, uint32_t *n, uint32_t vid) {
    int idx = 0;
    for (uint32_t i = 0; i < pci_device_number; i++) {
        if (pci_devices[i]->vendor_id == vid) {
            result[idx] = pci_devices[i];
            idx++;
            continue;
        }
    }
    *n = idx;
}

void pci_find_class(pci_device_t **result, uint32_t *n, uint32_t class_code) {
    int idx = 0;
    for (uint32_t i = 0; i < pci_device_number; i++) {
        if (pci_devices[i]->class_code == class_code) {
            result[idx] = pci_devices[i];
            idx++;
            continue;
        }
        if (class_code == (pci_devices[i]->class_code & 0xFFFF00)) {
            result[idx] = pci_devices[i];
            idx++;
            continue;
        }
    }
    *n = idx;
}

pci_device_t *pci_find_bdfs(uint8_t bus, uint8_t slot, uint8_t func,
                            uint16_t segment) {
    for (uint32_t i = 0; i < pci_device_number; i++) {
        if ((pci_devices[i]->bus == bus) && (pci_devices[i]->slot == slot) &&
            (pci_devices[i]->func == func) &&
            (pci_devices[i]->segment == segment)) {
            return pci_devices[i];
        }
    }
    return NULL;
}

void pci_scan_bus(pci_device_op_t *op, uint16_t segment_group, uint8_t bus);

void pci_scan_function(pci_device_op_t *op, uint16_t segment, uint8_t bus,
                       uint8_t device, uint8_t function) {
    // 读取 vendor ID
    uint16_t vendor_id = op->read16(bus, device, function, segment, 0x00);
    if (vendor_id == 0xFFFF || vendor_id == 0x0000) {
        return;
    }

    uint16_t device_id = op->read16(bus, device, function, segment, 0x02);

    // 读取 class code 和 revision
    uint32_t class_rev = op->read32(bus, device, function, segment, 0x08);
    uint8_t revision_id = class_rev & 0xFF;
    uint8_t prog_if = (class_rev >> 8) & 0xFF;
    uint8_t subclass = (class_rev >> 16) & 0xFF;
    uint8_t class_code = (class_rev >> 24) & 0xFF;

    // 读取 header type
    uint8_t header_type =
        op->read8(bus, device, function, segment, 0x0E) & 0x7F;

    // 创建设备结构
    pci_device_t *pci_device = (pci_device_t *)malloc(sizeof(pci_device_t));
    if (!pci_device) {
        printk("PCIe: Failed to allocate device structure\n");
        return;
    }
    memset(pci_device, 0, sizeof(pci_device_t));

    pci_device->header_type = header_type;
    pci_device->op = op;
    pci_device->revision_id = revision_id;
    pci_device->segment = segment;
    pci_device->bus = bus;
    pci_device->slot = device;
    pci_device->func = function;
    pci_device->vendor_id = vendor_id;
    pci_device->device_id = device_id;

    uint32_t class_code_24bit = (class_code << 16) | (subclass << 8) | prog_if;
    pci_device->class_code = class_code_24bit;
    pci_device->name = pci_classname(class_code_24bit);

    printk("PCIe: Found device %02x:%02x.%x - %04x:%04x %06x [%s]\n", bus,
           device, function, vendor_id, device_id, class_code_24bit,
           pci_device->name);

    switch (header_type) {
    case 0x00: { // Standard device (Endpoint)
        // 启用设备命令寄存器
        uint16_t command = op->read16(bus, device, function, segment, 0x04);
        command |= (1 << 0); // I/O Space Enable
        command |= (1 << 1); // Memory Space Enable
        command |= (1 << 2); // Bus Master Enable
        op->write16(bus, device, function, segment, 0x04, command);

        // 读取 subsystem ID
        uint32_t subsystem = op->read32(bus, device, function, segment, 0x2C);
        pci_device->subsystem_vendor_id = subsystem & 0xFFFF;
        pci_device->subsystem_device_id = (subsystem >> 16) & 0xFFFF;

        // 读取中断信息
        uint32_t interrupt = op->read32(bus, device, function, segment, 0x3C);
        pci_device->irq_line = interrupt & 0xFF;
        pci_device->irq_pin = (interrupt >> 8) & 0xFF;

        // 读取 capability pointer
        uint16_t status = op->read16(bus, device, function, segment, 0x06);
        if (status & (1 << 4)) { // Capabilities List present
            pci_device->capability_point =
                op->read8(bus, device, function, segment, 0x34) & 0xFC;
        }

        // 枚举 BARs
        for (int i = 0; i < 6; i++) {
            uint32_t offset = 0x10 + i * 4;
            uint32_t bar = op->read32(bus, device, function, segment, offset);

            if (bar == 0) {
                pci_device->bars[i].size = 0;
                pci_device->bars[i].address = 0;
                pci_device->bars[i].mmio = false;
                continue;
            }

            if (bar & 0x01) {
                // I/O Space BAR
                pci_device->bars[i].address = bar & 0xFFFFFFFC;
                pci_device->bars[i].mmio = false;

                // Probe size
                op->write32(bus, device, function, segment, offset, 0xFFFFFFFF);
                uint32_t size_mask =
                    op->read32(bus, device, function, segment, offset);
                op->write32(bus, device, function, segment, offset, bar);

                pci_device->bars[i].size = ~(size_mask & 0xFFFFFFFC) + 1;

                printk("  BAR%d: I/O at 0x%llx, size 0x%llx\n", i,
                       pci_device->bars[i].address, pci_device->bars[i].size);

            } else {
                // Memory Space BAR
                uint8_t mem_type = (bar >> 1) & 0x3;
                bool prefetchable = bar & (1 << 3);

                if (mem_type == 0x00) {
                    // 32-bit Memory BAR
                    uint64_t base = bar & 0xFFFFFFF0;

                    // Probe size
                    op->write32(bus, device, function, segment, offset,
                                0xFFFFFFFF);
                    uint32_t size_mask =
                        op->read32(bus, device, function, segment, offset);
                    op->write32(bus, device, function, segment, offset, bar);

                    uint64_t size = ~(size_mask & 0xFFFFFFF0) + 1;

                    if (op->convert_bar_address) {
                        base = op->convert_bar_address(base);
                    }
                    pci_device->bars[i].address = base;
                    pci_device->bars[i].size = size;
                    pci_device->bars[i].mmio = true;

                    printk("  BAR%d: 32-bit MMIO%s at 0x%llx, size 0x%llx\n", i,
                           prefetchable ? " (Prefetchable)" : "", base, size);

                } else if (mem_type == 0x02) {
                    // 64-bit Memory BAR
                    if (i >= 5) {
                        printk("  BAR%d: Invalid 64-bit BAR position\n", i);
                        break;
                    }

                    uint32_t bar_hi =
                        op->read32(bus, device, function, segment, offset + 4);
                    uint64_t base =
                        ((uint64_t)bar_hi << 32) | (bar & 0xFFFFFFF0);

                    // Probe size
                    uint32_t orig_lo = bar;
                    uint32_t orig_hi = bar_hi;

                    op->write32(bus, device, function, segment, offset,
                                0xFFFFFFFF);
                    op->write32(bus, device, function, segment, offset + 4,
                                0xFFFFFFFF);

                    uint32_t size_lo =
                        op->read32(bus, device, function, segment, offset);
                    uint32_t size_hi =
                        op->read32(bus, device, function, segment, offset + 4);

                    op->write32(bus, device, function, segment, offset,
                                orig_lo);
                    op->write32(bus, device, function, segment, offset + 4,
                                orig_hi);

                    uint64_t size_mask =
                        ((uint64_t)size_hi << 32) | (size_lo & 0xFFFFFFF0);
                    uint64_t size = ~size_mask + 1;

                    if (op->convert_bar_address) {
                        base = op->convert_bar_address(base);
                    }
                    pci_device->bars[i].address = base;
                    pci_device->bars[i].size = size;
                    pci_device->bars[i].mmio = true;

                    printk("  BAR%d: 64-bit MMIO%s at 0x%llx, size 0x%llx\n", i,
                           prefetchable ? " (Prefetchable)" : "", base, size);

                    // 64位BAR占用两个槽位
                    i++;
                    if (i < 6) {
                        pci_device->bars[i].address = 0;
                        pci_device->bars[i].size = 0;
                        pci_device->bars[i].mmio = true;
                    }
                }
            }
        }

        pcie_optimize_link(pci_device);

        // 添加到设备列表
        if (pci_device_number < PCI_DEVICE_MAX) {
            pci_devices[pci_device_number] = pci_device;
            pci_device_number++;
        } else {
            printk("PCIe: Device list full, dropping device\n");
            free(pci_device);
        }

        break;
    }

    case 0x01: { // PCI-to-PCI Bridge
        uint32_t buses = op->read32(bus, device, function, segment, 0x18);
        uint8_t primary_bus = buses & 0xFF;
        uint8_t secondary_bus = (buses >> 8) & 0xFF;
        uint8_t subordinate_bus = (buses >> 16) & 0xFF;

        printk("  PCI-PCI Bridge: Primary=%d, Secondary=%d, Subordinate=%d\n",
               primary_bus, secondary_bus, subordinate_bus);

        // 启用桥接器
        uint16_t bridge_ctrl = op->read16(bus, device, function, segment, 0x3E);
        bridge_ctrl &= ~(1 << 6); // Clear Secondary Bus Reset
        op->write16(bus, device, function, segment, 0x3E, bridge_ctrl);

        uint16_t command = op->read16(bus, device, function, segment, 0x04);
        command |= (1 << 0); // I/O Space Enable
        command |= (1 << 1); // Memory Space Enable
        command |= (1 << 2); // Bus Master Enable
        op->write16(bus, device, function, segment, 0x04, command);

        // 递归扫描次级总线范围
        if (secondary_bus != 0 && secondary_bus <= subordinate_bus) {
            for (uint8_t b = secondary_bus; b <= subordinate_bus; b++) {
                pci_scan_bus(op, segment, b);
            }
        }

        free(pci_device);
        break;
    }

    case 0x02: { // CardBus Bridge
        printk("  CardBus Bridge (not supported)\n");
        free(pci_device);
        break;
    }

    default:
        printk("  Unknown header type: 0x%02x\n", header_type);
        free(pci_device);
        break;
    }
}

static bool pci_function_exists(pci_device_op_t *op, uint16_t segment,
                                uint8_t bus, uint8_t slot, uint8_t func) {
    printk("PCIe: Probing device %02x:%02x.%x\n", bus, slot, func);

    uint16_t vendor = op->read16(bus, slot, func, segment, 0x00);

    // Vendor ID 必须有效
    if (vendor == 0xFFFF || vendor == 0x0000) {
        return false;
    }

    // 对于 function > 0，额外检查以防止误读
    if (func > 0) {
        // 读取 Device ID 确保不是全0xFF或全0x00
        uint16_t device = op->read16(bus, slot, func, segment, 0x02);
        if (device == 0xFFFF || device == 0x0000) {
            return false;
        }

        // 读取 class code 再次验证
        uint32_t class_rev = op->read32(bus, slot, func, segment, 0x08);
        if (class_rev == 0xFFFFFFFF || class_rev == 0x00000000) {
            return false;
        }
    }

    return true;
}

void pci_scan_slot(pci_device_op_t *op, uint16_t segment_group, uint8_t bus,
                   uint8_t slot) {
    // 先检查 function 0 是否存在
    if (!pci_function_exists(op, segment_group, bus, slot, 0)) {
        // Function 0 不存在，整个 slot 都不存在
        return;
    }

    // 扫描 function 0
    pci_scan_function(op, segment_group, bus, slot, 0);

    // 检查是否是多功能设备
    uint8_t header_type = op->read8(bus, slot, 0, segment_group, 0x0E);

    if (header_type != 0xFF && header_type & 0x80) {
        // 是多功能设备，逐个检查并扫描 function 1-7
        for (uint8_t func = 1; func < 8; func++) {
            if (pci_function_exists(op, segment_group, bus, slot, func)) {
                pci_scan_function(op, segment_group, bus, slot, func);
            }
        }
    }
}

void pci_scan_bus(pci_device_op_t *op, uint16_t segment_group, uint8_t bus) {
    // 扫描所有 32 个 slot
    for (uint8_t slot = 0; slot < 32; slot++) {
        pci_scan_slot(op, segment_group, bus, slot);
    }
}

void pci_scan_segment(pci_device_op_t *op, uint16_t segment_group) {
    pci_scan_bus(op, segment_group, 0);
}

extern pci_driver_t *pci_drivers[MAX_PCI_DRIVERS];

void pci_controller_init() {
    struct uacpi_table mcfg_table;
    uacpi_status status = uacpi_table_find_by_signature("MCFG", &mcfg_table);

    if (status == UACPI_STATUS_OK) {
        printk("Scanning PCIe bus\n");
        // Scan PCIe bus
        mcfg_addr_to_entries((struct acpi_mcfg *)mcfg_table.ptr, mcfg_entries,
                             &mcfg_entries_len);

        for (uint64_t i = 0; i < mcfg_entries_len; i++) {
            uint16_t segment_group = mcfg_entries[i]->segment;
            pci_scan_segment(&pcie_device_op, segment_group);
        }
    }
}

void pci_init() {
    for (uint64_t i = 0; i < pci_device_number; i++) {
        pci_device_t *device = pci_devices[i];

        for (uint64_t d = 0; d < MAX_PCI_DRIVERS; d++) {
            if (pci_drivers[d] && (pci_drivers[d]->flags == 0) &&
                ((pci_drivers[d]->class_id == device->class_code) ||
                 ((pci_drivers[d]->vendor_device_id & 0xFFFF0000) ==
                  ((uint32_t)device->vendor_id << 16)))) {
                int ret = pci_drivers[d]->probe(
                    device,
                    ((uint32_t)device->vendor_id << 16) | (device->device_id));
                if (ret < 0) {
                    printk("PCI driver %s probe failed!!!\n",
                           pci_drivers[d]->name);
                }
            }
        }
    }
}

void pci_init_after_sysfs() {
    for (uint64_t i = 0; i < pci_device_number; i++) {
        pci_device_t *device = pci_devices[i];

        for (uint64_t d = 0; d < MAX_PCI_DRIVERS; d++) {
            if (pci_drivers[d] &&
                (pci_drivers[d]->flags & PCI_DRIVER_FLAGS_NEED_SYSFS) &&
                ((pci_drivers[d]->class_id == device->class_code) ||
                 ((pci_drivers[d]->vendor_device_id & 0xFFFF0000) ==
                  ((uint32_t)device->vendor_id << 16)))) {
                int ret = pci_drivers[d]->probe(
                    device,
                    ((uint32_t)device->vendor_id << 16) | (device->device_id));
                if (ret < 0) {
                    printk("PCI driver %s probe failed!!!\n",
                           pci_drivers[d]->name);
                }
            }
        }
    }
}

void pci_init_after_mount_root() {
    for (uint64_t i = 0; i < pci_device_number; i++) {
        pci_device_t *device = pci_devices[i];

        for (uint64_t d = 0; d < MAX_PCI_DRIVERS; d++) {
            if (pci_drivers[d] &&
                (pci_drivers[d]->flags & PCI_DRIVER_FLAGS_NEED_ROOTFS) &&
                ((pci_drivers[d]->class_id == device->class_code) ||
                 ((pci_drivers[d]->vendor_device_id & 0xFFFF0000) ==
                  ((uint32_t)device->vendor_id << 16)))) {
                int ret = pci_drivers[d]->probe(
                    device,
                    ((uint32_t)device->vendor_id << 16) | (device->device_id));
                if (ret < 0) {
                    printk("PCI driver %s probe failed!!!\n",
                           pci_drivers[d]->name);
                }
            }
        }
    }
}

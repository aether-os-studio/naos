#include <drivers/bus/pci-dtb_ecam.h>

#ifndef __x86_64__

#include <drivers/fdt/fdt.h>
#include <drivers/logger.h>
#include <mm/mm.h>

#define PCI_DTB_ECAM_MAX_CONTROLLERS 16
#define PCI_DTB_ECAM_MAX_RANGES 64

typedef struct {
    uint32_t flags;
    uint64_t pci_addr;
    uint64_t cpu_addr;
    uint64_t size;
} pci_dtb_ecam_range_t;

typedef struct {
    bool initialized;
    uint16_t segment;
    uint8_t bus_start;
    uint8_t bus_end;
    uint64_t ecam_phys;
    uint64_t ecam_virt;
    uint64_t ecam_size;
    pci_dtb_ecam_range_t ranges[PCI_DTB_ECAM_MAX_RANGES];
    int range_count;
} pci_dtb_ecam_controller_t;

static pci_dtb_ecam_controller_t ecam_controllers[PCI_DTB_ECAM_MAX_CONTROLLERS];
static int ecam_controller_count = 0;

static uint64_t fdt_read_cells(const uint32_t **p, int cells) {
    uint64_t value = 0;

    if (cells <= 0 || cells > FDT_MAX_NCELLS)
        return 0;

    for (int i = 0; i < cells; i++) {
        value = (value << 32) | fdt32_ld(&(*p)[i]);
    }

    *p += cells;
    return value;
}

static uint64_t fdt_translate_address(const void *fdt, int node,
                                      uint64_t addr) {
    int parent = fdt_parent_offset(fdt, node);

    while (parent >= 0) {
        int len = 0;
        const uint32_t *ranges = fdt_getprop(fdt, parent, "ranges", &len);

        if (!ranges) {
            parent = fdt_parent_offset(fdt, parent);
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

        if (child_addr_cells <= 0 || child_addr_cells > FDT_MAX_NCELLS ||
            parent_addr_cells <= 0 || parent_addr_cells > FDT_MAX_NCELLS ||
            size_cells <= 0 || size_cells > FDT_MAX_NCELLS) {
            return addr;
        }

        int cells_per_entry = child_addr_cells + parent_addr_cells + size_cells;
        if (cells_per_entry <= 0)
            return addr;

        int entries = (len / (int)sizeof(uint32_t)) / cells_per_entry;
        const uint32_t *p = ranges;

        for (int i = 0; i < entries; i++) {
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

static int fdt_get_reg(const void *fdt, int node, uint64_t *addr,
                       uint64_t *size) {
    int len = 0;
    const uint32_t *reg = fdt_getprop(fdt, node, "reg", &len);

    if (!reg || len <= 0)
        return -EINVAL;

    int parent = fdt_parent_offset(fdt, node);
    int address_cells = (parent >= 0) ? fdt_address_cells(fdt, parent) : 2;
    int size_cells = (parent >= 0) ? fdt_size_cells(fdt, parent) : 2;

    if (address_cells <= 0 || address_cells > FDT_MAX_NCELLS ||
        size_cells <= 0 || size_cells > FDT_MAX_NCELLS) {
        return -EINVAL;
    }

    if (len < (address_cells + size_cells) * (int)sizeof(uint32_t))
        return -EINVAL;

    const uint32_t *p = reg;
    *addr = fdt_translate_address(fdt, node, fdt_read_cells(&p, address_cells));
    *size = fdt_read_cells(&p, size_cells);
    return 0;
}

static int pci_dtb_ecam_parse_ranges(const void *fdt, int node,
                                     pci_dtb_ecam_controller_t *controller) {
    int len = 0;
    const uint32_t *prop = fdt_getprop(fdt, node, "ranges", &len);
    if (!prop || len <= 0)
        return 0;

    int parent = fdt_parent_offset(fdt, node);
    int parent_addr_cells = (parent >= 0) ? fdt_address_cells(fdt, parent) : 2;
    int size_cells = fdt_size_cells(fdt, node);

    if (parent_addr_cells <= 0 || parent_addr_cells > FDT_MAX_NCELLS ||
        size_cells <= 0 || size_cells > FDT_MAX_NCELLS) {
        return -EINVAL;
    }

    int cells_per_entry = 3 + parent_addr_cells + size_cells;
    int total_cells = len / (int)sizeof(uint32_t);
    if (cells_per_entry <= 0 || total_cells < cells_per_entry)
        return 0;

    const uint32_t *p = prop;
    const uint32_t *end = prop + total_cells;
    int count = 0;

    while (p + cells_per_entry <= end && count < PCI_DTB_ECAM_MAX_RANGES) {
        uint32_t flags = fdt32_ld(p++);
        uint64_t pci_addr = fdt_read_cells(&p, 2);
        uint64_t cpu_addr = fdt_read_cells(&p, parent_addr_cells);
        uint64_t size = fdt_read_cells(&p, size_cells);

        controller->ranges[count].flags = flags;
        controller->ranges[count].pci_addr = pci_addr;
        controller->ranges[count].cpu_addr =
            fdt_translate_address(fdt, node, cpu_addr);
        controller->ranges[count].size = size;
        count++;
    }

    controller->range_count = count;
    return count;
}

static pci_dtb_ecam_controller_t *pci_dtb_ecam_find_controller(uint16_t segment,
                                                               uint8_t bus) {
    for (int i = 0; i < ecam_controller_count; i++) {
        pci_dtb_ecam_controller_t *controller = &ecam_controllers[i];
        if (!controller->initialized)
            continue;

        if (controller->segment == segment && bus >= controller->bus_start &&
            bus <= controller->bus_end) {
            return controller;
        }
    }

    return NULL;
}

static uint64_t pci_dtb_ecam_config_address(uint32_t bus, uint32_t slot,
                                            uint32_t func, uint32_t segment,
                                            uint32_t offset) {
    pci_dtb_ecam_controller_t *controller =
        pci_dtb_ecam_find_controller(segment, bus);

    if (!controller || slot > 31 || func > 7 || offset >= 0x1000)
        return 0;

    return controller->ecam_virt +
           (((uint64_t)bus - controller->bus_start) << 20) +
           ((uint64_t)slot << 15) + ((uint64_t)func << 12) + offset;
}

static uint8_t pci_dtb_ecam_read8(uint32_t bus, uint32_t slot, uint32_t func,
                                  uint32_t segment, uint32_t offset) {
    uint64_t addr =
        pci_dtb_ecam_config_address(bus, slot, func, segment, offset);
    return addr ? *(volatile uint8_t *)addr : 0xff;
}

static void pci_dtb_ecam_write8(uint32_t bus, uint32_t slot, uint32_t func,
                                uint32_t segment, uint32_t offset,
                                uint8_t value) {
    uint64_t addr =
        pci_dtb_ecam_config_address(bus, slot, func, segment, offset);
    if (addr)
        *(volatile uint8_t *)addr = value;
}

static uint16_t pci_dtb_ecam_read16(uint32_t bus, uint32_t slot, uint32_t func,
                                    uint32_t segment, uint32_t offset) {
    uint64_t addr =
        pci_dtb_ecam_config_address(bus, slot, func, segment, offset);
    return addr ? *(volatile uint16_t *)addr : 0xffff;
}

static void pci_dtb_ecam_write16(uint32_t bus, uint32_t slot, uint32_t func,
                                 uint32_t segment, uint32_t offset,
                                 uint16_t value) {
    uint64_t addr =
        pci_dtb_ecam_config_address(bus, slot, func, segment, offset);
    if (addr)
        *(volatile uint16_t *)addr = value;
}

static uint32_t pci_dtb_ecam_read32(uint32_t bus, uint32_t slot, uint32_t func,
                                    uint32_t segment, uint32_t offset) {
    uint64_t addr =
        pci_dtb_ecam_config_address(bus, slot, func, segment, offset);
    return addr ? *(volatile uint32_t *)addr : 0xffffffff;
}

static void pci_dtb_ecam_write32(uint32_t bus, uint32_t slot, uint32_t func,
                                 uint32_t segment, uint32_t offset,
                                 uint32_t value) {
    uint64_t addr =
        pci_dtb_ecam_config_address(bus, slot, func, segment, offset);
    if (addr)
        *(volatile uint32_t *)addr = value;
}

static uint64_t pci_dtb_ecam_convert_bar_address(uint64_t pci_addr) {
    for (int i = 0; i < ecam_controller_count; i++) {
        pci_dtb_ecam_controller_t *controller = &ecam_controllers[i];
        if (!controller->initialized)
            continue;

        for (int j = 0; j < controller->range_count; j++) {
            pci_dtb_ecam_range_t *range = &controller->ranges[j];
            uint32_t space_code = (range->flags >> 24) & 0x3;

            if (space_code != 0x2 && space_code != 0x3)
                continue;

            if (pci_addr >= range->pci_addr &&
                pci_addr < range->pci_addr + range->size) {
                return range->cpu_addr + (pci_addr - range->pci_addr);
            }
        }
    }

    printk("PCI DTB ECAM: no range for BAR 0x%llx, using 1:1\n", pci_addr);
    return pci_addr;
}

static pci_device_op_t pci_dtb_ecam_device_op = {
    .convert_bar_address = pci_dtb_ecam_convert_bar_address,
    .read8 = pci_dtb_ecam_read8,
    .write8 = pci_dtb_ecam_write8,
    .read16 = pci_dtb_ecam_read16,
    .write16 = pci_dtb_ecam_write16,
    .read32 = pci_dtb_ecam_read32,
    .write32 = pci_dtb_ecam_write32,
};

static int pci_dtb_ecam_probe(fdt_device_t *dev, const char *compatible) {
    if (ecam_controller_count >= PCI_DTB_ECAM_MAX_CONTROLLERS)
        return -ENOMEM;

    void *fdt = dev->fdt;
    int node = dev->node;
    pci_dtb_ecam_controller_t *controller =
        &ecam_controllers[ecam_controller_count];
    memset(controller, 0, sizeof(*controller));

    int len = 0;
    const uint32_t *bus_range = fdt_getprop(fdt, node, "bus-range", &len);
    if (bus_range && len >= 2 * (int)sizeof(uint32_t)) {
        controller->bus_start = (uint8_t)fdt32_ld(&bus_range[0]);
        controller->bus_end = (uint8_t)fdt32_ld(&bus_range[1]);
    } else {
        controller->bus_start = 0;
        controller->bus_end = 0xff;
    }

    const uint32_t *domain = fdt_getprop(fdt, node, "linux,pci-domain", &len);
    controller->segment =
        (domain && len >= (int)sizeof(uint32_t)) ? fdt32_ld(domain) : 0;

    if (fdt_get_reg(fdt, node, &controller->ecam_phys,
                    &controller->ecam_size) != 0 ||
        !controller->ecam_size) {
        printk("PCI DTB ECAM: missing reg property\n");
        return -EINVAL;
    }

    if (pci_dtb_ecam_parse_ranges(fdt, node, controller) < 0) {
        printk("PCI DTB ECAM: invalid ranges property\n");
        return -EINVAL;
    }

    uint64_t map_phys = PADDING_DOWN(controller->ecam_phys, PAGE_SIZE);
    uint64_t map_end =
        PADDING_UP(controller->ecam_phys + controller->ecam_size, PAGE_SIZE);
    uint64_t map_size = map_end - map_phys;
    uint64_t map_virt = (uint64_t)phys_to_virt(map_phys);

    if (!map_virt)
        return -EINVAL;

    if (map_page_range(get_current_page_dir(false), map_virt, map_phys,
                       map_size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE) != 0) {
        printk("PCI DTB ECAM: failed to map ECAM at 0x%llx\n",
               controller->ecam_phys);
        return -ENOMEM;
    }

    controller->ecam_virt = map_virt + (controller->ecam_phys - map_phys);
    controller->initialized = true;
    ecam_controller_count++;

    printk("PCI DTB ECAM: segment %u, bus %u-%u, ECAM 0x%llx size 0x%llx\n",
           controller->segment, controller->bus_start, controller->bus_end,
           controller->ecam_phys, controller->ecam_size);

    pci_scan_bus(&pci_dtb_ecam_device_op, controller->segment,
                 controller->bus_start);

    return 0;
}

static const char *pci_dtb_ecam_compatible[] = {
    "pci-host-ecam-generic",
    "pci-host-cam-generic",
    NULL,
};

static fdt_driver_t pci_dtb_ecam_generic_driver = {
    .name = "pci-dtb-ecam-generic",
    .compatible = pci_dtb_ecam_compatible,
    .probe = pci_dtb_ecam_probe,
};

void pci_dtb_ecam_init() { regist_fdt_driver(&pci_dtb_ecam_generic_driver); }

#endif

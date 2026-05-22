#include <drivers/fdt/syscon_poweroff.h>

#include <drivers/fdt/fdt.h>
#include <drivers/logger.h>
#include <mm/mm.h>
#include <mm/page_table_flags.h>

#if !defined(__x86_64__)

typedef struct syscon_poweroff_device {
    volatile uint8_t *base;
    uint64_t size;
    uint32_t offset;
    uint32_t value;
    uint32_t reg_io_width;
    uint32_t reg_shift;
} syscon_poweroff_device_t;

static syscon_poweroff_device_t *syscon_poweroff_dev;

static int fdt_read_u32_prop(const void *fdt, int node, const char *name,
                             uint32_t *value) {
    int len = 0;
    const fdt32_t *prop = fdt_getprop(fdt, node, name, &len);
    if (!prop || len < (int)sizeof(*prop))
        return -EINVAL;

    *value = fdt32_to_cpu(*prop);
    return 0;
}

static uint64_t fdt_read_cells(const fdt32_t **cells, int count) {
    uint64_t value = 0;
    for (int i = 0; i < count; i++)
        value = (value << 32) | fdt32_to_cpu(*((*cells)++));
    return value;
}

static int fdt_read_reg(const void *fdt, int node, uint64_t *addr,
                        uint64_t *size) {
    int parent = fdt_parent_offset(fdt, node);
    if (parent < 0)
        return parent;

    int address_cells = fdt_address_cells(fdt, parent);
    int size_cells = fdt_size_cells(fdt, parent);
    if (address_cells < 0)
        address_cells = 2;
    if (size_cells < 0)
        size_cells = 1;
    if (address_cells <= 0 || address_cells > 2 || size_cells < 0 ||
        size_cells > 2) {
        return -EINVAL;
    }

    int len = 0;
    const fdt32_t *reg = fdt_getprop(fdt, node, "reg", &len);
    int needed = (address_cells + size_cells) * (int)sizeof(fdt32_t);
    if (!reg || len < needed)
        return -EINVAL;

    const fdt32_t *cells = reg;
    *addr = fdt_read_cells(&cells, address_cells);
    *size = fdt_read_cells(&cells, size_cells);
    return 0;
}

static int syscon_poweroff_probe(fdt_device_t *dev, const char *compatible) {
    (void)compatible;

    if (syscon_poweroff_dev)
        return -EEXIST;

    uint32_t regmap = 0;
    uint32_t offset = 0;
    uint32_t value = 0;
    if (fdt_read_u32_prop(dev->fdt, dev->node, "regmap", &regmap) != 0 ||
        fdt_read_u32_prop(dev->fdt, dev->node, "offset", &offset) != 0 ||
        fdt_read_u32_prop(dev->fdt, dev->node, "value", &value) != 0) {
        return -EINVAL;
    }

    int syscon_node = fdt_node_offset_by_phandle(dev->fdt, regmap);
    if (syscon_node < 0)
        return -EINVAL;

    uint64_t phys = 0;
    uint64_t size = 0;
    if (fdt_read_reg(dev->fdt, syscon_node, &phys, &size) != 0 || size == 0)
        return -EINVAL;

    uint32_t reg_io_width = 4;
    uint32_t reg_shift = 0;
    fdt_read_u32_prop(dev->fdt, syscon_node, "reg-io-width", &reg_io_width);
    fdt_read_u32_prop(dev->fdt, syscon_node, "reg-shift", &reg_shift);
    if (reg_io_width != 1 && reg_io_width != 2 && reg_io_width != 4 &&
        reg_io_width != 8) {
        return -EINVAL;
    }

    uint64_t phys_base = PADDING_DOWN(phys, PAGE_SIZE);
    uint64_t phys_end = PADDING_UP(phys + size, PAGE_SIZE);
    uint64_t virt_base = (uint64_t)phys_to_virt(phys_base);
    if (!virt_base)
        return -EINVAL;

    if (map_page_range(get_current_page_dir(false), virt_base, phys_base,
                       phys_end - phys_base,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE) != 0) {
        return -ENOMEM;
    }

    syscon_poweroff_device_t *poweroff =
        malloc(sizeof(syscon_poweroff_device_t));
    if (!poweroff)
        return -ENOMEM;

    poweroff->base = (volatile uint8_t *)(virt_base + (phys - phys_base));
    poweroff->size = size;
    poweroff->offset = offset;
    poweroff->value = value;
    poweroff->reg_io_width = reg_io_width;
    poweroff->reg_shift = reg_shift;
    syscon_poweroff_dev = poweroff;
    dev->driver_data = poweroff;

    printk("syscon-poweroff: reg=0x%llx size=0x%llx offset=0x%x value=0x%x\n",
           phys, size, offset, value);
    return 0;
}

static void syscon_poweroff_remove(fdt_device_t *dev) {
    syscon_poweroff_device_t *poweroff = dev->driver_data;
    if (poweroff && poweroff == syscon_poweroff_dev)
        syscon_poweroff_dev = NULL;
    free(poweroff);
    dev->driver_data = NULL;
}

void syscon_poweroff_shutdown(void) {
    syscon_poweroff_device_t *poweroff = syscon_poweroff_dev;
    if (!poweroff)
        return;

    uint64_t reg_offset = ((uint64_t)poweroff->offset) << poweroff->reg_shift;
    if (reg_offset + poweroff->reg_io_width > poweroff->size)
        return;

    volatile uint8_t *reg = poweroff->base + reg_offset;
    switch (poweroff->reg_io_width) {
    case 1:
        *(volatile uint8_t *)reg = (uint8_t)poweroff->value;
        break;
    case 2:
        *(volatile uint16_t *)reg = (uint16_t)poweroff->value;
        break;
    case 4:
        *(volatile uint32_t *)reg = poweroff->value;
        break;
    case 8:
        *(volatile uint64_t *)reg = poweroff->value;
        break;
    }
}

static const char *syscon_poweroff_compatible[] = {
    "syscon-poweroff",
    NULL,
};

static fdt_driver_t syscon_poweroff_driver = {
    .name = "syscon-poweroff",
    .compatible = syscon_poweroff_compatible,
    .probe = syscon_poweroff_probe,
    .remove = syscon_poweroff_remove,
};

void syscon_poweroff_init(void) { regist_fdt_driver(&syscon_poweroff_driver); }

#endif

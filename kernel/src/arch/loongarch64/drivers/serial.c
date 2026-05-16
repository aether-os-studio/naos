#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>
#include <arch/loongarch64/drivers/serial.h>
#include <boot/boot.h>
#include <libs/fdt/libfdt.h>
#include <libs/klibc.h>
#include <mm/mm.h>

#define UART_RBR 0
#define UART_THR 0
#define UART_LSR 5

#define UART_LSR_DR 0x01
#define UART_LSR_THRE 0x20

#define DT_PATH_MAX 256

static volatile uint8_t *uart0 = NULL;
static uint32_t uart_reg_shift = 0;
static uint32_t uart_reg_io_width = 1;

bool serial_initialized = false;

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

static uint64_t fdt_translate_address(const void *fdt, int node_offset,
                                      uint64_t addr) {
    int parent = fdt_parent_offset(fdt, node_offset);

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

        if (child_addr_cells < 0 || child_addr_cells > FDT_MAX_NCELLS ||
            parent_addr_cells < 0 || parent_addr_cells > FDT_MAX_NCELLS ||
            size_cells < 0 || size_cells > FDT_MAX_NCELLS) {
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

static int fdt_get_reg(const void *fdt, int node_offset, int index,
                       uint64_t *addr, uint64_t *size) {
    int len = 0;
    const uint32_t *reg = fdt_getprop(fdt, node_offset, "reg", &len);

    if (!reg || len <= 0)
        return -1;

    int parent = fdt_parent_offset(fdt, node_offset);
    int address_cells = (parent >= 0) ? fdt_address_cells(fdt, parent) : 2;
    int size_cells = (parent >= 0) ? fdt_size_cells(fdt, parent) : 2;

    if (address_cells <= 0 || address_cells > FDT_MAX_NCELLS ||
        size_cells < 0 || size_cells > FDT_MAX_NCELLS) {
        return -1;
    }

    int cells_per_entry = address_cells + size_cells;
    if (cells_per_entry <= 0)
        return -1;

    int total_cells = len / (int)sizeof(uint32_t);
    int total_entries = total_cells / cells_per_entry;
    if (index < 0 || index >= total_entries)
        return -1;

    const uint32_t *p = reg + (index * cells_per_entry);
    *addr = fdt_translate_address(fdt, node_offset,
                                  fdt_read_cells(&p, address_cells));
    *size = fdt_read_cells(&p, size_cells);
    return 0;
}

static int fdt_get_u32(const void *fdt, int node_offset, const char *name,
                       uint32_t *value) {
    int len = 0;
    const uint32_t *prop = fdt_getprop(fdt, node_offset, name, &len);

    if (!prop || len < (int)sizeof(uint32_t))
        return -1;

    *value = fdt32_ld(prop);
    return 0;
}

static int map_serial_mmio(uint64_t phys, uint64_t size,
                           volatile uint8_t **out) {
    if (!phys || !size || !out)
        return -1;

    uint64_t phys_base = PADDING_DOWN(phys, PAGE_SIZE);
    uint64_t phys_end = PADDING_UP(phys + size, PAGE_SIZE);
    uint64_t map_size = phys_end - phys_base;
    uint64_t virt_base = (uint64_t)phys_to_virt(phys_base);

    if (!virt_base)
        return -1;

    if (map_page_range(get_current_page_dir(false), virt_base, phys_base,
                       map_size,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE) != 0) {
        return -1;
    }

    *out = (volatile uint8_t *)(virt_base + (phys - phys_base));
    return 0;
}

static const char *fdt_stdout_path(const void *fdt, char *buffer,
                                   size_t buflen) {
    int chosen = fdt_path_offset(fdt, "/chosen");
    if (chosen < 0 || buflen == 0)
        return NULL;

    int len = 0;
    const char *stdout_path = fdt_getprop(fdt, chosen, "stdout-path", &len);
    if (!stdout_path || len <= 1)
        stdout_path = fdt_getprop(fdt, chosen, "linux,stdout-path", &len);
    if (!stdout_path || len <= 1)
        return NULL;

    size_t copy_len = MIN((size_t)len, buflen - 1);
    size_t actual_len = 0;
    while (actual_len < copy_len && stdout_path[actual_len] != '\0' &&
           stdout_path[actual_len] != ':') {
        buffer[actual_len] = stdout_path[actual_len];
        actual_len++;
    }
    buffer[actual_len] = '\0';

    return actual_len ? buffer : NULL;
}

static int fdt_resolve_stdout_node(const void *fdt) {
    char stdout_path[DT_PATH_MAX];
    const char *path = fdt_stdout_path(fdt, stdout_path, sizeof(stdout_path));
    if (!path)
        return -1;

    if (path[0] == '/')
        return fdt_path_offset(fdt, path);

    const char *alias_path = fdt_get_alias(fdt, path);
    if (!alias_path)
        return -1;

    return fdt_path_offset(fdt, alias_path);
}

static bool dtb_node_is_16550(const void *fdt, int node_offset) {
    return fdt_node_check_compatible(fdt, node_offset, "ns16550a") == 0 ||
           fdt_node_check_compatible(fdt, node_offset, "ns16550") == 0 ||
           fdt_node_check_compatible(fdt, node_offset, "ns16550-compatible") ==
               0 ||
           fdt_node_check_compatible(fdt, node_offset, "loongson,ls7a-uart") ==
               0 ||
           fdt_node_check_compatible(fdt, node_offset, "snps,dw-apb-uart") == 0;
}

static int fdt_find_16550_node(const void *fdt) {
    int node = fdt_resolve_stdout_node(fdt);
    if (node >= 0 && dtb_node_is_16550(fdt, node))
        return node;

    for (node = fdt_next_node(fdt, -1, NULL); node >= 0;
         node = fdt_next_node(fdt, node, NULL)) {
        if (dtb_node_is_16550(fdt, node))
            return node;
    }

    return -1;
}

static int init_serial_from_dtb(void) {
    const void *fdt = (const void *)boot_get_dtb();
    if (!fdt || fdt_check_header(fdt) != 0)
        return -1;

    int node = fdt_find_16550_node(fdt);
    if (node < 0)
        return -1;

    uint64_t phys = 0;
    uint64_t size = 0;
    if (fdt_get_reg(fdt, node, 0, &phys, &size) != 0)
        return -1;

    uint32_t reg_shift = 0;
    uint32_t reg_io_width = 1;
    (void)fdt_get_u32(fdt, node, "reg-shift", &reg_shift);
    (void)fdt_get_u32(fdt, node, "reg-io-width", &reg_io_width);

    if (reg_io_width != 1 && reg_io_width != 4)
        reg_io_width = 1;
    if (!size)
        size = PAGE_SIZE;

    if (map_serial_mmio(phys, size, &uart0) != 0)
        return -1;

    uart_reg_shift = reg_shift;
    uart_reg_io_width = reg_io_width;
    return 0;
}

static int init_serial_from_acpi(void) {
    struct uacpi_table spcr_table;
    uacpi_status status = uacpi_table_find_by_signature("SPCR", &spcr_table);
    if (status != UACPI_STATUS_OK)
        return -1;

    struct acpi_spcr *spcr = spcr_table.ptr;
    if (!spcr)
        return -1;

    if ((spcr->interface_type != ACPI_DBG2_SUBTYPE_SERIAL_NS16550 &&
         spcr->interface_type != ACPI_DBG2_SUBTYPE_SERIAL_NS16550_DBGP1 &&
         spcr->interface_type != ACPI_DBG2_SUBTYPE_SERIAL_NS16550_NVIDIA &&
         spcr->interface_type != ACPI_DBG2_SUBTYPE_SERIAL_NS16550_GAS) ||
        spcr->base_address.address_space_id != ACPI_AS_ID_SYS_MEM ||
        spcr->base_address.address == 0) {
        return -1;
    }

    uint64_t size =
        spcr->base_address.register_bit_width
            ? (uint64_t)((spcr->base_address.register_bit_width + 7) / 8)
            : PAGE_SIZE;
    if (size < 8)
        size = 8;

    if (map_serial_mmio(spcr->base_address.address, size, &uart0) != 0)
        return -1;

    uart_reg_shift = 0;
    uart_reg_io_width =
        (spcr->base_address.access_size == ACPI_ACCESS_DWORD) ? 4 : 1;
    return 0;
}

static inline uint64_t uart_reg_offset(uint32_t reg) {
    return ((uint64_t)reg) << uart_reg_shift;
}

static uint8_t uart_read_reg(uint32_t reg) {
    uint64_t offset = uart_reg_offset(reg);

    if (uart_reg_io_width == 4)
        return (uint8_t)*(volatile uint32_t *)(uart0 + offset);

    return uart0[offset];
}

static void uart_write_reg(uint32_t reg, uint8_t value) {
    uint64_t offset = uart_reg_offset(reg);

    if (uart_reg_io_width == 4) {
        *(volatile uint32_t *)(uart0 + offset) = value;
        return;
    }

    uart0[offset] = value;
}

int init_serial() {
    uart0 = NULL;
    uart_reg_shift = 0;
    uart_reg_io_width = 1;

    if (init_serial_from_acpi() != 0 && init_serial_from_dtb() != 0) {
        serial_initialized = false;
        return -1;
    }

    serial_initialized = (uart0 != NULL);
    return serial_initialized ? 0 : -1;
}

char read_serial() {
    if (!serial_initialized)
        return 0;
    if ((uart_read_reg(UART_LSR) & UART_LSR_DR) == 0)
        return 0;
    return (char)uart_read_reg(UART_RBR);
}

void write_serial(char ch) {
    if (!serial_initialized)
        return;
    while ((uart_read_reg(UART_LSR) & UART_LSR_THRE) == 0)
        arch_pause();
    uart_write_reg(UART_THR, (uint8_t)ch);
}

void serial_printk(const char *buf, int len) {
    if (!serial_initialized || !buf || len <= 0)
        return;

    for (int i = 0; i < len; i++) {
        if (buf[i] == '\n')
            write_serial('\r');
        write_serial(buf[i]);
    }
}

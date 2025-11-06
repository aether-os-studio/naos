#include <arch/arch.h>
#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>
#include <arch/riscv64/drivers/ns16550.h>

bool serial_initialized = false;

uart_device_t uart0;
uart_config_t config;

int init_serial() {
    struct uacpi_table spcr_table;
    uacpi_status status = uacpi_table_find_by_signature("SPCR", &spcr_table);
    if (status == UACPI_STATUS_OK) {
        struct acpi_spcr *spcr = spcr_table.ptr;
        uint64_t virt = phys_to_virt(spcr->base_address.address);
        map_page_range(get_current_page_dir(false), virt,
                       spcr->base_address.address, DEFAULT_PAGE_SIZE,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE |
                           PT_FLAG_UNCACHEABLE);
        switch (spcr->interface_type) {
        case ACPI_DBG2_SUBTYPE_SERIAL_NS16550_GAS:
            uart_init(&uart0, (volatile void *)virt, NULL);
        default:
            break;
        }

        serial_initialized = true;
        return 0;
    } else {
        // todo: fdt
        return 0;
    }
}

char read_serial() {
    if (!serial_initialized)
        return 0;
    return 0;
}

void write_serial(char a) {
    if (!serial_initialized)
        return;
    uart_putc(&uart0, a);
}

void serial_printk(char *buf, int len) {
    for (int i = 0; i < len; i++) {
        if (buf[i] == '\n')
            write_serial('\r');
        write_serial(buf[i]);
    }
}

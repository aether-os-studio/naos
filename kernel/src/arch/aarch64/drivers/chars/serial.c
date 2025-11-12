#include <arch/aarch64/drivers/chars/serial.h>
#include <arch/aarch64/drivers/chars/pl011.h>
#include <mm/mm.h>
#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>

bool serial_initialized = false;

pl011_dev_t uart0 = {0};

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
        case ACPI_DBG2_SUBTYPE_SERIAL_PL011:
            uart_baudrate_t baudrate;
            switch (spcr->configured_baud_rate) {
            case 3:
                baudrate = BAUD_9600;
                break;
            case 4:
                baudrate = BAUD_19200;
                break;
            case 6:
                baudrate = BAUD_57600;
                break;
            case 7:
                baudrate = BAUD_115200;
                break;
            default:
                baudrate = BAUD_115200;
                break;
            }
            uart_config_t config = {
                .baudrate = baudrate,
                .data_bits = 8,
                .stop_bits = (spcr->stop_bits == 1) ? STOP_BITS_1 : STOP_BITS_1,
                .parity = PARITY_NONE,
                .fifo_enable = true};

            int ret = pl011_init(&uart0, (void *)virt,
                                 spcr->uart_clock_frequency, &config);
            if (ret)
                return -1;
        default:
            break;
        }

        serial_initialized = true;
        return 0;
    }
    return -1;
}

char read_serial() {
    if (serial_initialized) {
        char c;
        pl011_read(&uart0, (uint8_t *)&c, 1);
        return c;
    }
    return 0;
}

void write_serial(char a) {
    if (serial_initialized)
        pl011_write(&uart0, (const uint8_t *)&a, 1);
}

void serial_printk(char *buf, int len) {
    for (int i = 0; i < len; i++) {
        if (buf[i] == '\n')
            write_serial('\r');
        write_serial(buf[i]);
    }
}
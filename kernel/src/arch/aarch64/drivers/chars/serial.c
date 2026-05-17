#include <arch/aarch64/drivers/chars/serial.h>
#include <arch/aarch64/drivers/chars/pl011.h>
#include <mm/mm.h>
#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>

pl011_dev_t uart0 = {0};

static bool aarch64_serial_can_read(serial_driver_t *driver);
static bool aarch64_serial_read(serial_driver_t *driver, char *ch);
static void aarch64_serial_write(serial_driver_t *driver, char ch);

static serial_driver_t aarch64_serial_driver = {
    .name = "aarch64-pl011",
    .private_data = &uart0,
    .can_read = aarch64_serial_can_read,
    .read = aarch64_serial_read,
    .write = aarch64_serial_write,
};

int init_serial() {
    struct uacpi_table spcr_table;
    uacpi_status status = uacpi_table_find_by_signature("SPCR", &spcr_table);
    if (status == UACPI_STATUS_OK) {
        struct acpi_spcr *spcr = spcr_table.ptr;
        uint64_t virt = (uint64_t)phys_to_virt(spcr->base_address.address);
        map_page_range(get_current_page_dir(false), virt,
                       spcr->base_address.address, PAGE_SIZE,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE);
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

            return serial_register_driver(&aarch64_serial_driver);
        default:
            break;
        }

        return 0;
    }
    return -1;
}

static bool aarch64_serial_can_read(serial_driver_t *driver) {
    pl011_dev_t *dev = driver->private_data;
    return pl011_rx_ready(dev);
}

static bool aarch64_serial_read(serial_driver_t *driver, char *ch) {
    pl011_dev_t *dev = driver->private_data;

    if (!pl011_getc_nonblock(dev, ch))
        return false;

    return true;
}

static void aarch64_serial_write(serial_driver_t *driver, char ch) {
    pl011_dev_t *dev = driver->private_data;
    pl011_write(dev, (const uint8_t *)&ch, 1);
}

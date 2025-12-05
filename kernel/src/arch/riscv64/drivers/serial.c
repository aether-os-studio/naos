#include <arch/arch.h>
#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>
#include <arch/riscv64/drivers/ns16550.h>
#include <drivers/fdt/fdt.h>
#include <boot/boot.h>

bool serial_initialized = false;

uart_device_t uart0;
uart_config_t config;

static const char *serial_compatibles[] = {
    "ns16550a", "snps,dw-apb-uart", "sifive,uart0", "riscv,uart0", "uart0",
    NULL,
};

struct fdt_serial_device {
    uint64_t base_addr;
    uint32_t irq_num;
    uint32_t reg_shift;
    uint32_t clock_freq;
    uint32_t reg_io_width;
    int found;
};

static int find_serial_by_chosen(struct fdt_serial_device *device) {
    if (boot_get_dtb()) {
        int chosen_off = fdt_path_offset((void *)boot_get_dtb(), "/chosen");
        if (chosen_off < 0)
            return -ENODEV;
        int len = 0;
        const char *stdout_path = fdt_getprop((void *)boot_get_dtb(),
                                              chosen_off, "stdout-path", &len);
        if (!stdout_path || len <= 0)
            return -ENODEV;
        char path_buf[128];

        const char *colon = strchr(stdout_path, ':');
        size_t path_len =
            colon ? (size_t)(colon - stdout_path) : strlen(stdout_path);
        if (path_len >= sizeof(path_buf))
            return -ENAMETOOLONG;
        memcpy(path_buf, stdout_path, path_len);
        path_buf[path_len] = '\0';

        int serial_off = fdt_path_offset((void *)boot_get_dtb(), path_buf);
        if (serial_off < 0)
            return -ENODEV;

        const uint64_t *reg =
            fdt_getprop((void *)boot_get_dtb(), serial_off, "reg", &len);
        if (reg && len >= sizeof(uint64_t)) {
            device->base_addr = fdt64_to_cpu(*reg);
        }

        const uint32_t *irq =
            fdt_getprop((void *)boot_get_dtb(), serial_off, "interrupts", &len);
        if (irq && len >= sizeof(uint32_t)) {
            device->irq_num = fdt32_to_cpu(*irq);
        }

        const uint32_t *reg_shift =
            fdt_getprop((void *)boot_get_dtb(), serial_off, "reg-shift", &len);
        device->reg_shift = reg_shift ? fdt32_to_cpu(*reg_shift) : 0;

        const uint32_t *reg_io_width = fdt_getprop(
            (void *)boot_get_dtb(), serial_off, "reg-io-width", &len);
        device->reg_io_width = reg_io_width ? fdt32_to_cpu(*reg_io_width) : 1;

        const uint32_t *clock_freq = fdt_getprop(
            (void *)boot_get_dtb(), serial_off, "clock-frequency", &len);
        device->clock_freq = clock_freq ? fdt32_to_cpu(*clock_freq) : 0;

        device->found = 1;

        return EOK;
    } else
        return -1;
}

int find_serial_by_compatible(struct fdt_serial_device *serial) {
    void *fdt = (void *)boot_get_dtb();
    if (fdt) {
        int node;

        memset(serial, 0, sizeof(*serial));

        for (node = fdt_next_node(fdt, -1, NULL); node >= 0;
             node = fdt_next_node(fdt, node, NULL)) {

            const char *compatible = fdt_getprop(fdt, node, "compatible", NULL);
            if (!compatible)
                continue;

            // 匹配已知串口类型
            for (int i = 0; serial_compatibles[i]; i++) {
                if (strstr(compatible, serial_compatibles[i])) {
                    int len;
                    const fdt64_t *reg = fdt_getprop(fdt, node, "reg", &len);
                    if (reg && len >= sizeof(fdt64_t)) {
                        serial->base_addr = fdt64_to_cpu(reg[0]);
                        serial->found = 1;

                        // interrupts
                        const fdt32_t *irq =
                            fdt_getprop(fdt, node, "interrupts", &len);
                        if (irq && len >= sizeof(fdt32_t))
                            serial->irq_num = fdt32_to_cpu(irq[0]);

                        // reg-shift
                        const fdt32_t *reg_shift =
                            fdt_getprop(fdt, node, "reg-shift", &len);
                        if (reg_shift && len >= sizeof(fdt32_t))
                            serial->reg_shift = fdt32_to_cpu(*reg_shift);

                        // reg-io-width
                        const fdt32_t *reg_io_width =
                            fdt_getprop(fdt, node, "reg-io-width", &len);
                        if (reg_io_width && len >= sizeof(fdt32_t))
                            serial->reg_io_width = fdt32_to_cpu(*reg_io_width);

                        // clock-frequency
                        const fdt32_t *clock =
                            fdt_getprop(fdt, node, "clock-frequency", &len);
                        if (clock && len >= sizeof(fdt32_t))
                            serial->clock_freq = fdt32_to_cpu(*clock);

                        return EOK;
                    }
                }
            }
        }
    }

    return -ENODEV;
}

/**
 * 统一的串口查找函数
 */
int find_serial_device(struct fdt_serial_device *serial) {
    // 按优先级尝试不同的查找方法
    if (find_serial_by_chosen(serial) == 0) {
        return 0;
    }

    if (find_serial_by_compatible(serial) == 0) {
        return 0;
    }

    return -1;
}

int init_serial() {
    struct uacpi_table spcr_table;
    uacpi_status status = uacpi_table_find_by_signature("SPCR", &spcr_table);
    if (status == UACPI_STATUS_OK) {
        struct acpi_spcr *spcr = spcr_table.ptr;
        uint64_t virt = phys_to_virt(spcr->base_address.address);
        map_page_range(get_current_page_dir(false), virt,
                       spcr->base_address.address, DEFAULT_PAGE_SIZE,
                       PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE);
        switch (spcr->interface_type) {
        case ACPI_DBG2_SUBTYPE_SERIAL_NS16550_GAS:
            uart_init(&uart0, (volatile void *)virt, NULL);
        default:
            break;
        }

        serial_initialized = true;
        return 0;
    } else {
        struct fdt_serial_device fdt_serial;
        find_serial_device(&fdt_serial);
        if (fdt_serial.found) {
            uint64_t virt = phys_to_virt(fdt_serial.base_addr);
            map_page_range(get_current_page_dir(false), virt,
                           fdt_serial.base_addr, DEFAULT_PAGE_SIZE,
                           PT_FLAG_R | PT_FLAG_W | PT_FLAG_UNCACHEABLE);
            uart_init(&uart0, (volatile void *)virt, NULL);

            serial_initialized = true;
        }

        return 0;
    }
}

char read_serial() {
    if (!serial_initialized)
        return 0;

    return uart_getc(&uart0);
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

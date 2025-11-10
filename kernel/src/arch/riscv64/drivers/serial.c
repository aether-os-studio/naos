#include <arch/arch.h>
#include <acpi/uacpi/acpi.h>
#include <acpi/uacpi/tables.h>
#include <arch/riscv64/drivers/ns16550.h>
#include <drivers/fdt/fdt.h>

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

/**
 * 通过 compatible 属性查找串口设备
 */
int find_serial_by_compatible(struct fdt_serial_device *serial) {
    int node_offset;
    int depth = 0;
    uint32_t *p = (uint32_t *)g_fdt_ctx.dt_struct;

    memset(serial, 0, sizeof(*serial));

    while (1) {
        uint32_t tag = fdt32_to_cpu(*p++);

        switch (tag) {
        case FDT_BEGIN_NODE: {
            const char *name = (const char *)p;
            node_offset = (uint8_t *)p - (uint8_t *)g_fdt_ctx.dt_struct - 4;

            // 检查节点的 compatible 属性
            int len;
            const char *compatible =
                fdt_get_property(node_offset, "compatible", &len);
            if (compatible && len > 0) {
                // 检查是否匹配已知的串口设备
                for (int i = 0; serial_compatibles[i]; i++) {
                    if (strstr(compatible, serial_compatibles[i])) {
                        // 找到串口设备，解析寄存器地址
                        const void *reg =
                            fdt_get_property(node_offset, "reg", &len);
                        if (reg && len >= 8) {
                            // 解析 reg 属性：通常包含地址和大小
                            const uint64_t *reg_data = (const uint64_t *)reg;
                            serial->base_addr = fdt64_to_cpu(reg_data[0]);
                            serial->found = 1;

                            // 解析中断号
                            const uint32_t *interrupts = fdt_get_property(
                                node_offset, "interrupts", &len);
                            if (interrupts && len >= 4) {
                                serial->irq_num = fdt32_to_cpu(interrupts[0]);
                            }

                            // 解析寄存器移位
                            const uint32_t *reg_shift = fdt_get_property(
                                node_offset, "reg-shift", &len);
                            if (reg_shift && len >= 4) {
                                serial->reg_shift = fdt32_to_cpu(*reg_shift);
                            }

                            // 解析时钟频率
                            const uint32_t *clock_freq = fdt_get_property(
                                node_offset, "clock-frequency", &len);
                            if (clock_freq && len >= 4) {
                                serial->clock_freq = fdt32_to_cpu(*clock_freq);
                            }

                            // 解析寄存器IO宽度
                            const uint32_t *reg_io_width = fdt_get_property(
                                node_offset, "reg-io-width", &len);
                            if (reg_io_width && len >= 4) {
                                serial->reg_io_width =
                                    fdt32_to_cpu(*reg_io_width);
                            }
                            return 0;
                        }
                    }
                }
            }

            depth++;
            p = (uint32_t *)ALIGN_UP((uintptr_t)p + strlen(name) + 1, 4);
            break;
        }

        case FDT_END_NODE:
            depth--;
            if (depth < 0)
                return -1;
            break;

        case FDT_PROP: {
            struct fdt_property *prop = (struct fdt_property *)p;
            uint32_t len = fdt32_to_cpu(prop->len);
            p = (uint32_t *)ALIGN_UP(
                (uintptr_t)p + sizeof(struct fdt_property) + len, 4);
            break;
        }

        case FDT_NOP:
            break;

        case FDT_END:
            return -1;

        default:
            return -1;
        }
    }

    return -1;
}

/**
 * 通过 aliases 节点查找串口
 */
int find_serial_by_alias(struct fdt_serial_device *serial) {
    int aliases_offset = fdt_find_node("/aliases");
    if (aliases_offset < 0) {
        return -1;
    }

    // 尝试 serial0 别名
    const char *alias = fdt_get_property_string(aliases_offset, "serial0");
    if (!alias) {
        // 尝试 uart0 别名
        alias = fdt_get_property_string(aliases_offset, "uart0");
    }

    if (!alias) {
        return -1;
    }

    // 根据别名找到对应的节点
    int node_offset = fdt_find_node(alias);
    if (node_offset < 0) {
        return -1;
    }

    // 解析串口设备信息
    int len;
    const void *reg = fdt_get_property(node_offset, "reg", &len);
    if (reg && len >= 8) {
        const uint64_t *reg_data = (const uint64_t *)reg;
        serial->base_addr = fdt64_to_cpu(reg_data[0]);
        serial->found = 1;

        // 解析其他属性
        const uint32_t *interrupts =
            fdt_get_property(node_offset, "interrupts", &len);
        if (interrupts && len >= 4) {
            serial->irq_num = fdt32_to_cpu(interrupts[0]);
        }
        return 0;
    }

    return -1;
}

/**
 * 通过 chosen 节点查找串口
 */
int find_serial_by_chosen(struct fdt_serial_device *serial) {
    int chosen_offset = fdt_find_node("/chosen");
    if (chosen_offset < 0) {
        return -1;
    }

    // 查找 stdout-path 属性
    const char *stdout_path =
        fdt_get_property_string(chosen_offset, "stdout-path");
    if (!stdout_path) {
        return -1;
    }

    // 解析 stdout-path，格式通常是 "serial0:115200n8" 或类似
    char node_path[256];
    const char *colon = strchr(stdout_path, ':');
    if (colon) {
        size_t len = colon - stdout_path;
        if (len < sizeof(node_path)) {
            strncpy(node_path, stdout_path, len);
            node_path[len] = '\0';

            // 找到对应的串口节点
            int node_offset = fdt_find_node(node_path);
            if (node_offset >= 0) {
                int len;
                const void *reg = fdt_get_property(node_offset, "reg", &len);
                if (reg && len >= 8) {
                    const uint64_t *reg_data = (const uint64_t *)reg;
                    serial->base_addr = fdt64_to_cpu(reg_data[0]);
                    serial->found = 1;
                    return 0;
                }
            }
        }
    }

    return -1;
}

/**
 * 统一的串口查找函数
 */
int find_serial_device(struct fdt_serial_device *serial) {
    // 按优先级尝试不同的查找方法
    if (find_serial_by_chosen(serial) == 0) {
        return 0;
    }

    if (find_serial_by_alias(serial) == 0) {
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
        struct fdt_serial_device fdt_serial;
        find_serial_device(&fdt_serial);
        if (fdt_serial.found) {
            uint64_t virt = phys_to_virt(fdt_serial.base_addr);
            map_page_range(get_current_page_dir(false), virt,
                           fdt_serial.base_addr, DEFAULT_PAGE_SIZE,
                           PT_FLAG_R | PT_FLAG_W | PT_FLAG_DEVICE |
                               PT_FLAG_UNCACHEABLE);
            uart_init(&uart0, (volatile void *)virt, NULL);
        }

        serial_initialized = true;
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

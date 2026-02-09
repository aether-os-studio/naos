#include <drivers/tty.h>
#include <mm/mm.h>
#include <boot/boot.h>

struct llist_header tty_device_list;
tty_t *kernel_session = NULL; // 内核会话

tty_device_t *alloc_tty_device(enum tty_device_type type) {
    tty_device_t *device = (tty_device_t *)calloc(1, sizeof(tty_device_t));
    device->type = type;
    llist_init_head(&device->node);
    return device;
}

uint64_t register_tty_device(tty_device_t *device) {
    if (device->private_data == NULL)
        return -EINVAL;
    llist_append(&tty_device_list, &device->node);
    return EOK;
}

uint64_t delete_tty_device(tty_device_t *device) {
    if (device == NULL)
        return -EINVAL;
    free(device->private_data);
    llist_delete(&device->node);
    free(device);
    return EOK;
}

tty_device_t *get_tty_device(const char *name) {
    if (name == NULL)
        return NULL;
    tty_device_t *pos = NULL;
    tty_device_t *n = NULL;
    llist_for_each(pos, n, &tty_device_list, node) {
        if (strcmp(pos->name, name) == 0) {
            return pos;
        }
    }
    return NULL;
}

// 全局默认控制台路径（初始为 /dev/ttyS0）
char *default_console = NULL;

void parse_cmdline_console(const char *cmdline) {
    static char console_name[64];
    memset(console_name, 0, sizeof(console_name));

    if (!cmdline || !*cmdline) {
        strcpy(console_name, DEFAULT_TTY);
        goto next;
    }

    // 查找 "console="
    const char *key = "console=";
    const char *pos = strstr(cmdline, key);
    if (!pos) {
        strcpy(console_name, DEFAULT_TTY);
        goto next;
    }

    pos += strlen(key);

    // 复制 console 设备名
    size_t i = 0;
    while (*pos && *pos != ' ' && i < sizeof(console_name) - 1) {
        console_name[i++] = *pos++;
    }
    console_name[i] = '\0';

next:
    // 输出调试信息
    printk("Detected console device: %s\n", console_name);

    char buf[64];
    sprintf(buf, "/dev/%s", console_name);

    default_console = strdup(buf);

    printk("Set default to %s\n", default_console);
}

void tty_init() {
    llist_init_head(&tty_device_list);
    kernel_session = malloc(sizeof(tty_t));

    tty_device_t *fb_device = alloc_tty_device(TTY_DEVICE_GRAPHI);
    struct tty_graphics_ *graphics = malloc(sizeof(struct tty_graphics_));

    boot_framebuffer_t *framebuffer = boot_get_framebuffer();

    graphics->address = (void *)framebuffer->address;
    graphics->width = framebuffer->width;
    graphics->height = framebuffer->height;
    graphics->bpp = framebuffer->bpp;
    graphics->pitch = framebuffer->pitch;

    graphics->blue_mask_shift = framebuffer->blue_mask_shift;
    graphics->red_mask_shift = framebuffer->red_mask_shift;
    graphics->green_mask_shift = framebuffer->green_mask_shift;
    graphics->blue_mask_size = framebuffer->blue_mask_size;
    graphics->red_mask_size = framebuffer->red_mask_size;
    graphics->green_mask_size = framebuffer->green_mask_size;

    fb_device->private_data = graphics;

    char name[32];
    sprintf(name, "tty%lu", 0);
    strcpy(fb_device->name, name);
    register_tty_device(fb_device);

    tty_device_t *serial_dev = alloc_tty_device(TTY_DEVICE_SERIAL);
    struct tty_serial_ *serial = malloc(sizeof(struct tty_serial_));
    serial->port = 0; // 第一个串口

    serial_dev->private_data = serial;
    strcpy(serial_dev->name, "ttyS0");
    register_tty_device(serial_dev);

    // 解析命令行 console 参数
    const char *cmdline = boot_get_cmdline();
    parse_cmdline_console(cmdline);

    if (!strncmp(default_console, "/dev/ttyS", 9)) {
        // 如果是串口终端，初始化串口终端会话
        tty_init_session_serial();
    } else {
        // 否则初始化普通终端会话
        tty_init_session();
    }
}

extern void create_session_terminal(tty_t *tty);
extern void create_session_terminal_serial(tty_t *tty);

int tty_ioctl(void *dev, int cmd, void *args) {
    tty_t *tty = dev;
    return tty->ops.ioctl(tty, cmd, (uint64_t)args);
}

int tty_poll(void *dev, int events) {
    tty_t *tty = dev;
    return tty->ops.poll(tty, events);
}

int tty_read(void *dev, void *buf, uint64_t offset, size_t size,
             uint64_t flags) {
    tty_t *tty = dev;
    return tty->ops.read(tty, buf, size);
}

int tty_write(void *dev, void *buf, uint64_t offset, size_t size,
              uint64_t flags) {
    tty_t *tty = dev;
    return tty->ops.write(tty, (const void *)buf, size);
}

void tty_init_session() {
    const char *tty_name = "tty0";
    tty_device_t *device = get_tty_device(tty_name);
    if (!device) {
        printk("tty_init_session: no device '%s', fallback to last tty\n",
               tty_name);
        device = container_of(tty_device_list.prev, tty_device_t, node);
    }

    tty_t *tty = calloc(1, sizeof(tty_t));
    tty->device = device;
    create_session_terminal(tty);
    device_install(DEV_CHAR, DEV_TTY, tty, tty_name, 0, NULL, NULL, tty_ioctl,
                   tty_poll, tty_read, tty_write, NULL);

    kernel_session = tty;
}

void tty_init_session_serial() {
    const char *tty_name = "ttyS0";
    tty_device_t *device = get_tty_device(tty_name);
    if (!device) {
        printk("tty_init_serial: device not found: %s\n", tty_name);
        return;
    }

    tty_t *tty = calloc(1, sizeof(tty_t));
    tty->device = device;
    create_session_terminal_serial(tty);
    device_install(DEV_CHAR, DEV_TTY, tty, tty_name, 0, NULL, NULL, tty_ioctl,
                   tty_poll, tty_read, tty_write, NULL);

    kernel_session = tty;
}

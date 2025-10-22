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

void tty_init() {
    llist_init_head(&tty_device_list);
    kernel_session = malloc(sizeof(tty_t));

    tty_device_t *device = alloc_tty_device(TTY_DEVICE_GRAPHI);
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

    device->private_data = graphics;

    char name[32];
    sprintf(name, "tty%zu", 0);
    strcpy(device->name, name);
    register_tty_device(device);
}

extern void create_session_terminal(tty_t *tty);

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
    device = device == NULL
                 ? container_of(tty_device_list.prev, tty_device_t, node)
                 : device;
    kernel_session = calloc(1, sizeof(tty_t));
    kernel_session->device = device;
    create_session_terminal(kernel_session);
    device_install(DEV_CHAR, DEV_TTY, kernel_session, tty_name, 0, tty_ioctl,
                   tty_poll, tty_read, tty_write, NULL);
}

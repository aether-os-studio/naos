#include <drivers/fb.h>
#include <drivers/kernel_logger.h>
#include <fs/vfs/dev.h>

extern volatile struct limine_framebuffer_request framebuffer_request;

ssize_t fb_read(void *data, uint64_t offset, void *buf, uint64_t len)
{
    struct limine_framebuffer *fb = (struct limine_framebuffer *)data;
    (void)fb;
    (void)offset;
    (void)buf;
    (void)len;
    return 0;
}

ssize_t fb_write(void *data, uint64_t offset, const void *buf, uint64_t len)
{
    struct limine_framebuffer *fb = (struct limine_framebuffer *)data;
    memcpy((char *)fb->address + offset, buf, len);
    return len;
}

void fbdev_init()
{
    for (uint64_t i = 0; i < framebuffer_request.response->framebuffer_count; i++)
    {
        char name[MAX_DEV_NAME_LEN];
        sprintf(name, "fb%d", i);
        regist_dev(name, fb_read, fb_write, framebuffer_request.response->framebuffers[i]);
    }
}

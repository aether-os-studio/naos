#include <arch/riscv64/drivers/fw_cfg.h>
#include <arch/riscv64/drivers/ramfb.h>
#include <drivers/fdt/fdt.h>
#include <mm/mm.h>
#include <boot/boot.h>

#define RAMFB_CFG_FILE "etc/ramfb"
extern struct fw_cfg_device fw_cfg_dev;

struct ramfb_device ramfb_dev;
uint16_t ramfb_select;

int ramfb_init() {
#ifdef OPENSBI
    struct fw_cfg_device *fwcfg;
    struct ramfb_device *dev = &ramfb_dev;
    uint32_t file_size;

    if (dev->initialized) {
        return 0;
    }

    /* 获取fw_cfg设备 */
    fwcfg = &fw_cfg_dev;
    if (!fwcfg) {
        return -1;
    }

    /* 查找ramfb配置文件 */
    if (fw_cfg_find_file(fwcfg, RAMFB_CFG_FILE, &ramfb_select, &file_size) !=
        0) {
        return -1;
    }

    if (file_size < sizeof(struct ramfb_config)) {
        return -1;
    }

    /* 设置默认参数 */
    dev->width = 1024;
    dev->height = 768;
    dev->format = RAMFB_FORMAT_XRGB8888;
    dev->bpp = 32;
    dev->stride = dev->width * 4;
    dev->fb_size = dev->stride * dev->height;

    /* 对齐到页 */
    dev->fb_size = (dev->fb_size + 0xFFF) & ~0xFFF;

    dev->fb_base = alloc_frames_bytes(dev->fb_size);
    if (!dev->fb_base) {
        return -1;
    }

    dev->fb_phys =
        translate_address(get_current_page_dir(false), (uint64_t)dev->fb_base);
    memset(dev->fb_base, 0, dev->fb_size);

    /* 构建配置 */
    struct ramfb_config cfg = {0};
    cfg.addr = cpu_to_fdt64(dev->fb_phys);
    cfg.fourcc = cpu_to_fdt32(dev->format);
    cfg.flags = 0;
    cfg.width = cpu_to_fdt32(dev->width);
    cfg.height = cpu_to_fdt32(dev->height);
    cfg.stride = cpu_to_fdt32(dev->stride);

    /* 通过fw_cfg写入配置 */
    if (fw_cfg_dma_write(fwcfg, ramfb_select, &cfg, sizeof(cfg)) != 0) {
        return -1;
    }

    dev->initialized = true;
    strcpy(dev->name, "ramfb-fwcfg");

    extern boot_framebuffer_t opensbi_fb;
    opensbi_fb.address = (uint64_t)dev->fb_base;
    opensbi_fb.width = dev->width;
    opensbi_fb.height = dev->height;
    opensbi_fb.bpp = dev->bpp;
    opensbi_fb.pitch = dev->stride;
    opensbi_fb.red_mask_size = 8;
    opensbi_fb.red_mask_shift = 16;
    opensbi_fb.green_mask_size = 8;
    opensbi_fb.green_mask_shift = 8;
    opensbi_fb.blue_mask_size = 8;
    opensbi_fb.blue_mask_shift = 0;
#endif

    return 0;
}
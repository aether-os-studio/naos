#pragma once

#include <libs/klibc.h>

/* RAMFB 像素格式 */
#define RAMFB_FORMAT_XRGB8888 0x34325258 /* 'XR24' */
#define RAMFB_FORMAT_ARGB8888 0x34325241 /* 'AR24' */
#define RAMFB_FORMAT_RGB565 0x36314752   /* 'RG16' */
#define RAMFB_FORMAT_RGB888 0x34324752   /* 'RG24' */

struct ramfb_config {
    uint64_t addr;   /* framebuffer物理地址 */
    uint32_t fourcc; /* 像素格式 */
    uint32_t flags;  /* 标志位 */
    uint32_t width;  /* 宽度(像素) */
    uint32_t height; /* 高度(像素) */
    uint32_t stride; /* 每行字节数 */
} __attribute__((packed));

struct ramfb_device {
    /* 设备信息 */
    char name[64];
    uint64_t cfg_reg; /* 配置寄存器地址 */

    /* Framebuffer信息 */
    void *fb_base;    /* framebuffer虚拟地址 */
    uint64_t fb_phys; /* framebuffer物理地址 */
    uint32_t fb_size; /* framebuffer大小 */

    /* 显示参数 */
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t bpp; /* bits per pixel */
    uint32_t format;

    /* 状态 */
    bool initialized;
};

int ramfb_init();

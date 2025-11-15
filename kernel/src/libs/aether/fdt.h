#pragma once

#include <drivers/fdt/fdt.h>

struct fdt_driver;

typedef struct fdt_device {
    const char *name;
    int node;                  // 设备树节点偏移
    void *driver_data;         // 驱动私有数据
    struct fdt_driver *driver; // 关联的驱动
} fdt_device_t;

#define MAX_FDT_DEVICES_NUM 256
extern fdt_device_t fdt_devices[MAX_FDT_DEVICES_NUM];
extern int fdt_device_count;

typedef struct fdt_driver {
    const char *name;
    const char **compatible; // compatible字符串数组，NULL结尾
    int (*probe)(fdt_device_t *dev, const char *compatible);
    void (*remove)(fdt_device_t *dev);
    void (*shutdown)(fdt_device_t *dev);
    int flags;
} fdt_driver_t;

extern fdt_driver_t *fdt_drivers[MAX_FDT_DEVICES_NUM];

int regist_fdt_driver(fdt_driver_t *driver);

void *get_dtb_ptr();

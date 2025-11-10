#include <libs/aether/fdt.h>
#include <mod/dlinker.h>

fdt_driver_t *fdt_drivers[MAX_FDT_DEVICES_NUM] = {NULL};
int fdt_driver_count = 0;

fdt_device_t fdt_devices[MAX_FDT_DEVICES_NUM];
int fdt_device_count = 0;

int regist_fdt_driver(fdt_driver_t *driver) {
    for (int i = 0; i < MAX_FDT_DEVICES_NUM; i++) {
        if (!fdt_drivers[i]) {
            fdt_drivers[i] = driver;
            fdt_driver_count++;
            break;
        }
    }

    return 0;
}

EXPORT_SYMBOL(regist_fdt_driver);

#if !defined(__x86_64__)
EXPORT_SYMBOL(fdt_get_property);
EXPORT_SYMBOL(fdt_get_property_u32);
EXPORT_SYMBOL(fdt_get_property_u64);
EXPORT_SYMBOL(fdt_get_property_string);
#endif

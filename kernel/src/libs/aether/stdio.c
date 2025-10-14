#include <libs/aether/stdio.h>
#include <mod/dlinker.h>

#include <drivers/kernel_logger.h>

EXPORT_SYMBOL(printk);
EXPORT_SYMBOL(serial_fprintk);
EXPORT_SYMBOL(sprintf);
EXPORT_SYMBOL(vsprintf);
EXPORT_SYMBOL(vsnprintf);

EXPORT_SYMBOL(get_current_fb);

EXPORT_SYMBOL(panic);

uint64_t get_cpu_count() { return cpu_count; }

EXPORT_SYMBOL(get_cpu_count);

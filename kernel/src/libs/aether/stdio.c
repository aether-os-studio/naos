#include <libs/aether/stdio.h>
#include <mod/dlinker.h>

#include <drivers/kernel_logger.h>

char vsnprintf_buf[8192];

EXPORT_SYMBOL(printk);
EXPORT_SYMBOL(serial_fprintk);
EXPORT_SYMBOL(sprintf);
EXPORT_SYMBOL(vsprintf);
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args) {
    int ret = vsprintf(vsnprintf_buf, fmt, args);
    int to_copy = MIN((size_t)ret, size);
    memcpy(buf, vsnprintf_buf, to_copy);
    return to_copy;
}
EXPORT_SYMBOL(vsnprintf);

EXPORT_SYMBOL(get_current_fb);

EXPORT_SYMBOL(panic);

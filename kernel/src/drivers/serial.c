#include <drivers/serial.h>

bool serial_initialized = false;

static serial_driver_t *active_serial_driver = NULL;
static spinlock_t serial_write_lock = SPIN_INIT;

int serial_register_driver(serial_driver_t *driver) {
    if (!driver || !driver->write)
        return -1;

    active_serial_driver = driver;
    serial_initialized = true;
    return 0;
}

serial_driver_t *serial_get_driver() { return active_serial_driver; }

bool serial_can_read() {
    if (!serial_initialized || !active_serial_driver)
        return false;

    if (active_serial_driver->can_read)
        return active_serial_driver->can_read(active_serial_driver);

    return active_serial_driver->read != NULL;
}

bool serial_read(char *ch) {
    if (!ch || !serial_initialized || !active_serial_driver ||
        !active_serial_driver->read)
        return false;

    return active_serial_driver->read(active_serial_driver, ch);
}

char read_serial() {
    char ch = 0;
    (void)serial_read(&ch);
    return ch;
}

void write_serial(char ch) {
    if (!serial_initialized || !active_serial_driver ||
        !active_serial_driver->write) {
        return;
    }

    active_serial_driver->write(active_serial_driver, ch);
}

void serial_printk(const char *buf, int len) {
    if (!serial_initialized || !buf || len <= 0)
        return;

    spin_lock(&serial_write_lock);

    for (int i = 0; i < len; i++) {
        if (buf[i] == '\n')
            write_serial('\r');
        write_serial(buf[i]);
    }

    spin_unlock(&serial_write_lock);
}

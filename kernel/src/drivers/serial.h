#pragma once

#include <libs/klibc.h>

typedef struct serial_driver {
    const char *name;
    void *private_data;
    bool (*can_read)(struct serial_driver *driver);
    bool (*read)(struct serial_driver *driver, char *ch);
    void (*write)(struct serial_driver *driver, char ch);
} serial_driver_t;

extern bool serial_initialized;

int init_serial();
int serial_register_driver(serial_driver_t *driver);
serial_driver_t *serial_get_driver();

bool serial_can_read();
bool serial_read(char *ch);
char read_serial();
void write_serial(char ch);
void serial_printk(const char *buf, int len);

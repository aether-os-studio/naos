#pragma once

#include <libs/klibc.h>

void serial_printk(char *str, int len);

void init_serial();

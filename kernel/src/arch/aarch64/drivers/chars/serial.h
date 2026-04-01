#pragma once

int init_serial();
char read_serial();
void write_serial(char a);
void serial_printk(const char *buf, int len);

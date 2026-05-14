#pragma once

int init_serial();
char read_serial();
void write_serial(char ch);
void serial_printk(const char *buf, int len);

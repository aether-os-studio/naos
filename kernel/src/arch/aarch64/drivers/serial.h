#pragma once

#include <libs/klibc.h>
#include <arch/aarch64/acpi/acpi.h>

extern uint64_t uart_base;

// PL011寄存器偏移量
#define UART_DR 0x00    // 数据寄存器
#define UART_RSR 0x04   // 接收状态寄存器
#define UART_FR 0x18    // 标志寄存器
#define UART_IBRD 0x24  // 整数分频
#define UART_FBRD 0x28  // 小数分频
#define UART_LCR_H 0x2C // 线路控制寄存器
#define UART_CR 0x30    // 控制寄存器
#define UART_IMSC 0x38  // 中断掩码寄存器

void serial_printk(char *str, int len);

void init_serial();

void uart_setup(SPCR *spcr);

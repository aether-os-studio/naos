#pragma once

#include <libs/klibc.h>

/* PL011 寄存器偏移 */
#define UART_DR 0x000    // 数据寄存器
#define UART_RSR 0x004   // 接收状态寄存器
#define UART_ECR 0x004   // 错误清除寄存器
#define UART_FR 0x018    // 标志寄存器
#define UART_ILPR 0x020  // IrDA低功耗计数器寄存器
#define UART_IBRD 0x024  // 整数波特率寄存器
#define UART_FBRD 0x028  // 小数波特率寄存器
#define UART_LCR_H 0x02C // 线路控制寄存器
#define UART_CR 0x030    // 控制寄存器
#define UART_IFLS 0x034  // 中断FIFO级别选择寄存器
#define UART_IMSC 0x038  // 中断屏蔽设置/清除寄存器
#define UART_RIS 0x03C   // 原始中断状态寄存器
#define UART_MIS 0x040   // 屏蔽中断状态寄存器
#define UART_ICR 0x044   // 中断清除寄存器

/* FR (Flag Register) 位定义 */
#define UART_FR_TXFE (1 << 7) // 发送FIFO空
#define UART_FR_RXFF (1 << 6) // 接收FIFO满
#define UART_FR_TXFF (1 << 5) // 发送FIFO满
#define UART_FR_RXFE (1 << 4) // 接收FIFO空
#define UART_FR_BUSY (1 << 3) // UART忙
#define UART_FR_CTS (1 << 0)  // 清除发送

/* LCR_H (Line Control Register) 位定义 */
#define UART_LCR_H_SPS (1 << 7)    // 粘滞奇偶校验选择
#define UART_LCR_H_WLEN_8 (3 << 5) // 字长8位
#define UART_LCR_H_WLEN_7 (2 << 5) // 字长7位
#define UART_LCR_H_WLEN_6 (1 << 5) // 字长6位
#define UART_LCR_H_WLEN_5 (0 << 5) // 字长5位
#define UART_LCR_H_FEN (1 << 4)    // FIFO使能
#define UART_LCR_H_STP2 (1 << 3)   // 两个停止位
#define UART_LCR_H_EPS (1 << 2)    // 偶校验选择
#define UART_LCR_H_PEN (1 << 1)    // 奇偶校验使能
#define UART_LCR_H_BRK (1 << 0)    // 发送中断

/* CR (Control Register) 位定义 */
#define UART_CR_CTSEN (1 << 15) // CTS硬件流控使能
#define UART_CR_RTSEN (1 << 14) // RTS硬件流控使能
#define UART_CR_RTS (1 << 11)   // 请求发送
#define UART_CR_RXE (1 << 9)    // 接收使能
#define UART_CR_TXE (1 << 8)    // 发送使能
#define UART_CR_LBE (1 << 7)    // 环回使能
#define UART_CR_UARTEN (1 << 0) // UART使能

/* 中断位定义 */
#define UART_INT_OE (1 << 10) // 溢出错误中断
#define UART_INT_BE (1 << 9)  // 中断错误中断
#define UART_INT_PE (1 << 8)  // 奇偶校验错误中断
#define UART_INT_FE (1 << 7)  // 帧错误中断
#define UART_INT_RT (1 << 6)  // 接收超时中断
#define UART_INT_TX (1 << 5)  // 发送中断
#define UART_INT_RX (1 << 4)  // 接收中断

/* 波特率配置 */
typedef enum {
    BAUD_9600 = 9600,
    BAUD_19200 = 19200,
    BAUD_38400 = 38400,
    BAUD_57600 = 57600,
    BAUD_115200 = 115200,
} uart_baudrate_t;

/* 数据位配置 */
typedef enum {
    DATA_BITS_5 = UART_LCR_H_WLEN_5,
    DATA_BITS_6 = UART_LCR_H_WLEN_6,
    DATA_BITS_7 = UART_LCR_H_WLEN_7,
    DATA_BITS_8 = UART_LCR_H_WLEN_8,
} uart_data_bits_t;

/* 停止位配置 */
typedef enum {
    STOP_BITS_1 = 0,
    STOP_BITS_2 = UART_LCR_H_STP2,
} uart_stop_bits_t;

/* 奇偶校验配置 */
typedef enum {
    PARITY_NONE = 0,
    PARITY_ODD = UART_LCR_H_PEN,
    PARITY_EVEN = UART_LCR_H_PEN | UART_LCR_H_EPS,
} uart_parity_t;

/* UART配置结构体 */
typedef struct {
    uart_baudrate_t baudrate;
    uart_data_bits_t data_bits;
    uart_stop_bits_t stop_bits;
    uart_parity_t parity;
    bool fifo_enable;
} uart_config_t;

/* PL011驱动结构体 */
typedef struct {
    volatile uint32_t *base; // 基地址
    uint32_t clock_freq;     // 时钟频率（Hz）
} pl011_dev_t;

/* 函数声明 */

/**
 * 初始化PL011 UART
 * @param dev: PL011设备结构体指针
 * @param base: UART基地址
 * @param clock_freq: UART时钟频率（Hz）
 * @param config: UART配置参数
 * @return: 0成功，-1失败
 */
int pl011_init(pl011_dev_t *dev, void *base, uint32_t clock_freq,
               const uart_config_t *config);

/**
 * 发送一个字符
 * @param dev: PL011设备结构体指针
 * @param ch: 要发送的字符
 */
void pl011_putc(pl011_dev_t *dev, char ch);

/**
 * 接收一个字符（阻塞）
 * @param dev: PL011设备结构体指针
 * @return: 接收到的字符
 */
char pl011_getc(pl011_dev_t *dev);

/**
 * 非阻塞接收字符
 * @param dev: PL011设备结构体指针
 * @param ch: 用于存储接收字符的指针
 * @return: true接收成功，false接收失败（无数据）
 */
bool pl011_getc_nonblock(pl011_dev_t *dev, char *ch);

/**
 * 发送字符串
 * @param dev: PL011设备结构体指针
 * @param str: 要发送的字符串
 */
void pl011_puts(pl011_dev_t *dev, const char *str);

/**
 * 发送数据块
 * @param dev: PL011设备结构体指针
 * @param buf: 数据缓冲区
 * @param len: 数据长度
 */
void pl011_write(pl011_dev_t *dev, const uint8_t *buf, uint32_t len);

/**
 * 接收数据块
 * @param dev: PL011设备结构体指针
 * @param buf: 数据缓冲区
 * @param len: 要接收的数据长度
 * @return: 实际接收的字节数
 */
uint32_t pl011_read(pl011_dev_t *dev, uint8_t *buf, uint32_t len);

/**
 * 检查发送FIFO是否为空
 * @param dev: PL011设备结构体指针
 * @return: true为空，false不为空
 */
bool pl011_tx_empty(pl011_dev_t *dev);

/**
 * 检查接收FIFO是否有数据
 * @param dev: PL011设备结构体指针
 * @return: true有数据，false无数据
 */
bool pl011_rx_ready(pl011_dev_t *dev);

/**
 * 等待发送完成
 * @param dev: PL011设备结构体指针
 */
void pl011_flush(pl011_dev_t *dev);

/**
 * 使能中断
 * @param dev: PL011设备结构体指针
 * @param mask: 中断掩码
 */
void pl011_enable_interrupts(pl011_dev_t *dev, uint32_t mask);

/**
 * 禁用中断
 * @param dev: PL011设备结构体指针
 * @param mask: 中断掩码
 */
void pl011_disable_interrupts(pl011_dev_t *dev, uint32_t mask);

/**
 * 清除中断
 * @param dev: PL011设备结构体指针
 * @param mask: 中断掩码
 */
void pl011_clear_interrupts(pl011_dev_t *dev, uint32_t mask);

/**
 * 获取中断状态
 * @param dev: PL011设备结构体指针
 * @return: 中断状态
 */
uint32_t pl011_get_interrupt_status(pl011_dev_t *dev);

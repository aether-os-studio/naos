#include <arch/aarch64/drivers/chars/pl011.h>

/* 寄存器读写宏 */
#define UART_READ(dev, offset)                                                 \
    (*(volatile uint32_t *)((uint8_t *)(dev)->base + (offset)))

#define UART_WRITE(dev, offset, value)                                         \
    (*(volatile uint32_t *)((uint8_t *)(dev)->base + (offset)) = (value))

/**
 * 初始化PL011 UART
 */
int pl011_init(pl011_dev_t *dev, void *base, uint32_t clock_freq,
               const uart_config_t *config) {
    if (!dev || !base || !config) {
        return -1;
    }

    dev->base = (volatile uint32_t *)base;
    dev->clock_freq = clock_freq;

    // 1. 禁用UART
    UART_WRITE(dev, UART_CR, 0);

    // 2. 等待当前传输完成
    while (UART_READ(dev, UART_FR) & UART_FR_BUSY)
        ;

    // 3. 清空FIFO
    UART_WRITE(dev, UART_LCR_H, 0);

    // 4. 计算波特率分频值
    // BAUDDIV = (FUARTCLK / (16 * Baud rate))
    // IBRD = integer part of BAUDDIV
    // FBRD = integer((fractional part of BAUDDIV) * 64 + 0.5)
    uint32_t bauddiv = (clock_freq * 4) / config->baudrate;
    uint32_t ibrd = bauddiv >> 6;
    uint32_t fbrd = bauddiv & 0x3F;

    UART_WRITE(dev, UART_IBRD, ibrd);
    UART_WRITE(dev, UART_FBRD, fbrd);

    // 5. 配置数据格式
    uint32_t lcr_h = config->data_bits | config->stop_bits | config->parity;
    if (config->fifo_enable) {
        lcr_h |= UART_LCR_H_FEN;
    }
    UART_WRITE(dev, UART_LCR_H, lcr_h);

    // 6. 清除所有中断
    UART_WRITE(dev, UART_ICR, 0x7FF);

    // 7. 禁用所有中断
    UART_WRITE(dev, UART_IMSC, 0);

    // 8. 使能UART、发送和接收
    UART_WRITE(dev, UART_CR, UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE);

    return 0;
}

/**
 * 发送一个字符
 */
void pl011_putc(pl011_dev_t *dev, char ch) {
    // 等待发送FIFO不满
    while (UART_READ(dev, UART_FR) & UART_FR_TXFF)
        ;

    // 写入数据
    UART_WRITE(dev, UART_DR, (uint32_t)ch);
}

/**
 * 接收一个字符（阻塞）
 */
char pl011_getc(pl011_dev_t *dev) {
    // 等待接收FIFO非空
    while (UART_READ(dev, UART_FR) & UART_FR_RXFE)
        ;

    // 读取数据
    return (char)(UART_READ(dev, UART_DR) & 0xFF);
}

/**
 * 非阻塞接收字符
 */
bool pl011_getc_nonblock(pl011_dev_t *dev, char *ch) {
    if (UART_READ(dev, UART_FR) & UART_FR_RXFE) {
        return false; // 无数据
    }

    *ch = (char)(UART_READ(dev, UART_DR) & 0xFF);
    return true;
}

/**
 * 发送字符串
 */
void pl011_puts(pl011_dev_t *dev, const char *str) {
    if (!str) {
        return;
    }

    while (*str) {
        if (*str == '\n') {
            pl011_putc(dev, '\r'); // 添加回车
        }
        pl011_putc(dev, *str++);
    }
}

/**
 * 发送数据块
 */
void pl011_write(pl011_dev_t *dev, const uint8_t *buf, uint32_t len) {
    if (!buf) {
        return;
    }

    for (uint32_t i = 0; i < len; i++) {
        pl011_putc(dev, buf[i]);
    }
}

/**
 * 接收数据块
 */
uint32_t pl011_read(pl011_dev_t *dev, uint8_t *buf, uint32_t len) {
    if (!buf) {
        return 0;
    }

    uint32_t count = 0;
    for (uint32_t i = 0; i < len; i++) {
        if (!pl011_getc_nonblock(dev, (char *)&buf[i])) {
            break;
        }
        count++;
    }

    return count;
}

/**
 * 检查发送FIFO是否为空
 */
bool pl011_tx_empty(pl011_dev_t *dev) {
    return (UART_READ(dev, UART_FR) & UART_FR_TXFE) != 0;
}

/**
 * 检查接收FIFO是否有数据
 */
bool pl011_rx_ready(pl011_dev_t *dev) {
    return (UART_READ(dev, UART_FR) & UART_FR_RXFE) == 0;
}

/**
 * 等待发送完成
 */
void pl011_flush(pl011_dev_t *dev) {
    // 等待发送FIFO为空且UART不忙
    while (!(UART_READ(dev, UART_FR) & UART_FR_TXFE))
        ;
    while (UART_READ(dev, UART_FR) & UART_FR_BUSY)
        ;
}

/**
 * 使能中断
 */
void pl011_enable_interrupts(pl011_dev_t *dev, uint32_t mask) {
    uint32_t imsc = UART_READ(dev, UART_IMSC);
    UART_WRITE(dev, UART_IMSC, imsc | mask);
}

/**
 * 禁用中断
 */
void pl011_disable_interrupts(pl011_dev_t *dev, uint32_t mask) {
    uint32_t imsc = UART_READ(dev, UART_IMSC);
    UART_WRITE(dev, UART_IMSC, imsc & ~mask);
}

/**
 * 清除中断
 */
void pl011_clear_interrupts(pl011_dev_t *dev, uint32_t mask) {
    UART_WRITE(dev, UART_ICR, mask);
}

/**
 * 获取中断状态
 */
uint32_t pl011_get_interrupt_status(pl011_dev_t *dev) {
    return UART_READ(dev, UART_MIS);
}

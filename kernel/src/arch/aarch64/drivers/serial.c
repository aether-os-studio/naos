#include <arch/arch.h>

uint64_t uart_base = 0;

void serial_printk(char *str, int len)
{
    if (uart_base == 0)
        return;

    volatile uint32_t *uart = (volatile uint32_t *)uart_base;

    for (int i = 0; i < len; i++)
    {
        // 等待发送缓冲区非满
        while (uart[UART_FR] & (1 << 5))
            ; // 检查FR[5]（TXFF位）
        uart[UART_DR] = (uint32_t)str[i];
    }
}

void init_serial()
{
}

void uart_setup(SPCR *spcr)
{
    if (spcr->address.address == 0)
        return;

    uart_base = phys_to_virt(spcr->address.address);
    map_page_range(get_current_page_dir(false), uart_base, spcr->address.address, spcr->address.access_size, PT_FLAG_R | PT_FLAG_W);

    volatile uint32_t *uart = (volatile uint32_t *)uart_base;

    // 禁用UART
    uart[UART_CR] = 0x00000000;

    // 设置波特率（24MHz时钟，115200波特率）
    float divisor = 24000000.0 / (16.0 * 115200);
    uint16_t ibrd = (uint16_t)divisor;
    uint16_t fbrd = (uint16_t)((divisor - ibrd) * 64 + 0.5);
    uart[UART_IBRD] = ibrd;
    uart[UART_FBRD] = fbrd;

    // 配置数据格式：8N1，启用FIFO
    uart[UART_LCR_H] = (1 << 5) | (1 << 6) | (1 << 4); // 0x70 (8N1 + FIFO)

    // 启用UART，发送和接收
    uart[UART_CR] = (1 << 0) | (1 << 8) | (1 << 9); // 0x301
}

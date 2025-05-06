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

uint8_t serial_read()
{
    if (uart_base == 0)
        return;

    if (*(volatile uint32_t *)(uart_base + UART_FR) & (1 << 4))
        return 0; // FIFO为空

    uint32_t dr = *(volatile uint32_t *)(uart_base + UART_DR);
    // if (dr == (uint32_t)'\033')
    // {
    //     uint32_t dr1 = *(volatile uint32_t *)(uart_base + UART_DR);
    //     uint32_t dr2 = *(volatile uint32_t *)(uart_base + UART_DR);
    //     if (dr1 != (uint32_t)'[')
    //         return 0;

    //     switch (dr2)
    //     {
    //     case 'a':
    //     case 'A':
    //         return (uint8_t)-1;
    //     case 'b':
    //     case 'B':
    //         return (uint8_t)-2;
    //     case 'd':
    //     case 'D':
    //         return (uint8_t)-3;
    //     case 'c':
    //     case 'C':
    //         return (uint8_t)-4;
    //     default:
    //         return 0;
    //     }
    // }
    if (dr == (uint32_t)'\177')
        return (uint8_t)'\b';
    if (dr == (uint32_t)'\r')
        return (uint8_t)'\n';

    return (uint8_t)(dr & 0xFF);
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
    uart[UART_CR / 4] = 0x00000000;

    // 配置数据格式：8N1，启用FIFO
    uart[UART_LCR_H / 4] = (1 << 5) | (1 << 6) | (1 << 4); // 0x70 (8N1 + FIFO)

    // 启用UART，发送和接收
    uart[UART_CR / 4] = (1 << 0) | (1 << 8) | (1 << 9); // 0x301
}

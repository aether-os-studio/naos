#pragma once

#include <libs/klibc.h>

#if defined(__x86_64__)

#define REG_MAC0 0x00
#define REG_TSR 0x10
#define REG_RXCONFIG 0x44
#define REG_COMMAND 0x37
#define REG_IMR 0x3C
#define REG_ISR 0x3E

typedef struct rtl8139
{
    uint16_t io_base;             // I/O端口基地址
    uint8_t *rx_buffer;           // 接收缓冲区指针
    uint32_t rx_current;          // 当前接收位置
    uint8_t *tx_buffer[4];        // 发送描述符环（4个条目）
    uint8_t tx_cur;               // 当前发送描述符索引
    uint16_t rx_size;             // 接收缓冲区大小
    uint8_t irq_line;             // 中断线号
    uint8_t mac_addr[6];          // MAC地址存储
    uint32_t tx_count;            // 发送数据包计数
    uint32_t rx_count;            // 接收数据包计数
    bool use_msi;                 // MSI中断使能标志
    struct pci_device *pci_dev;   // 关联的PCI设备
    struct msi_desc_t *msix_desc; // MSI-X描述符（如果使用）
} rtl8139_t;

bool rtl8139_init();

#endif

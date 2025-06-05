#include <arch/arch.h>
#include <mm/mm.h>
#include <drivers/net/net.h>
#include <drivers/net/rtl8139.h>
#include <drivers/bus/pci.h>
#include <drivers/bus/msi.h>
#include <interrupt/irq_manager.h>

#if defined(__x86_64__)

rtl8139_t rtl8139_controller;

static void rtl8139_hw_init(pci_device_t *pci_dev)
{
    // 获取IO基地址
    uint16_t io_base = pci_dev->bars[0].address & ~0x3;

    // 重置网卡
    io_out8(io_base + REG_COMMAND, 0x10);
    while ((io_in8(io_base + REG_COMMAND) & 0x10))
        ;

    // 设置MAC地址
    uint8_t mac[6];
    for (int i = 0; i < 6; i++)
        mac[i] = io_in8(io_base + REG_MAC0 + i);

    printk("RTL8139 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // 配置接收缓冲区
    uint8_t *rx_buffer = malloc(8192 + 16);
    io_out32(io_base + 0x30, (uint32_t)translate_address(get_current_page_dir(false), (uint64_t)rx_buffer)); // RBSTART寄存器

    // 启用接收功能
    io_out16(io_base + REG_RXCONFIG, 0x0F | (1 << 7)); // 接收所有数据包
    io_out8(io_base + REG_COMMAND, 0x0C);              // 启用接收和发送

    // 启用中断
    io_out16(io_base + REG_IMR, 0x0005); // 启用接收完成中断
}

// 中断处理函数
static void rtl8139_irq_handler(uint64_t irq_num, void *data, struct pt_regs *regs)
{
    uint16_t io_base = rtl8139_controller.io_base;
    uint16_t status = io_in16(io_base + REG_ISR);

    if (status & 0x01)
    { // 接收中断
        uint32_t packet_header = *(volatile uint32_t *)(rtl8139_controller.rx_buffer);
        uint16_t packet_len = packet_header >> 16;

        // 处理数据包（示例）
        printk("Received packet, len=%d\n", packet_len);

        // 移动接收指针
        io_out16(io_base + 0x38, (uint16_t)(rtl8139_controller.rx_current + packet_len + 4));
    }

    io_out16(io_base + REG_ISR, status); // 清除中断标志
}

extern nic_controller_t nic_controller;

// 完善初始化函数
bool rtl8139_init()
{
    pci_device_t *devices[4];
    uint32_t num;
    pci_find_vid(devices, &num, 0x10ec);

    for (uint32_t i = 0; i < num; i++)
    {
        if (devices[i]->device_id == 0x8139)
        {
            struct msi_desc_t desc;
            desc.irq_num = devices[i]->irq_line + 32;
            desc.processor = 0;
            desc.edge_trigger = false;
            desc.assert = true;
            desc.pci_dev = devices[i];
            pci_enable_msi(&desc);

            // 注册中断处理（使用现有IRQ管理）
            irq_regist_irq(devices[i]->irq_line + 32, rtl8139_irq_handler, devices[i]->irq_line, NULL, &apic_controller, "RTL8139");

            // 初始化硬件
            rtl8139_hw_init(devices[i]);

            // 保存控制器状态
            rtl8139_controller.io_base = devices[i]->bars[0].address & ~0x3;

            nic_controller.type = RTL8139;
            nic_controller.inner = &rtl8139_controller;

            return true;
        }
    }
    return false;
}

// 添加数据包发送函数
int rtl8139_send_packet(void *data, uint16_t len)
{
    uint16_t io_base = rtl8139_controller.io_base;

    // 等待上一个发送完成
    while (!(io_in8(io_base + REG_TSR) & 0x01))
        ;

    // 复制数据到发送缓冲区
    uint8_t *tx_buf = malloc(len);
    memcpy(tx_buf, data, len);

    // 启动发送
    io_out32(io_base + 0x20, (uint32_t)translate_address(get_current_page_dir(false), (uint64_t)tx_buf)); // TSAD寄存器
    io_out32(io_base + 0x24, len);                                                                        // TSD寄存器

    free(tx_buf);

    return len;
}

#endif

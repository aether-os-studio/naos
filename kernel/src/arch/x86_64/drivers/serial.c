#include <arch/arch.h>

static bool x86_64_serial_can_read(serial_driver_t *driver);
static bool x86_64_serial_read(serial_driver_t *driver, char *ch);
static void x86_64_serial_write(serial_driver_t *driver, char ch);

static serial_driver_t x86_64_serial_driver = {
    .name = "x86_64-16550",
    .can_read = x86_64_serial_can_read,
    .read = x86_64_serial_read,
    .write = x86_64_serial_write,
};

int init_serial() {
    io_out8(SERIAL_PORT + 1, 0x00); // 禁止COM的中断发生
    io_out8(SERIAL_PORT + 3, 0x80); // 启用DLAB（设置波特率除数）。
    io_out8(SERIAL_PORT + 0, 0x03); // 设置除数为3，(低位) 38400波特
    io_out8(SERIAL_PORT + 1, 0x00); //            (高位)
    io_out8(SERIAL_PORT + 3, 0x03); // 8位，无奇偶性，一个停止位
    io_out8(SERIAL_PORT + 2, 0xC7); // 启用FIFO，有14字节的阈值
    io_out8(SERIAL_PORT + 4, 0x0B); // 启用IRQ，设置RTS/DSR
    io_out8(SERIAL_PORT + 4, 0x1E); // 设置为环回模式，测试串口
    io_out8(SERIAL_PORT + 0,
            0xAE); // 测试串口（发送字节0xAE并检查串口是否返回相同的字节）

    // 检查串口是否有问题（即：与发送的字节不一样）
    if (io_in8(SERIAL_PORT + 0) != 0xAE) {
        return 1;
    }

    // 如果串口没有故障，将其设置为正常运行模式。
    // (非环回，启用IRQ，启用OUT#1和OUT#2位)
    io_out8(SERIAL_PORT + 4, 0x0F);
    return serial_register_driver(&x86_64_serial_driver);
}

static bool x86_64_serial_can_read(serial_driver_t *driver) {
    return (io_in8(SERIAL_PORT + 5) & 1) != 0;
}

static bool x86_64_serial_read(serial_driver_t *driver, char *ch) {
    if (!x86_64_serial_can_read(driver))
        return false;

    *ch = io_in8(SERIAL_PORT);
    return true;
}

static void x86_64_serial_write(serial_driver_t *driver, char a) {
    while ((io_in8(SERIAL_PORT + 5) & 0x20) == 0)
        arch_pause();
    io_out8(SERIAL_PORT, a);
}

#include <arch/x64/drivers/chars/ps2_kbd.h>
#include <arch/x64/drivers/chars/ps2_mouse.h>
#include <interrupt/irq_manager.h>
#include <arch/x64/io.h>
#include <task/task.h>

mouse_dec ms_dec;
int32_t mouse_x = 0;
int32_t mouse_y = 0;
int32_t old_x = 0;
int32_t old_y = 0;
int32_t delta_x = 0;
int32_t delta_y = 0;

extern struct limine_framebuffer *fb;

bool mousedecode(uint8_t data)
{
    close_interrupt;

    if (ms_dec.phase == 0)
    {
        if (data == 0xfa)
        {
            ms_dec.phase = 1;
        }

        open_interrupt;

        return false;
    }
    if (ms_dec.phase == 1)
    {
        if ((data & 0xc8) == 0x08)
        {
            ms_dec.buf[0] = data;
            ms_dec.phase = 2;
        }

        open_interrupt;

        return 0;
    }
    if (ms_dec.phase == 2)
    {
        ms_dec.buf[1] = data;
        ms_dec.phase = 3;
        return 0;
    }
    if (ms_dec.phase == 3)
    {
        ms_dec.buf[2] = data;
        ms_dec.phase = 1;
        ms_dec.btn = ms_dec.buf[0] & 0x07;
        ms_dec.x = ms_dec.buf[1];
        ms_dec.y = ms_dec.buf[2];

        if ((ms_dec.buf[0] & 0x10) != 0)
            ms_dec.x |= 0xffffff00;
        if ((ms_dec.buf[0] & 0x20) != 0)
            ms_dec.y |= 0xffffff00;
        ms_dec.y = -ms_dec.y;

        open_interrupt;

        return true;
    }

    open_interrupt;

    ms_dec.phase = 0;

    return false;
}

void mouse_handler(uint64_t irq, void *param, struct pt_regs *regs)
{
    uint8_t data = io_in8(PORT_KB_DATA);

    if (mousedecode(data))
    {
        old_x = mouse_x;
        old_y = mouse_y;

        mouse_x += ms_dec.x;
        mouse_y += ms_dec.y;

        if (mouse_x < 0)
            mouse_x = 0;
        if (mouse_y < 0)
            mouse_y = 0;
        if (fb && mouse_x > (int32_t)fb->width)
            mouse_x = (int32_t)fb->width;
        if (fb && mouse_y > (int32_t)fb->height)
            mouse_y = (int32_t)fb->height;

        delta_x = mouse_x - old_x;
        delta_y = mouse_y - old_y;

        if (ms_dec.btn & 0x01)
        {
            ms_dec.left = true;
        }
        else
        {
            ms_dec.left = false;
        }

        if (ms_dec.btn & 0x02)
        {
            ms_dec.right = true;
        }
        else
        {
            ms_dec.right = false;
        }

        if (ms_dec.btn & 0x04)
        {
            ms_dec.center = true;
        }
        else
        {
            ms_dec.center = false;
        }
    }
}

void get_mouse_xy(int32_t *x, int32_t *y)
{
    *x = mouse_x;
    *y = mouse_y;
}

bool mouse_click_left()
{
    return (ms_dec.left);
}

bool mouse_click_right()
{
    return (ms_dec.right);
}

err_t mouse_install(uint64_t vector, uint64_t arg)
{
    ioapic_add(vector, 12);
}

irq_controller_t mouse_controller =
    {
        .install = mouse_install,
        .unmask = apic_unmask,
        .mask = apic_mask,
        .ack = apic_ack,
};

void mouse_init()
{
    irq_regist_irq(PS2_MOUSE_INTERRUPT_VECTOR, mouse_handler, 12, NULL, &mouse_controller, "PS2 MOUSE");

    // 启用鼠标端口
    wait_KB_write();
    io_out8(PORT_KB_CMD, KB_EN_MOUSE_INTFACE); // 0xA8

    // 发送鼠标启用命令
    wait_KB_write();
    io_out8(PORT_KB_CMD, KB_SEND2MOUSE); // 0xD4
    wait_KB_write();
    io_out8(PORT_KB_DATA, MOUSE_EN); // 0xF4

    // 必须等待ACK
    wait_KB_read();
    if (io_in8(PORT_KB_DATA) != 0xFA)
    {
        printk("Mouse enable failed\n");
    }

    // 设置鼠标采样率为100 (可选，但推荐)
    wait_KB_write();
    io_out8(PORT_KB_CMD, KB_SEND2MOUSE);
    wait_KB_write();
    io_out8(PORT_KB_DATA, 0xF3); // 设置采样率
    wait_KB_read();
    if (io_in8(PORT_KB_DATA) != 0xFA)
    {
    }

    wait_KB_write();
    io_out8(PORT_KB_CMD, KB_SEND2MOUSE);
    wait_KB_write();
    io_out8(PORT_KB_DATA, 100); // 100 samples/s
    wait_KB_read();
    if (io_in8(PORT_KB_DATA) != 0xFA)
    {
    }

    memset(&ms_dec, 0, sizeof(ms_dec));
}

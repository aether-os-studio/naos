#include <arch/x64/drivers/chars/ps2_kbd.h>
#include <drivers/kernel_logger.h>
#include <interrupt/irq_manager.h>
#include <task/task.h>
#include <arch/x64/io.h>

enum special_key_code
{
    KEY_ESC = 128,
    KEY_BACKSPACE,
    KEY_TAB,
    KEY_ENTER,
    KEY_CAPS,
    KEY_SHIFT,
    KEY_CTRL,
    KEY_ALT,
    KEY_SPACE,
    KEY_F1,
    KEY_F2,
    KEY_F3,
    KEY_F4,
    KEY_F5,
    KEY_F6,
    KEY_F7,
    KEY_F8,
    KEY_F9,
    KEY_F10,
    KEY_NUML,
    KEY_SCROLL,
    KEY_F11,
    KEY_F12,
    KEY_UP,
    KEY_DOWN,
    KEY_LEFT,
    KEY_RIGHT,
};

static char keyboard_code[0x54] = { // 未按下Shift
    0, 0x01, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b', '\t', 'q',
    'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', 10, 0, 'a', 's', 'd', 'f',
    'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm',
    ',', '.', '/', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, '7', '8', '9', '-', '4', '5', '6', '+', '1', '2', '3', '0', '.'};

static char keyboard_code1[0x54] = { // 按下Shift
    0, 0x01, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b', '\t', 'Q',
    'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', 10, 0, 'A', 'S', 'D', 'F',
    'G', 'H', 'J', 'K', 'L', ':', '\"', '~', 0, '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M',
    '<', '>', '?', 0, '*', 0, ' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, '7', 'D', '8', '-', '4', '5', '6', '+', '1', '2', '3', '0', '.'};

struct keyboard_buf kb_fifo;

void kbd_handler(uint64_t irq, void *param, struct pt_regs *regs)
{
    uint8_t x = io_in8(PORT_KB_DATA);
    parse_scan_code(x);
}

void kbd_init()
{
    kb_fifo.p_head = kb_fifo.buf;
    kb_fifo.p_tail = kb_fifo.buf;
    kb_fifo.count = 0;

    irq_regist_irq(PS2_KBD_INTERRUPT_VECTOR, kbd_handler, PS2_KBD_INTERRUPT_VECTOR - 32, NULL, &apic_controller, "PS2 KBD");

    wait_KB_write();
    io_out8(PORT_KB_CMD, 0xAD);

    while (io_in8(PORT_KB_STATUS) & KBSTATUS_OBF)
    {
        io_in8(PORT_KB_DATA);
    }

    wait_KB_write();
    io_out8(PORT_KB_CMD, KBCMD_WRITE_CMD); // 0x60
    wait_KB_write();
    io_out8(PORT_KB_DATA, KB_INIT_MODE); // 0x03

    wait_KB_write();
    io_out8(PORT_KB_CMD, 0xAE);

    wait_KB_write();
    io_out8(PORT_KB_DATA, 0xFF); // 重置命令
    wait_KB_read();
    uint8_t response = io_in8(PORT_KB_DATA);
    if (response != 0xAA)
    {
        printk("Keyboard reset failed: 0x%x\n", response);
    }

    wait_KB_write();
    io_out8(PORT_KB_DATA, 0xF4); // 启用数据报告
    wait_KB_read();
    if (io_in8(PORT_KB_DATA) != 0xFA)
    {
        printk("Keyboard enable failed\n");
    }
}

extern uint64_t cpu_count;

void parse_scan_code(uint8_t x)
{
    if (x == 0x2a || x == 0x36)
    {
        kb_fifo.shift = 1;
    }
    else if (x == 0x1d)
    {
        kb_fifo.ctrl = 1;
    }
    else if (x == 0x3a)
    {
        kb_fifo.caps = kb_fifo.caps ^ 1;
    }
    else if (x == 0xaa || x == 0xb6)
    {
        kb_fifo.shift = 0;
    }
    else if (x == 0x9d)
    {
        kb_fifo.ctrl = 0;
    }

    if (kb_fifo.ctrl && x == 0x2e && current_task)
    {
    }
    else if (x < 0x80)
    {
        *kb_fifo.p_head = x;
        kb_fifo.count++;
        kb_fifo.p_head++;
    }

    if (kb_fifo.p_head >= kb_fifo.buf + KB_BUF_SIZE)
    {
        memset(kb_fifo.buf, 0, KB_BUF_SIZE - 1);
        kb_fifo.p_head = kb_fifo.buf;
    }
}

uint8_t get_keyboard_input()
{
    if (kb_fifo.p_tail != kb_fifo.p_head)
    {
        uint8_t temp = 0;

        uint8_t x = *kb_fifo.p_tail;

        if (x == 0x48)
            temp = (uint8_t)-1;
        else if (x == 0x50)
            temp = (uint8_t)-2;
        else if (x == 0x4b)
            temp = (uint8_t)-3;
        else if (x == 0x4d)
            temp = (uint8_t)-4;
        else
        {
            temp = keyboard_code[x];
            if (kb_fifo.shift == 1 || kb_fifo.caps == 1)
            {
                temp = keyboard_code1[x];
            }
        }

        kb_fifo.p_tail++;

        if (kb_fifo.p_tail >= kb_fifo.buf + KB_BUF_SIZE)
        {
            kb_fifo.p_tail = kb_fifo.buf;
        }

        return temp;
    }

    return 0;
}

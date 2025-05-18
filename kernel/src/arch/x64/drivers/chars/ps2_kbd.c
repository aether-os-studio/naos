#include <arch/x64/drivers/chars/ps2_kbd.h>
#include <drivers/kernel_logger.h>
#include <interrupt/irq_manager.h>
#include <task/task.h>
#include <arch/x64/io.h>
#include <fs/vfs/dev.h>
#include <task/task.h>

// Very bare bones, and basic keyboard driver
// Copyright (C) 2024 Panagiotis

char character_table[] = {
    0,
    27,
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    '0',
    '-',
    '=',
    0,
    9,
    'q',
    'w',
    'e',
    'r',
    't',
    'y',
    'u',
    'i',
    'o',
    'p',
    '[',
    ']',
    0,
    0,
    'a',
    's',
    'd',
    'f',
    'g',
    'h',
    'j',
    'k',
    'l',
    ';',
    '\'',
    '`',
    0,
    '\\',
    'z',
    'x',
    'c',
    'v',
    'b',
    'n',
    'm',
    ',',
    '.',
    '/',
    0,
    '*',
    0,
    ' ',
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x1B,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x0E,
    0x1C,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    '/',
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x1E,
    0x1F,
    0x20,
    0x21,
    0x22,
    0x23,
    0x24,
    0x25,
    0x26,
    0x27,
    0x28,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x2C,
};

char shiftedCharacterTable[] = {
    0,
    27,
    '!',
    '@',
    '#',
    '$',
    '%',
    '^',
    '&',
    '*',
    '(',
    ')',
    '_',
    '+',
    0,
    9,
    'Q',
    'W',
    'E',
    'R',
    'T',
    'Y',
    'U',
    'I',
    'O',
    'P',
    '{',
    '}',
    0,
    0,
    'A',
    'S',
    'D',
    'F',
    'G',
    'H',
    'J',
    'K',
    'L',
    ':',
    '"',
    '~',
    0,
    '|',
    'Z',
    'X',
    'C',
    'V',
    'B',
    'N',
    'M',
    '<',
    '>',
    '?',
    0,
    '*',
    0,
    ' ',
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x1B,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x0E,
    0x1C,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    '?',
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x1E,
    0x1F,
    0x20,
    0x21,
    0x22,
    0x23,
    0x24,
    0x25,
    0x26,
    0x27,
    0x28,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0x2C,
};

const uint8_t evdevTable[89] = {
    0,
    KEY_ESC,
    KEY_1,
    KEY_2,
    KEY_3,
    KEY_4,
    KEY_5,
    KEY_6,
    KEY_7,
    KEY_8,
    KEY_9,
    KEY_0,
    KEY_MINUS,
    KEY_EQUAL,
    KEY_BACKSPACE,
    KEY_TAB,
    KEY_Q,
    KEY_W,
    KEY_E,
    KEY_R,
    KEY_T,
    KEY_Y,
    KEY_U,
    KEY_I,
    KEY_O,
    KEY_P,
    KEY_LEFTBRACE,
    KEY_RIGHTBRACE,
    KEY_ENTER,
    KEY_LEFTCTRL,
    KEY_A,
    KEY_S,
    KEY_D,
    KEY_F,
    KEY_G,
    KEY_H,
    KEY_J,
    KEY_K,
    KEY_L,
    KEY_SEMICOLON,
    KEY_APOSTROPHE,
    KEY_GRAVE,
    KEY_LEFTSHIFT,
    KEY_BACKSLASH,
    KEY_Z,
    KEY_X,
    KEY_C,
    KEY_V,
    KEY_B,
    KEY_N,
    KEY_M,
    KEY_COMMA,
    KEY_DOT,
    KEY_SLASH,
    KEY_RIGHTSHIFT,
    KEY_KPASTERISK,
    KEY_LEFTALT,
    KEY_SPACE,
    KEY_CAPSLOCK,
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
    KEY_NUMLOCK,
    KEY_SCROLLLOCK,
    KEY_KP7,
    KEY_UP, // KEY_KP8
    KEY_KP9,
    KEY_KPMINUS,
    KEY_LEFT, // KEY_KP4
    KEY_KP5,
    KEY_RIGHT, // KEY_KP6
    KEY_KPPLUS,
    KEY_KP1,
    KEY_DOWN, // KEY_KP2
    KEY_KP3,
    KEY_INSERT, // KEY_KP0
    KEY_DELETE, // KEY_KPDOT
    0,
    0,
    0,
    KEY_F11,
    KEY_F12,
};

// it's just a bitmap to accurately track press/release/repeat ops
#define EVDEV_INTERNAL_SIZE (((sizeof(evdevTable) / sizeof(evdevTable[0]) + 7) / 8))

uint8_t evdevInternal[EVDEV_INTERNAL_SIZE] = {0};

uint8_t lastPressed = 0;

dev_input_event_t *kb_event = NULL;

void kb_evdev_generate(uint8_t raw)
{
    if (!kb_event)
        return;

    uint8_t index = 0;
    bool clicked = false;
    if (raw <= 0x58)
    {
        clicked = true;
        index = raw;
    }
    else if (raw <= 0xD8)
    {
        clicked = false;
        index = raw - 0x80;
    }
    else
        return;

    if (index > 88)
        return;
    uint8_t evdevCode = evdevTable[index];
    if (!evdevCode)
        return;

    bool oldstate = evdevInternal[index / 8];
    if (!oldstate && clicked)
    {
        // was not clicked previously, now clicked (click)
        input_generate_event(kb_event, EV_KEY, evdevCode, 1);
        lastPressed = evdevCode;
    }
    else if (oldstate && clicked)
    {
        // was clicked previously, now clicked (repeat)
        if (evdevCode != lastPressed)
            return; // no need to re-set it on the bitmap
        input_generate_event(kb_event, EV_KEY, evdevCode, 2);
    }
    else if (oldstate && !clicked)
    {
        // was clicked previously, now not clicked (release)
        input_generate_event(kb_event, EV_KEY, evdevCode, 0);
    }
    input_generate_event(kb_event, EV_SYN, SYN_REPORT, 0);

    evdevInternal[index / 8] |= (clicked << (index % 8));
}

bool ctrled = false;

bool shifted = false;
bool capsLocked = false;

char *kbBuff = 0;
uint32_t kbCurr = 0;
uint32_t kbMax = 0;
task_t *kb_task = NULL;

void kb_reset()
{
    kbBuff = 0;
    kbCurr = 0;
    kbMax = 0;
    kb_task = NULL;
}

void kb_finalise_stream()
{
    task_t *task = kb_task;
    if (task)
    {
        task->tmp_rec_v = kbCurr;
        task_unblock(kb_task, EOK);
    }
    kb_reset();
}

char handle_kb_event()
{
    uint8_t scan_code = io_in8(PORT_KB_DATA);
    kb_evdev_generate(scan_code);

    if (scan_code == 0xE0)
    {
        uint8_t extended_code = io_in8(PORT_KB_DATA);
        switch (extended_code)
        {
        case 0x48:
            return KEY_BUTTON_UP;
        case 0x50:
            return KEY_BUTTON_DOWN;
        case 0x4b:
            return KEY_BUTTON_LEFT;
        case 0x4d:
            return KEY_BUTTON_RIGHT;
        default:
            return 0;
        }
    }

    /* No, I will not fix/improve the rest, idc about the kernel shell */

    // Shift checks
    if (shifted == 1 && scan_code & 0x80)
    {
        if ((scan_code & 0x7F) == 42) // & 0x7F clears the release
        {
            shifted = 0;
            return 0;
        }
    }

    if (ctrled == 1 && scan_code & 0x80)
    {
        if ((scan_code & 0x7F) == 0x1d) // & 0x7F clears the release
        {
            ctrled = false;
            return 0;
        }
    }

    if (scan_code < sizeof(character_table) && !(scan_code & 0x80))
    {
        char character = (shifted || capsLocked) ? shiftedCharacterTable[scan_code] : character_table[scan_code];

        if (character != 0)
        { // Normal char
            return character;
        }

        switch (scan_code)
        {
        case SCANCODE_ENTER:
            return CHARACTER_ENTER;
            break;
        case SCANCODE_BACK:
            return CHARACTER_BACK;
            break;
        case SCANCODE_SHIFT:
            shifted = true;
            break;
        case 0x1d:
            ctrled = true;
            break;
        case SCANCODE_CAPS:
            capsLocked = !capsLocked;
            break;
        }
    }

    return 0;
}

// used by the kernel atm
uint32_t read_str(char *buffstr)
{
    while (kb_is_ocupied())
        arch_pause();

    task_t *task = tasks[0];
    if (!task)
        return 0;

    while (kbBuff)
    {
        arch_enable_interrupt();
        arch_pause();
    }
    uint32_t ret = task->tmp_rec_v;
    buffstr[ret] = '\0';
    return ret;
}

uint8_t kb_special_key_status = 0;
char kb_special_key = 0;

bool task_read(task_t *task, char *buff, uint32_t limit, bool change_state)
{
    while (kb_is_ocupied())
    {
        arch_enable_interrupt();
        arch_pause();
    }

    kbBuff = buff;
    kbCurr = 0;
    kbMax = limit;
    kb_task = task;

    if (kb_special_key_status == 1) // 上下左右
    {
        kbBuff[kbCurr++] = '[';
        kb_special_key_status = 2;
        kb_finalise_stream();
        return true;
    }
    else if (kb_special_key_status == 2) // 上下左右第二阶段
    {
        kbBuff[kbCurr++] = kb_special_key;
        kb_special_key_status = 0;
        kb_special_key = 0;
        kb_finalise_stream();
        return true;
    }

    if (change_state)
        task->state = TASK_BLOCKING;

    return true;
}

void keyboard_handler(uint64_t irq_num, void *data, struct pt_regs *regs);

void kbd_init()
{
    kb_reset();

    irq_regist_irq(PS2_KBD_INTERRUPT_VECTOR, keyboard_handler, PS2_KBD_INTERRUPT_VECTOR - 32, NULL, &apic_controller, "PS2 KBD");

    wait_KB_write();
    io_out8(PORT_KB_CMD, KBCMD_WRITE_CMD);
    wait_KB_read();
    io_out8(PORT_KB_DATA, KB_INIT_MODE);

    wait_KB_write();
    io_out8(PORT_KB_DATA, 0xF0);
    wait_KB_write();
    io_out8(PORT_KB_DATA, 0x02);

    wait_KB_read();

    for (uint64_t i = 0; i < MAX_DEV_NUM; i++)
    {
        if (devfs_handles[i] != NULL && !strncmp(devfs_handles[i]->name, "event0", MAX_DEV_NAME_LEN))
        {
            devfs_handle_t handle = devfs_handles[i];
            kb_event = (dev_input_event_t *)handle->data;
            break;
        }
    }

    if (!kb_event)
        return;

    strncpy(kb_event->uniq, "ps2kbd", sizeof(kb_event->uniq));
}

void kb_char(task_t *task, char out)
{
    if (task->term.c_lflag & ECHO)
        printk("%c", out);
    if (kbCurr < kbMax)
        kbBuff[kbCurr++] = out;
    if (!(task->term.c_lflag & ICANON))
        kb_finalise_stream();
}

void keyboard_handler(uint64_t irq_num, void *data, struct pt_regs *regs)
{
    (void)irq_num;
    (void)data;
    (void)regs;

    char out = handle_kb_event();
    if (!out)
        return;

    task_t *task = kb_task;

    if (!task)
        return;

    switch ((uint8_t)out)
    {
    case CHARACTER_ENTER:
        // kbBuff[kbCurr] = '\0';
        if (task->term.c_lflag & ICANON)
            kb_finalise_stream();
        else
            kb_char(task, out);
        break;
    case CHARACTER_BACK:
        if (task->term.c_lflag & ICANON && kbCurr > 0)
        {
            uint32_t back_steps = (kbCurr >= 3 &&
                                   kbBuff[kbCurr - 3] == '\x1b' &&
                                   kbBuff[kbCurr - 2] == '[')
                                      ? 3
                                      : 1;

            kbCurr = (kbCurr >= back_steps) ? kbCurr - back_steps : 0;
            memset(&kbBuff[kbCurr], 0, back_steps);
        }

        else if (!(task->term.c_lflag & ICANON))
            kb_char(task, out);
        break;
    case KEY_BUTTON_UP:
        kb_char(task, '\x1b');
        kb_special_key_status = 1;
        kb_special_key = 'A';
        break;
    case KEY_BUTTON_DOWN:
        kb_char(task, '\x1b');
        kb_special_key_status = 1;
        kb_special_key = 'B';
        break;
    case KEY_BUTTON_LEFT:
        kb_char(task, '\x1b');
        kb_special_key_status = 1;
        kb_special_key = 'D';
        break;
    case KEY_BUTTON_RIGHT:
        kb_char(task, '\x1b');
        kb_special_key_status = 1;
        kb_special_key = 'C';
        break;
    default:
        if (ctrled)
            out &= 0x1f;
        kb_char(task, out);
        break;
    }

    if (task->state == TASK_BLOCKING)
        task->state = TASK_READY;
}

bool kb_is_ocupied() { return !!kbBuff; }

size_t kb_event_bit(void *data, uint64_t request, void *arg)
{
    size_t number = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);

    size_t ret = (size_t)-ENOSYS;
    switch (number)
    {
    case 0x20:
    {
        size_t out = (1 << EV_SYN) | (1 << EV_KEY);
        ret = MIN(sizeof(size_t), size);
        memcpy(arg, &out, ret);
        break;
    }
    case (0x20 + EV_SW):
    case (0x20 + EV_MSC):
    case (0x20 + EV_SND):
    case (0x20 + EV_LED):
    case (0x20 + EV_REL):
    case (0x20 + EV_ABS):
    {
        ret = MIN(sizeof(size_t), size);
        break;
    }
    case (0x20 + EV_FF):
    {
        ret = MIN(16, size);
        break;
    }
    case (0x20 + EV_KEY):
    {
        uint8_t map[96] = {0};
        for (int i = KEY_ESC; i <= KEY_MENU; i++)
            map[i / 8] |= (1 << (i % 8));
        ret = MIN(96, size);
        memcpy(arg, map, ret);
        break;
    }
    case 0x18: // EVIOCGKEY()
    {
        uint8_t map[96];
        memset(map, 0, sizeof(map));
        ret = MIN(96, size);
        memcpy(arg, map, ret);
        break;
    }
    case 0x19: // EVIOCGLED()
        ret = MIN(8, size);
        break;
    case 0x1b: // EVIOCGSW()
        ret = MIN(8, size);
        break;
    default:
        break;
    }

    return ret;
}

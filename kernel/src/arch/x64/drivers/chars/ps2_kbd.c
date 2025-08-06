#include <arch/x64/drivers/chars/ps2_kbd.h>
#include <drivers/kernel_logger.h>
#include <interrupt/irq_manager.h>
#include <arch/arch.h>
#include <task/task.h>
#include <arch/x64/io.h>
#include <fs/vfs/dev.h>
#include <task/task.h>
#include <libs/keys.h>

extern bool ctrled;

static char cache_buffer[8] = {0};

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

    if (cache_buffer[0] != 0) // 上下左右
    {
        uint32_t offset = (limit > 2) ? 2 : limit;
        memcpy(kbBuff, cache_buffer, offset);
        memset(cache_buffer, 0, offset);
        memmove(cache_buffer, &cache_buffer[offset], sizeof(cache_buffer) - offset);
        kb_reset();
        return true;
    }

    if (change_state)
        task_block(task, TASK_BLOCKING, -1);

    return true;
}

void keyboard_handler(uint64_t irq_num, void *data, struct pt_regs *regs);

extern dev_input_event_t *kb_event;

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

    memset(cache_buffer, 0, sizeof(cache_buffer));

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

    uint8_t scancode = io_in8(PORT_KB_DATA);

    char out = 0;

    if (scancode == 0xE0)
        out = handle_kb_event(scancode, io_in8(PORT_KB_DATA), 0);
    else if (scancode == 0xE1)
        out = handle_kb_event(scancode, io_in8(PORT_KB_DATA), io_in8(PORT_KB_DATA));
    else
        out = handle_kb_event(scancode, 0, 0);
    if (!out)
        return;

    task_t *task = kb_task;

    if (!task)
        return;

    // if (ctrled && out == 'c')
    // {
    //     kb_finalise_stream();
    //     task->signal |= SIGMASK(SIGINT);
    //     task_unblock(task, SIGINT);
    //     return;
    // }

    switch ((uint8_t)out)
    {
    case CHARACTER_ENTER:
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
        if (kbMax - kbCurr >= 2)
        {
            kb_char(task, '[');
            kb_char(task, 'A');
        }
        else
        {
            cache_buffer[0] = '[';
            cache_buffer[1] = 'A';
        }
        break;
    case KEY_BUTTON_DOWN:
        kb_char(task, '\x1b');
        if (kbMax - kbCurr >= 2)
        {
            kb_char(task, '[');
            kb_char(task, 'B');
        }
        else
        {
            cache_buffer[0] = '[';
            cache_buffer[1] = 'B';
        }
        break;
    case KEY_BUTTON_LEFT:
        kb_char(task, '\x1b');
        if (kbMax - kbCurr >= 2)
        {
            kb_char(task, '[');
            kb_char(task, 'D');
        }
        else
        {
            cache_buffer[0] = '[';
            cache_buffer[1] = 'D';
        }
        break;
    case KEY_BUTTON_RIGHT:
        kb_char(task, '\x1b');
        if (kbMax - kbCurr >= 2)
        {
            kb_char(task, '[');
            kb_char(task, 'C');
        }
        else
        {
            cache_buffer[0] = '[';
            cache_buffer[1] = 'C';
        }
        break;
    default:
        if (ctrled)
            out &= 0x1f;
        kb_char(task, out);
        break;
    }
}

void push_kb_char(char c)
{
    kb_char(current_task, c);
}

bool kb_is_ocupied() { return !!kbBuff; }

struct input_repeat_params
{
    int delay;
    int period;
};

size_t kb_event_bit(void *data, uint64_t request, void *arg)
{
    size_t number = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);

    size_t ret = (size_t)-ENOSYS;
    switch (number)
    {
    case 0x03:
    {
        struct input_repeat_params *params = arg;
        params->delay = 500;
        params->period = 50;
        break;
    }
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
    case 0xa0:
        dev_input_event_t *event = data;
        event->clock_id = *(int *)arg;
        ret = 0;
        break;
    default:
        printk("kb_event_bit(): Unsupported ioctl: request = %#018lx\n", request);
        break;
    }

    return ret;
}

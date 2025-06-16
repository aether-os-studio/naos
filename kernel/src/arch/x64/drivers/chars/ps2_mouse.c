#include <arch/x64/drivers/chars/ps2_kbd.h>
#include <arch/x64/drivers/chars/ps2_mouse.h>
#include <interrupt/irq_manager.h>
#include <arch/x64/io.h>
#include <arch/arch.h>
#include <task/task.h>
#include <fs/vfs/dev.h>
#include <drivers/fb.h>

int64_t mouse_install(uint64_t vector, uint64_t arg)
{
    ioapic_add(vector, 12);

    return 0;
}

irq_controller_t mouse_controller =
    {
        .install = mouse_install,
        .unmask = apic_unmask,
        .mask = apic_mask,
        .ack = apic_ack,
};

void mouse_wait(uint8_t a_type)
{
    uint32_t timeout = 1000;
    if (!a_type)
    {
        while (--timeout)
        {
            if (io_in8(PORT_KB_STATUS) & MOUSE_BBIT)
                break;
        }
    }
    else
    {
        while (--timeout)
        {
            if (!((io_in8(PORT_KB_STATUS) & MOUSE_ABIT)))
                break;
        }
    }
}

void mouse_write(uint8_t write)
{
    mouse_wait(1);
    io_out8(PORT_KB_STATUS, KB_SEND2MOUSE);
    mouse_wait(1);
    io_out8(PORT_KB_DATA, write);
}

uint8_t mouse_read()
{
    mouse_wait(0);
    char t = io_in8(PORT_KB_DATA);
    return t;
}

int mouseCycle = 0;

int mouse1 = 0;
int mouse2 = 0;

int gx = 0;
int gy = 0;

bool clickedLeft = false;
bool clickedRight = true;

dev_input_event_t *mouse_event = NULL;

void mouse_handler(uint64_t irq, void *param, struct pt_regs *regs)
{
    uint8_t byte = mouse_read();

    if (!mouse_event)
        return;

    // return;
    // rest are just for demonstration

    // debugf("%d %d %d\n", byte1, byte2, byte3);
    if (mouseCycle == 0)
        mouse1 = byte;
    else if (mouseCycle == 1)
        mouse2 = byte;
    else
    {
        int mouse3 = byte;

        do
        {
            int x = mouse2;
            int y = mouse3;
            if (x && mouse1 & (1 << 4))
                x -= 0x100;
            if (y && mouse1 & (1 << 5))
                y -= 0x100;

            gx += x;
            gy += -y;
            if (gx < 0)
                gx = 0;
            if (gy < 0)
                gy = 0;

            size_t addr;
            size_t width;
            size_t height;
            size_t bpp;
            size_t cols;
            size_t rows;

            os_terminal_get_screen_info(&addr, &width, &height, &bpp, &cols, &rows);

            if ((size_t)gx > width)
                gx = width;
            if ((size_t)gy > height)
                gy = height;

            bool click = mouse1 & (1 << 0);
            bool rclick = mouse1 & (1 << 1);

            if (clickedLeft && !click)
                input_generate_event(mouse_event, EV_KEY, BTN_LEFT, 0);
            if (!clickedLeft && click)
                input_generate_event(mouse_event, EV_KEY, BTN_LEFT, 1);

            if (clickedRight && !rclick)
                input_generate_event(mouse_event, EV_KEY, BTN_RIGHT, 0);
            if (!clickedRight && rclick)
                input_generate_event(mouse_event, EV_KEY, BTN_RIGHT, 1);

            clickedRight = rclick;
            clickedLeft = click;

            input_generate_event(mouse_event, EV_REL, REL_X, x);
            input_generate_event(mouse_event, EV_REL, REL_Y, -y);
            input_generate_event(mouse_event, EV_SYN, SYN_REPORT, 0);

            (void)mouse3;
        } while (0);
    }

    mouseCycle++;
    if (mouseCycle > 2)
        mouseCycle = 0;
}

void mouse_init()
{
    irq_regist_irq(PS2_MOUSE_INTERRUPT_VECTOR, mouse_handler, 12, NULL, &mouse_controller, "PS2 MOUSE");

    mouse_wait(1);
    io_out8(0x64, 0xA8);

    // enable interrupts
    mouse_wait(1);
    io_out8(0x64, 0x20);
    mouse_wait(0);
    uint8_t status;
    status = (io_in8(0x60) | 2);
    mouse_wait(1);
    io_out8(0x64, 0x60);
    mouse_wait(1);
    io_out8(0x60, status);

    // default settings
    mouse_write(0xF6);
    mouse_read();

    // enable device
    mouse_write(0xF4);
    mouse_read();

    for (uint64_t i = 0; i < MAX_DEV_NUM; i++)
    {
        if (devfs_handles[i] != NULL && !strncmp(devfs_handles[i]->name, "event1", MAX_DEV_NAME_LEN))
        {
            devfs_handle_t handle = devfs_handles[i];
            mouse_event = (dev_input_event_t *)handle->data;
            break;
        }
    }

    if (!mouse_event)
        return;

    strncpy(mouse_event->uniq, "ps2mouse", sizeof(mouse_event->uniq));
}

size_t mouse_event_bit(void *data, uint64_t request, void *arg)
{
    size_t addr;
    size_t width;
    size_t height;
    size_t bpp;
    size_t cols;
    size_t rows;

    os_terminal_get_screen_info(&addr, &width, &height, &bpp, &cols, &rows);

    size_t number = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);

    size_t ret = (size_t)-ENOSYS;
    switch (number)
    {
    case 0x20:
    {
        size_t out = (1 << EV_SYN) | (1 << EV_KEY) | (1 << EV_REL);
        ret = MIN(sizeof(size_t), size);
        memcpy(arg, &out, ret);
        break;
    }
    case (0x20 + EV_SW):
    case (0x20 + EV_MSC):
    case (0x20 + EV_SND):
    case (0x20 + EV_LED):
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
    case (0x20 + EV_REL):
    {
        size_t out = (1 << REL_X) | (1 << REL_Y);
        ret = MIN(sizeof(size_t), size);
        memcpy(arg, &out, ret);
        break;
    }
    case (0x20 + EV_KEY):
    {
        uint8_t map[96] = {0};
        map[BTN_RIGHT / 8] |= (1 << (BTN_RIGHT % 8));
        map[BTN_LEFT / 8] |= (1 << (BTN_LEFT % 8));
        ret = MIN(96, size);
        memcpy(arg, map, ret);
        break;
    }
    case (0x40 + ABS_X):
    {
        struct input_absinfo *target = (struct input_absinfo *)arg;
        memset(target, 0, sizeof(struct input_absinfo));
        target->value = 0; // todo
        target->minimum = 0;
        target->maximum = width;
        ret = 0;
        break;
    }
    case (0x40 + ABS_Y):
    {
        struct input_absinfo *target = (struct input_absinfo *)arg;
        memset(target, 0, sizeof(struct input_absinfo));
        target->value = 0; // todo
        target->minimum = 0;
        target->maximum = height;
        ret = 0;
        break;
    }
    case 0x18: // EVIOCGKEY()
        ret = MIN(96, size);
        break;
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

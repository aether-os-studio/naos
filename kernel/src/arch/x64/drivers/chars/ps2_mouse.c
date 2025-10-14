#include <arch/x64/drivers/chars/ps2_kbd.h>
#include <arch/x64/drivers/chars/ps2_mouse.h>
#include <interrupt/irq_manager.h>
#include <arch/x64/io.h>
#include <arch/arch.h>
#include <task/task.h>
#include <fs/vfs/dev.h>
#include <drivers/fb.h>
#include <libs/keys.h>

int64_t mouse_install(uint64_t vector, uint64_t arg) {
    ioapic_add(vector, 12);

    return 0;
}

irq_controller_t mouse_controller = {
    .install = mouse_install,
    .unmask = apic_unmask,
    .mask = apic_mask,
    .ack = apic_ack,
};

void mouse_wait(uint8_t a_type) {
    uint32_t timeout = 100000;
    if (!a_type) {
        while (--timeout) {
            if (io_in8(PORT_KB_STATUS) & MOUSE_BBIT)
                break;
        }
    } else {
        while (--timeout) {
            if (!((io_in8(PORT_KB_STATUS) & MOUSE_ABIT)))
                break;
        }
    }
}

void mouse_write(uint8_t write) {
    mouse_wait(1);
    io_out8(PORT_KB_CMD, KB_SEND2MOUSE);
    mouse_wait(1);
    io_out8(PORT_KB_DATA, write);
}

uint8_t mouse_read() {
    mouse_wait(0);
    char t = io_in8(PORT_KB_DATA);
    return t;
}

int mouseCycle = 0xffffffff;

int mouse1 = 0;
int mouse2 = 0;
int mouse3 = 0;

int gx = 0;
int gy = 0;

extern bool clickedLeft;
extern bool clickedRight;

extern dev_input_event_t *mouse_event;

spinlock_t mouse_irq_lock = {0};

bool has_wheel = false;

extern void handle_mouse_event(uint8_t flag, int8_t x, int8_t y, int8_t z);

// 提取的数据处理函数
void process_mouse_packet(uint8_t b1, uint8_t b2, uint8_t b3, int8_t wheel) {
    int x = b2;
    int y = b3;

    if (x && (b1 & (1 << 4)))
        x |= 0xffffff00;
    if (y && (b1 & (1 << 5)))
        y |= 0xffffff00;

    gx += x;
    gy += -y;

    // 边界检查...
    if (gx < 0)
        gx = 0;
    if (gy < 0)
        gy = 0;
    if ((size_t)gx > framebuffer->width)
        gx = framebuffer->width;
    if ((size_t)gy > framebuffer->height)
        gy = framebuffer->height;

    handle_mouse_event(b1, x, -y, -wheel); // 添加 wheel 参数
}

void mouse_handler(uint64_t irq, void *param, struct pt_regs *regs) {
    uint8_t byte = mouse_read();

    if (!mouse_event)
        return;

    spin_lock(&mouse_irq_lock);

    if (mouseCycle == 0xffffffff) {
        if (byte == 0xfa) {
            mouseCycle = 0;
        }
    } else if (mouseCycle == 0) {
        if ((byte & 0xc8) == 0x08) {
            mouse1 = byte;
            mouseCycle = 1;
        }
    } else if (mouseCycle == 1) {
        mouse2 = byte;
        mouseCycle = 2;
    } else if (mouseCycle == 2) {
        mouse3 = byte;
        mouseCycle = has_wheel ? 3 : 0; // 如果有滚轮，继续读取第4字节

        if (!has_wheel) {
            process_mouse_packet(mouse1, mouse2, mouse3, 0);
        }
    } else if (mouseCycle == 3) {    // 滚轮数据
        int8_t wheel = (int8_t)byte; // 有符号的滚轮值

        process_mouse_packet(mouse1, mouse2, mouse3, wheel);
        mouseCycle = 0;
    }

    spin_unlock(&mouse_irq_lock);
}

// 在鼠标初始化函数中添加
bool mouse_enable_wheel(void) {
    // 发送魔术序列启用滚轮
    mouse_write(0xf3); // Set Sample Rate
    mouse_read();      // ACK
    mouse_write(200);
    mouse_read(); // ACK

    mouse_write(0xf3);
    mouse_read();
    mouse_write(100);
    mouse_read();

    mouse_write(0xf3);
    mouse_read();
    mouse_write(80);
    mouse_read();

    // 读取设备 ID
    mouse_write(0xf2); // Get Device ID
    mouse_read();      // ACK
    uint8_t id = mouse_read();

    return (id == 0x03); // 0x03 表示支持滚轮
}

void mouse_init() {
    irq_regist_irq(PS2_MOUSE_INTERRUPT_VECTOR, mouse_handler, 12, NULL,
                   &mouse_controller, "PS2 MOUSE");

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

    has_wheel = mouse_enable_wheel();

    for (uint64_t i = 0; i < MAX_DEV_NUM; i++) {
        if (devfs_handles[i] != NULL &&
            !strncmp(devfs_handles[i]->name, "event1", MAX_DEV_NAME_LEN)) {
            devfs_handle_t handle = devfs_handles[i];
            mouse_event = (dev_input_event_t *)handle->data;
            break;
        }
    }

    if (!mouse_event)
        return;

    strncpy(mouse_event->uniq, "ps2mouse", sizeof(mouse_event->uniq));
    mouse_event->devname = strdup("input/event1");
}

struct input_repeat_params {
    int delay;
    int period;
};

size_t mouse_event_bit(void *data, uint64_t request, void *arg) {
    size_t number = _IOC_NR(request);
    size_t size = _IOC_SIZE(request);

    size_t ret = (size_t)-ENOSYS;
    switch (number) {
    // case 0x03:
    // {
    //     struct input_repeat_params *params = arg;
    //     params->delay = 500;
    //     params->period = 50;
    //     break;
    // }
    case 0x20: {
        size_t out = (1 << EV_KEY) | (1 << EV_REL);
        ret = MIN(sizeof(size_t), size);
        memcpy(arg, &out, ret);
        break;
    }
    case (0x20 + EV_SW):
    case (0x20 + EV_MSC):
    case (0x20 + EV_SND):
    case (0x20 + EV_LED):
    case (0x20 + EV_ABS): {
        *(size_t *)arg = 0;
        ret = MIN(sizeof(size_t), size);
        break;
    }
    case (0x20 + EV_FF): {
        *(size_t *)arg = 0;
        ret = MIN(16, size);
        break;
    }
    case (0x20 + EV_REL): {
        size_t out = (1 << REL_X) | (1 << REL_Y);
        ret = MIN(sizeof(size_t), size);
        memcpy(arg, &out, ret);
        break;
    }
    case (0x20 + EV_KEY): {
        uint8_t map[96] = {0};
        map[BTN_RIGHT / 8] |= (1 << (BTN_RIGHT % 8));
        map[BTN_LEFT / 8] |= (1 << (BTN_LEFT % 8));
        ret = MIN(96, size);
        memcpy(arg, map, ret);
        break;
    }
    case (0x40 + ABS_X): {
        struct input_absinfo *target = (struct input_absinfo *)arg;
        memset(target, 0, sizeof(struct input_absinfo));
        target->value = 0; // todo
        target->minimum = 0;
        target->maximum = framebuffer->width;
        ret = 0;
        break;
    }
    case (0x40 + ABS_Y): {
        struct input_absinfo *target = (struct input_absinfo *)arg;
        memset(target, 0, sizeof(struct input_absinfo));
        target->value = 0; // todo
        target->minimum = 0;
        target->maximum = framebuffer->height;
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
    case 0xa0:
        dev_input_event_t *event = data;
        event->clock_id = *(int *)arg;
        ret = 0;
        break;
    default:
        printk("mouse_event_bit(): Unsupported ioctl: request = %#018lx\n",
               request);
        break;
    }

    return ret;
}

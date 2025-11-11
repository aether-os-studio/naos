#include "kb.h"
#include <task/task.h>
#include <fs/vfs/dev.h>
#include <libs/keys.h>

dev_input_event_t *kb_input_event = NULL;
dev_input_event_t *mouse_input_event = NULL;

size_t kb_event_bit(void *data, uint64_t request, void *arg) {
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
        size_t out = (1 << EV_KEY);
        ret = MIN(sizeof(size_t), size);
        memcpy(arg, &out, ret);
        break;
    }
    case (0x20 + EV_SW):
    case (0x20 + EV_MSC):
    case (0x20 + EV_SND):
    case (0x20 + EV_LED):
    case (0x20 + EV_REL):
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
    case (0x20 + EV_KEY): {
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
        *(size_t *)arg = 0;
        ret = MIN(8, size);
        break;
    case 0x1b: // EVIOCGSW()
        *(size_t *)arg = 0;
        ret = MIN(8, size);
        break;
    case 0xa0:
        dev_input_event_t *event = data;
        event->clock_id = *(int *)arg;
        ret = 0;
        break;
    default:
        printk("kb_event_bit(): Unsupported ioctl: request = %#018lx\n",
               request);
        break;
    }

    return ret;
}

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
        size_t out = (1 << REL_X) | (1 << REL_Y) | (1 << REL_WHEEL);
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

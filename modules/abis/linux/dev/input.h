#pragma once

#include <drivers/bus/bus.h>

typedef enum input_event_from {
    INPUT_FROM_PS2,
    INPUT_FROM_USB,
} input_event_from_t;

#define INPUT_BITMAP_BYTES(nr) (((nr) + 7) / 8)

typedef struct input_dev_desc {
    const char *uevent_append;
    input_event_from_t from;
    bus_device_t *parent_bus_device;
    struct input_id inputid;
    size_t properties;
    uint8_t evbit[INPUT_BITMAP_BYTES(EV_CNT)];
    uint8_t keybit[INPUT_BITMAP_BYTES(KEY_CNT)];
    uint8_t relbit[INPUT_BITMAP_BYTES(REL_CNT)];
    uint8_t absbit[INPUT_BITMAP_BYTES(ABS_CNT)];
    struct input_absinfo absinfo[ABS_CNT];
} input_dev_desc_t;

static inline void input_bitmap_set(uint8_t *bitmap, size_t bit) {
    bitmap[bit / 8] |= (1u << (bit % 8));
}

static inline bool input_bitmap_test(const uint8_t *bitmap, size_t bit) {
    return (bitmap[bit / 8] & (1u << (bit % 8))) != 0;
}

static inline void input_dev_desc_set_event(input_dev_desc_t *desc,
                                            uint16_t type) {
    if (type < EV_CNT)
        input_bitmap_set(desc->evbit, type);
}

static inline void input_dev_desc_set_key(input_dev_desc_t *desc,
                                          uint16_t code) {
    if (code < KEY_CNT) {
        input_dev_desc_set_event(desc, EV_KEY);
        input_bitmap_set(desc->keybit, code);
    }
}

static inline void input_dev_desc_set_rel(input_dev_desc_t *desc,
                                          uint16_t code) {
    if (code < REL_CNT) {
        input_dev_desc_set_event(desc, EV_REL);
        input_bitmap_set(desc->relbit, code);
    }
}

static inline void input_dev_desc_set_abs(input_dev_desc_t *desc, uint16_t code,
                                          int32_t minimum, int32_t maximum) {
    if (code < ABS_CNT) {
        input_dev_desc_set_event(desc, EV_ABS);
        input_bitmap_set(desc->absbit, code);
        desc->absinfo[code].minimum = minimum;
        desc->absinfo[code].maximum = maximum;
    }
}

static inline void input_dev_desc_set_property(input_dev_desc_t *desc,
                                               uint16_t property) {
    if (property < (sizeof(size_t) * 8))
        desc->properties |= (size_t)1 << property;
}

dev_input_event_t *regist_input_dev(const char *device_name,
                                    const input_dev_desc_t *desc);

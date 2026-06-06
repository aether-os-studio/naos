#pragma once

#include <libs/klibc.h>

struct clockevent_device;

typedef struct clockevent_ops {
    int (*set_next_event)(struct clockevent_device *dev, uint64_t delta_ns);
    void (*shutdown)(struct clockevent_device *dev);
} clockevent_ops_t;

typedef struct clockevent_device {
    const char *name;
    uint32_t rating;
    uint64_t min_delta_ns;
    uint64_t max_delta_ns;
    const clockevent_ops_t *ops;
    void *private_data;
} clockevent_device_t;

int clockevent_register_device(clockevent_device_t *dev);
void clockevent_program_event(uint64_t monotonic_deadline_ns);
void clockevent_shutdown(void);
void clockevent_handle_irq(void);

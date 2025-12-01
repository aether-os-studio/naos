#pragma once

#include <fs/vfs/dev.h>
#include <fs/fs_syscall.h>

typedef enum input_event_from {
    INPUT_FROM_PS2,
    INPUT_FROM_USB,
} input_event_from_t;

dev_input_event_t *regist_input_dev(const char *device_name,
                                    const char *uevent_append,
                                    input_event_from_t from,
                                    event_bit_t event_bit);

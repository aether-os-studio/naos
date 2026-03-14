#pragma once

#include <dev/input.h>

typedef struct regist_input_dev_arg {
    const char *uevent_append;
    input_event_from_t from;
    event_bit_t event_bit;
} regist_input_dev_arg_t;

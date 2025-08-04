#pragma once

#include <libs/klibc.h>

typedef struct
{
    bool is_use;
    char module_name[64];
    char *path;
    uint8_t *data;
    size_t size;
} module_t;

#pragma once

#include <libs/klibc.h>

typedef struct {
    bool is_use;
    bool mapped;
    bool is_verify;
    char module_name[64];
    char *path;
    uint8_t *data;
    size_t size;
    uint64_t load_base;
    size_t load_size;
} module_t;

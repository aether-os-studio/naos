#pragma once

#include <libs/klibc.h>

#define MAX_PIPES 32

#define PIPE_BUF_SIZE 1024

typedef struct pipe
{
    uint8_t buffer[PIPE_BUF_SIZE];
    size_t read_pos;
    size_t write_pos;
    uint64_t reference_count;
} pipe_t;

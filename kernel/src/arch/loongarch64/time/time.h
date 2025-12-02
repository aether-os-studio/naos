#pragma once

#include <libs/klibc.h>

typedef struct {
    uint64_t timestamp;
} tm;

void time_read(tm *time);
int64_t mktime(tm *time);

uint64_t nano_time();

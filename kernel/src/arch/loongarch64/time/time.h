#pragma once

#include <libs/klibc.h>

typedef struct
{
} tm;

void time_read(tm *time);
int64_t mktime(tm *time);

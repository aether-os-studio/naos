#pragma once

#include <arch/arch.h>
#include <libs/klibc.h>

static inline int atoi(const char *nptr) {
    int sign = 1;
    int value = 0;

    if (!nptr) {
        return 0;
    }
    while (*nptr == ' ' || *nptr == '\t' || *nptr == '\n' || *nptr == '\r' ||
           *nptr == '\f' || *nptr == '\v') {
        nptr++;
    }
    if (*nptr == '-') {
        sign = -1;
        nptr++;
    } else if (*nptr == '+') {
        nptr++;
    }
    while (*nptr >= '0' && *nptr <= '9') {
        value = value * 10 + (*nptr - '0');
        nptr++;
    }
    return sign * value;
}

static inline void abort(void) {
    for (;;) {
        arch_pause();
    }
}

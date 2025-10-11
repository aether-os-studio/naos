#pragma once

#include <arch/arch.h>

struct gdb_state {
    int signum;
    size_t registers[70];
    spinlock_t lock;
};

void gdbstub_loop(struct hart_state *hstate, int signum);

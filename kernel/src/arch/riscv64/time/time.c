#include <arch/arch.h>

void time_read(tm *time) {}

int64_t mktime(tm *time) { return time->timestamp; }

uint64_t nanoTime() { return get_timer() * 100; }

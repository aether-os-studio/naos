#include <arch/arch.h>

void time_read(tm *time) {}

int64_t mktime(tm *time) { return time->timestamp; }

uint64_t nanoTime() {
    uint64_t current_ns = 0;

    return current_ns;
}

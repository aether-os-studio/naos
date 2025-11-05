#include <arch/arch.h>
#include <boot/boot.h>

void time_read(tm *time) {
    time->timestamp = boot_get_boottime() + get_timer() * timer_freq / 1000000000ULL;
}

int64_t mktime(tm *time) { return time->timestamp; }

uint64_t nanoTime() { return get_timer() * timer_freq; }

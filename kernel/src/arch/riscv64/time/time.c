#include <arch/arch.h>
#include <boot/boot.h>

uint64_t nano_time() { return get_timer() * (timer_freq / 100000); }

void time_read(tm *time) {
    time->timestamp = boot_get_boottime() + nano_time() / 1000000000ULL;
}

int64_t mktime(tm *time) { return time->timestamp; }

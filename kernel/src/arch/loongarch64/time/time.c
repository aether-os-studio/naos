#include <arch/arch.h>
#include <boot/boot.h>

void time_read(tm *time) {
    uint64_t current_ns;
    asm volatile("rdtime.d %0, $r0\n" : "=r"(current_ns)::"memory");
    uint64_t timestamp = boot_get_boottime() + current_ns / 1000000000;
    time->timestamp = timestamp;
}

int64_t mktime(tm *time) { return time->timestamp; }

uint64_t nano_time() {
    uint64_t current_ns;
    asm volatile("rdtime.d %0, $r0\n" : "=r"(current_ns)::"memory");

    return current_ns;
}

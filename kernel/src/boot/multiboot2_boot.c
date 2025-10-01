#include <boot/boot.h>

void boot_init() {}

uint64_t boot_get_hhdm_offset() { return 0xffff800000000000; };

boot_memory_map_t multiboot2_boot_memory_map;

boot_memory_map_t *boot_get_memory_map() {
    size_t entry_count = 0;
    return &multiboot2_boot_memory_map;
};

uintptr_t boot_get_acpi_rsdp() { return (uintptr_t)0; }

uint64_t boot_get_boottime() { return 0; }

extern uint64_t cpu_count;

extern spinlock_t ap_startup_lock;

void boot_smp_init(uintptr_t entry) {}

#if defined(__x86_64__)
bool boot_cpu_support_x2apic() { return false; }
#endif

boot_framebuffer_t mulitboo2_boot_fb;

boot_framebuffer_t *boot_get_framebuffer() { return &mulitboo2_boot_fb; }

char *boot_get_cmdline() { return ""; }

void boot_get_modules(boot_module_t **modules, size_t *count) { *count = 0; }

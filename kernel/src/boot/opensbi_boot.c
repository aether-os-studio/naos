#include <boot/boot.h>

extern uintptr_t smp_entry;

boot_memory_map_t opensbi_memory_map;
boot_framebuffer_t opensbi_fb;

extern uintptr_t opensbi_dtb_vaddr;

void boot_init() {}

uint64_t boot_get_hhdm_offset() { return 0xffff800000000000; };

boot_memory_map_t *boot_get_memory_map() { return &opensbi_memory_map; };

uintptr_t boot_get_acpi_rsdp() { return 0; }

uint64_t boot_get_boottime() { return 0; }

extern uint64_t cpu_count;

extern spinlock_t ap_startup_lock;

void opensbi_smp_init(uintptr_t entry) { smp_entry = entry; }

void boot_smp_init(uintptr_t entry) { opensbi_smp_init(entry); }

boot_framebuffer_t *boot_get_framebuffer() { return &opensbi_fb; }

static void *find_string_tag(void *mb2_info_addr) { return NULL; }

char *boot_get_cmdline() { return (char *)""; }

boot_module_t opensbi_modules[MAX_MODULES_NUM];

void boot_get_modules(boot_module_t **modules, size_t *count) { *count = 0; }

uint64_t boot_get_dtb() { return opensbi_dtb_vaddr; }

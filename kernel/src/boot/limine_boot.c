#include <boot/boot.h>

__attribute__((used,
               section(".limine_requests_"
                       "start"))) static volatile LIMINE_REQUESTS_START_MARKER;

__attribute__((
    used, section(".limine_requests"))) static volatile LIMINE_BASE_REVISION(3);

__attribute__((
    used,
    section(
        ".limine_requests"))) static volatile struct limine_stack_size_request
    stack_size_request = {
        .id = LIMINE_STACK_SIZE_REQUEST,
        .revision = 0,
        .stack_size = STACK_SIZE,
};

__attribute__((
    used,
    section(".limine_requests"))) static volatile struct limine_hhdm_request
    hhdm_request = {.id = LIMINE_HHDM_REQUEST, .revision = 0};

__attribute__((
    used,
    section(".limine_requests"))) static volatile struct limine_memmap_request
    memmap_request = {
        .id = LIMINE_MEMMAP_REQUEST,
        .revision = 0,
};

__attribute__((used,
               section(".limine_requests"))) volatile struct limine_rsdp_request
    rsdp_request = {.id = LIMINE_RSDP_REQUEST, .revision = 0, .response = NULL};

__attribute__((
    used,
    section(".limine_requests"))) volatile struct limine_date_at_boot_request
    boot_time_request = {
        .id = LIMINE_DATE_AT_BOOT_REQUEST,
        .revision = 0,
};

__attribute__((
    used,
    section(".limine_requests"))) volatile struct limine_framebuffer_request
    framebuffer_request = {.id = LIMINE_FRAMEBUFFER_REQUEST, .revision = 0};

void boot_init() {}

uint64_t boot_get_hhdm_offset() { return hhdm_request.response->offset; };

boot_memory_map_t limine_boot_memory_map;

boot_memory_map_t *boot_get_memory_map() {
    size_t entry_count = 0;
    for (entry_count = 0; entry_count < memmap_request.response->entry_count;
         entry_count++) {
        struct limine_memmap_entry *limine_entry =
            memmap_request.response->entries[entry_count];
        limine_boot_memory_map.entries[entry_count] = (boot_memory_map_entry_t){
            .addr = limine_entry->base,
            .len = limine_entry->length,
            .type = (limine_entry->type == LIMINE_MEMMAP_USABLE) ? USABLE
                                                                 : RESERVED,
        };
    }
    limine_boot_memory_map.entry_count = entry_count;
    return &limine_boot_memory_map;
};

uintptr_t boot_get_acpi_rsdp() {
    return (uintptr_t)rsdp_request.response->address;
}

uint64_t boot_get_boottime() { return boot_time_request.response->timestamp; }

__attribute__((
    used, section(".limine_requests"))) static volatile struct limine_mp_request
    mp_request = {
        .id = LIMINE_MP_REQUEST,
        .revision = 0,
        .flags = LIMINE_MP_X2APIC,
};

extern uint64_t cpu_count;

extern spinlock_t ap_startup_lock;

void boot_smp_init(uintptr_t entry) {
    struct limine_mp_response *mp_response = mp_request.response;

    cpu_count = mp_response->cpu_count;

    for (uint64_t i = 0; i < mp_response->cpu_count; i++) {
        struct limine_mp_info *cpu = mp_response->cpus[i];
#if defined(__x86_64__)
        extern uint32_t cpuid_to_lapicid[MAX_CPU_NUM];
        cpuid_to_lapicid[i] = cpu->lapic_id;

        if (cpu->lapic_id == mp_response->bsp_lapic_id)
            continue;
#endif

        spin_lock(&ap_startup_lock);

        cpu->goto_address = (limine_goto_address)entry;
    }
}

#if defined(__x86_64__)
bool boot_cpu_support_x2apic() {
    return !!(mp_request.response->flags & LIMINE_MP_X2APIC);
}
#endif

boot_framebuffer_t limine_boot_fb;

boot_framebuffer_t *boot_get_framebuffer() {
    limine_boot_fb.address =
        (uintptr_t)framebuffer_request.response->framebuffers[0]->address;
    limine_boot_fb.width = framebuffer_request.response->framebuffers[0]->width;
    limine_boot_fb.height =
        framebuffer_request.response->framebuffers[0]->height;
    limine_boot_fb.bpp = framebuffer_request.response->framebuffers[0]->bpp;
    limine_boot_fb.pitch = framebuffer_request.response->framebuffers[0]->pitch;
    limine_boot_fb.red_mask_shift =
        framebuffer_request.response->framebuffers[0]->red_mask_shift;
    limine_boot_fb.red_mask_size =
        framebuffer_request.response->framebuffers[0]->red_mask_size;
    limine_boot_fb.blue_mask_shift =
        framebuffer_request.response->framebuffers[0]->blue_mask_shift;
    limine_boot_fb.blue_mask_size =
        framebuffer_request.response->framebuffers[0]->blue_mask_size;
    limine_boot_fb.green_mask_shift =
        framebuffer_request.response->framebuffers[0]->green_mask_shift;
    limine_boot_fb.green_mask_size =
        framebuffer_request.response->framebuffers[0]->green_mask_size;

    return &limine_boot_fb;
}

__attribute__((used, section(".limine_requests"))) static volatile struct
    limine_executable_cmdline_request executable_cmdline_request = {
        .id = LIMINE_EXECUTABLE_CMDLINE_REQUEST,
};

char *boot_get_cmdline() {
    return executable_cmdline_request.response->cmdline;
}

__attribute__((
    used,
    section(".limine_requests"))) static volatile struct limine_module_request
    modules_request = {
        .id = LIMINE_MODULE_REQUEST,
        .revision = 0,
};

boot_module_t limine_boot_modules[MAX_MODULES_NUM];

void boot_get_modules(boot_module_t **modules, size_t *count) {
    *count = 0;
    for (uint64_t i = 0; i < modules_request.response->module_count; i++) {
        strcpy(limine_boot_modules[i].path,
               modules_request.response->modules[i]->path);
        limine_boot_modules[i].data =
            modules_request.response->modules[i]->address;
        limine_boot_modules[i].size =
            modules_request.response->modules[i]->size;
        modules[i] = &limine_boot_modules[i];
        (*count)++;
    }
}

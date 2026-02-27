#include <boot/boot.h>
#include <boot/multiboot2/x64/multiboot2.h>

uintptr_t mb2_info_addr;

extern int setup_2m_page_tables(void *mb2_info_addr, uint64_t **out_pml4);

void multiboot2_c_start(uint32_t magic, uintptr_t addr) {
    if (magic != MULTIBOOT2_BOOTLOADER_MAGIC)
        return;
    mb2_info_addr = addr + 0xffff800000000000;

    uint64_t *pml4;
    int res = setup_2m_page_tables((void *)mb2_info_addr, &pml4);
    if (res != 0)
        return;

    asm volatile("movq %0, %%cr3" ::"r"(pml4) : "memory");

    asm volatile("jmp _start");
}

void boot_init() {}

uint64_t boot_get_hhdm_offset() { return 0xffff800000000000; };

boot_memory_map_t multiboot2_memory_map;

boot_memory_map_t *boot_get_memory_map() { return &multiboot2_memory_map; };

static struct multiboot_tag *next_tag(struct multiboot_tag *tag) {
    uint8_t *addr = (uint8_t *)tag;
    addr += ((tag->size + 7) & ~7); // 8字节对齐
    return (struct multiboot_tag *)addr;
}

static void *find_acpi_rsdp_tag(void *mb2_info_addr) {
    struct multiboot_tag *tag =
        (struct multiboot_tag *)((uint8_t *)mb2_info_addr + 8);

    while (tag->type != MULTIBOOT_TAG_TYPE_END) {
        if (tag->type == MULTIBOOT_TAG_TYPE_ACPI_OLD ||
            tag->type == MULTIBOOT_TAG_TYPE_ACPI_NEW) {
            return (void *)tag;
        }
        tag = next_tag(tag);
    }

    return NULL;
}

static struct multiboot_tag_smbios *find_smbios_tag(void *mb2_info_addr) {
    struct multiboot_tag *tag =
        (struct multiboot_tag *)((uint8_t *)mb2_info_addr + 8);

    while (tag->type != MULTIBOOT_TAG_TYPE_END) {
        if (tag->type == MULTIBOOT_TAG_TYPE_SMBIOS) {
            return (struct multiboot_tag_smbios *)tag;
        }
        tag = next_tag(tag);
    }

    return NULL;
}

uintptr_t boot_get_acpi_rsdp() {
    struct multiboot_tag_old_acpi *tag =
        find_acpi_rsdp_tag((void *)mb2_info_addr);
    return (uintptr_t)&tag->rsdp - 0xffff800000000000;
}

void boot_get_smbios_entries(void **entry32, void **entry64) {
    if (entry32)
        *entry32 = NULL;
    if (entry64)
        *entry64 = NULL;

    struct multiboot_tag_smbios *tag = find_smbios_tag((void *)mb2_info_addr);
    if (!tag)
        return;

    if (tag->major >= 3) {
        if (entry64)
            *entry64 = (void *)&tag->tables[0];
    } else {
        if (entry32)
            *entry32 = (void *)&tag->tables[0];
    }
}

uint64_t boot_get_boottime() { return 0; }

extern uint64_t cpu_count;

extern spinlock_t ap_startup_lock;

extern void multiboot2_smp_init(uintptr_t ap_entry);

#define CPUID_FEAT_ECX_X2APIC (1 << 21) // ECX bit 21

static inline void lapic_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax,
                               uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(leaf), "c"(subleaf));
}

bool detect_x2apic_support(void) {
    uint32_t eax, ebx, ecx, edx;

    // 首先检查是否支持 CPUID 扩展功能
    lapic_cpuid(0, 0, &eax, &ebx, &ecx, &edx);

    if (eax < 1) {
        // CPU 太老，不支持 CPUID leaf 1
        return false;
    }

    // CPUID.01H:ECX[21] = 1 表示支持 x2APIC
    lapic_cpuid(1, 0, &eax, &ebx, &ecx, &edx);

    return (ecx & CPUID_FEAT_ECX_X2APIC) != 0;
}

void boot_smp_init(uintptr_t entry) { multiboot2_smp_init(entry); }

bool boot_cpu_support_x2apic() { return detect_x2apic_support(); }

boot_framebuffer_t multiboot2_fb;

static struct multiboot_tag_framebuffer *
find_framebuffer_tag(void *mb2_info_addr) {
    struct multiboot_tag *tag =
        (struct multiboot_tag *)((uint8_t *)mb2_info_addr + 8);

    while (tag->type != MULTIBOOT_TAG_TYPE_END) {
        if (tag->type == MULTIBOOT_TAG_TYPE_FRAMEBUFFER) {
            return (void *)tag;
        }
        tag = next_tag(tag);
    }

    return NULL;
}

boot_framebuffer_t *boot_get_framebuffer() {
    struct multiboot_tag_framebuffer *fb =
        find_framebuffer_tag((void *)mb2_info_addr);

    multiboot2_fb.address =
        (uintptr_t)(fb->common.framebuffer_addr + 0xffff800000000000);
    multiboot2_fb.width = fb->common.framebuffer_width;
    multiboot2_fb.height = fb->common.framebuffer_height;
    multiboot2_fb.bpp = fb->common.framebuffer_bpp;
    multiboot2_fb.pitch = fb->common.framebuffer_pitch;
    multiboot2_fb.red_mask_shift = fb->framebuffer_red_field_position;
    multiboot2_fb.red_mask_size = fb->framebuffer_red_mask_size;
    multiboot2_fb.blue_mask_shift = fb->framebuffer_blue_field_position;
    multiboot2_fb.blue_mask_size = fb->framebuffer_blue_mask_size;
    multiboot2_fb.green_mask_shift = fb->framebuffer_green_field_position;
    multiboot2_fb.green_mask_size = fb->framebuffer_green_mask_size;

    return &multiboot2_fb;
}

static void *find_string_tag(void *mb2_info_addr) {
    struct multiboot_tag *tag =
        (struct multiboot_tag *)((uint8_t *)mb2_info_addr + 8);

    while (tag->type != MULTIBOOT_TAG_TYPE_END) {
        if (tag->type == MULTIBOOT_TAG_TYPE_CMDLINE) {
            return (void *)tag;
        }
        tag = next_tag(tag);
    }

    return NULL;
}

char *boot_get_cmdline() {
    struct multiboot_tag_string *string_tag =
        find_string_tag((void *)mb2_info_addr);
    return (char *)string_tag->string;
}

boot_module_t multiboot2_modules[MAX_MODULES_NUM];

void boot_get_modules(boot_module_t **modules, size_t *count) {
    *count = 0;

    struct multiboot_tag *tag =
        (struct multiboot_tag *)((uint8_t *)mb2_info_addr + 8);

    while (tag->type != MULTIBOOT_TAG_TYPE_END) {
        if (tag->type == MULTIBOOT_TAG_TYPE_MODULE) {
            struct multiboot_tag_module *module =
                (struct multiboot_tag_module *)tag;
            multiboot2_modules[(*count)].data =
                (void *)(module->mod_start + 0xffff800000000000);
            multiboot2_modules[(*count)].size =
                (size_t)(module->mod_end - module->mod_start);
            memcpy(multiboot2_modules[(*count)].path, module->cmdline,
                   strlen(module->cmdline));
            modules[(*count)] = &multiboot2_modules[(*count)];
            (*count)++;
        }
        tag = next_tag(tag);
    }
}

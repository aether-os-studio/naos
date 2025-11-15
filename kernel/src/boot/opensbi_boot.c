#include <boot/boot.h>
#include <boot/opensbi/opensbi_boot.h>
#include <arch/arch.h>
#include <drivers/fdt/fdt.h>

extern uintptr_t smp_entry;

boot_memory_map_t opensbi_memory_map = {0};
boot_framebuffer_t opensbi_fb = {0};

extern uintptr_t opensbi_dtb_vaddr;

void boot_init() {}

uint64_t boot_get_hhdm_offset() { return 0xffff800000000000; };

boot_memory_map_t *boot_get_memory_map() { return &opensbi_memory_map; };

uintptr_t boot_get_acpi_rsdp() { return 0; }

uint64_t boot_get_boottime() { return 0; }

extern uint64_t cpu_count;
extern atomic_t started_cpu_count;

extern spinlock_t ap_startup_lock;

extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];
extern uint64_t bsp_hart_id;

extern void _opensbi_start_ap();

void opensbi_smp_init(uintptr_t entry) {
    cpu_count = 0;
    cpuid_to_hartid[cpu_count++] = bsp_hart_id;
    atomic_inc(&started_cpu_count);
    smp_entry = entry;

    const void *fdt = (const void *)boot_get_dtb();
    int depth = 0;

    map_page_range(get_current_page_dir(false), EARLY_MAP_BASE, EARLY_MAP_BASE,
                   EARLY_MAP_END - EARLY_MAP_BASE,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_X);

    int offset = -1;
    while ((offset = fdt_next_node((void *)opensbi_dtb_vaddr, offset, NULL)) >=
           0) {
        const char *name =
            fdt_get_name((void *)opensbi_dtb_vaddr, offset, NULL);
        if (!name)
            continue;
        if (strncmp(name, "cpu@", 4) == 0) {
            int reg_len;
            const fdt32_t *reg =
                (const fdt32_t *)fdt_getprop(fdt, offset, "reg", &reg_len);
            if (reg && reg_len >= (int)sizeof(uint32_t)) {
                uint32_t hartid = fdt32_to_cpu(reg[0]);
                if (hartid == bsp_hart_id) {
                    continue;
                }
                cpuid_to_hartid[cpu_count++] = hartid;
                sbi_ecall(0x48534D, 0, hartid, 0x80200088,
                          (uint64_t)virt_to_phys(get_current_page_dir(false)),
                          0, 0, 0);
            }
        }
    }

end:
    while (atomic_read(&started_cpu_count) < cpu_count)
        arch_pause();

    unmap_page_range(get_current_page_dir(false), EARLY_MAP_BASE,
                     EARLY_MAP_END - EARLY_MAP_BASE);
}

void boot_smp_init(uintptr_t entry) { opensbi_smp_init(entry); }

boot_framebuffer_t *boot_get_framebuffer() { return &opensbi_fb; }

static void *find_string_tag(void *mb2_info_addr) { return NULL; }

extern char *fdt_kernel_cmdline(void *fdt);
char *boot_get_cmdline() { return fdt_kernel_cmdline((void *)boot_get_dtb()); }

boot_module_t opensbi_modules[MAX_MODULES_NUM];

void boot_get_modules(boot_module_t **modules, size_t *count) { *count = 0; }

uint64_t boot_get_dtb() { return opensbi_dtb_vaddr; }

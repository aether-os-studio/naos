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

    uint32_t *p = (uint32_t *)g_fdt_ctx.dt_struct;
    int depth = 0;

    map_page_range(get_current_page_dir(false), EARLY_MAP_BASE, EARLY_MAP_BASE,
                   EARLY_MAP_END - EARLY_MAP_BASE,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_X);

    while (1) {
        uint32_t tag = fdt32_to_cpu(*p++);

        switch (tag) {
        case FDT_BEGIN_NODE: {
            const char *name = (const char *)p;
            int node_off = (uint8_t *)p - (uint8_t *)g_fdt_ctx.dt_struct - 4;

            // 检查是否是 CPU 节点
            if (strncmp(name, "cpu@", 4) == 0) {
                // 获取 Hart ID
                uint32_t hartid;
                if (fdt_get_property_u32(node_off, "reg", &hartid) == 0) {
                    if (hartid == bsp_hart_id) {
                        continue;
                    }
                    cpuid_to_hartid[cpu_count++] = hartid;
                    sbi_ecall(
                        0x48534D, 0, hartid, 0x80200088,
                        (uint64_t)virt_to_phys(get_current_page_dir(false)), 0,
                        0, 0);
                }
            }

            depth++;
            p = (uint32_t *)ALIGN_UP((uintptr_t)p + strlen(name) + 1, 4);
            break;
        }

        case FDT_END_NODE:
            depth--;
            break;

        case FDT_PROP: {
            struct fdt_property *prop = (struct fdt_property *)p;
            uint32_t len = fdt32_to_cpu(prop->len);
            p = (uint32_t *)ALIGN_UP(
                (uintptr_t)p + sizeof(struct fdt_property) + len, 4);
            break;
        }

        case FDT_END:
            goto end;

        default:
            break;
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

char *boot_get_cmdline() { return (char *)""; }

boot_module_t opensbi_modules[MAX_MODULES_NUM];

void boot_get_modules(boot_module_t **modules, size_t *count) { *count = 0; }

uint64_t boot_get_dtb() { return opensbi_dtb_vaddr; }

#include <boot/boot.h>
#include <arch/riscv64/mm/arch.h>
#include <drivers/fdt/fdt.h>
#include <drivers/logger.h>
#include <limine.h>
#include <mm/hhdm.h>
#include <mm/mm.h>

static uintptr_t align_down(uintptr_t value, uintptr_t align);
static uintptr_t align_up(uintptr_t value, uintptr_t align);

#define SBI_HHDM_OFFSET 0xffffffc000000000ULL
#define SBI_PAGING_MODE LIMINE_PAGING_MODE_RISCV_SV39
#define SBI_KERNEL_VIRT_OFFSET (0xffffffff80200000ULL - 0x80200000ULL)
#define SBI_HHDM_ROOT_INDEX_START 256
#define SBI_HHDM_ROOT_INDEX_END 510
#define SBI_EXT_HSM 0x48534dULL
#define SBI_HSM_HART_START 0

extern uint64_t __sbi_boot_hartid_virt;
extern uint64_t __sbi_boot_dtb_phys_virt;
extern char __kernel_image_start[];
extern char __kernel_image_end[];
extern char __sbi_boot_start_virt[];
extern char __sbi_boot_end_virt[];
extern char __sbi_ap_trampoline_virt[];
extern uint64_t __sbi_root_pt_virt[];
extern uint64_t __sbi_hhdm_l1_pts_virt[];

static boot_memory_map_t sbi_memory_map;
static boot_memory_map_t sbi_memory_map_scratch;
static bool sbi_memory_map_ready = false;
static char sbi_cmdline[1] = "";

static uint64_t sbi_bsp_hartid(void) { return __sbi_boot_hartid_virt; }

static uint64_t sbi_dtb_phys(void) { return __sbi_boot_dtb_phys_virt; }

typedef struct sbi_ret {
    int64_t error;
    uint64_t value;
} sbi_ret_t;

typedef struct sbi_ap_startup_data {
    uint64_t satp;
    uint64_t stack_top;
    uint64_t entry;
} sbi_ap_startup_data_t;

static sbi_ret_t sbi_ecall(uint64_t eid, uint64_t fid, uint64_t arg0,
                           uint64_t arg1, uint64_t arg2, uint64_t arg3,
                           uint64_t arg4, uint64_t arg5) {
    register uint64_t a0 asm("a0") = arg0;
    register uint64_t a1 asm("a1") = arg1;
    register uint64_t a2 asm("a2") = arg2;
    register uint64_t a3 asm("a3") = arg3;
    register uint64_t a4 asm("a4") = arg4;
    register uint64_t a5 asm("a5") = arg5;
    register uint64_t a6 asm("a6") = fid;
    register uint64_t a7 asm("a7") = eid;

    asm volatile("ecall"
                 : "+r"(a0), "+r"(a1)
                 : "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7)
                 : "memory");

    return (sbi_ret_t){.error = (int64_t)a0, .value = a1};
}

static int64_t sbi_hart_start(uint64_t hartid, uint64_t start_addr,
                              uint64_t opaque) {
    return sbi_ecall(SBI_EXT_HSM, SBI_HSM_HART_START, hartid, start_addr,
                     opaque, 0, 0, 0)
        .error;
}

static uintptr_t align_down(uintptr_t value, uintptr_t align) {
    return value & ~(align - 1);
}

static uintptr_t align_up(uintptr_t value, uintptr_t align) {
    return align_down(value + align - 1, align);
}

static uintptr_t high_virt_to_loaded_phys(uintptr_t addr) {
    return addr - SBI_KERNEL_VIRT_OFFSET;
}

static uint64_t *sbi_hhdm_l1_table(uint64_t root_index) {
    if (root_index < SBI_HHDM_ROOT_INDEX_START ||
        root_index >= SBI_HHDM_ROOT_INDEX_END) {
        return NULL;
    }

    return __sbi_hhdm_l1_pts_virt + (root_index - SBI_HHDM_ROOT_INDEX_START) *
                                        (PAGE_SIZE / sizeof(uint64_t));
}

static void sbi_map_hhdm_2m(uint64_t phys) {
    uint64_t phys_2m = align_down(phys, 1ULL << 21);
    uint64_t virt = SBI_HHDM_OFFSET + phys_2m;
    uint64_t root_index = (virt >> 30) & 511;
    uint64_t *l1 = sbi_hhdm_l1_table(root_index);
    if (!l1)
        return;

    if (__sbi_root_pt_virt[root_index] == 0) {
        uint64_t l1_phys = high_virt_to_loaded_phys((uintptr_t)l1);
        __sbi_root_pt_virt[root_index] =
            (((uint64_t)l1_phys >> 12) << 10) | 0x1;
    }

    uint64_t entry_index = (virt >> 21) & 511;
    l1[entry_index] = ((phys_2m >> 12) << 10) | 0xcf;

    asm volatile("sfence.vma %0, zero" : : "r"(virt) : "memory");
}

static void sbi_map_hhdm_range(uint64_t start, uint64_t len) {
    if (len == 0)
        return;

    uint64_t cur = align_down(start, 1ULL << 21);
    uint64_t end = align_up(start + len, 1ULL << 21);

    while (cur < end) {
        sbi_map_hhdm_2m(cur);
        cur += 1ULL << 21;
    }
}

static void *sbi_dtb_early_ptr(void) {
    uint64_t dtb_phys = sbi_dtb_phys();
    if (!dtb_phys)
        return NULL;

    return (void *)(uintptr_t)(SBI_HHDM_OFFSET + dtb_phys);
}

static void sbi_add_memory_entry(uintptr_t addr, size_t len,
                                 typeof(sbi_memory_map.entries[0].type) type) {
    if (len == 0 ||
        sbi_memory_map.entry_count >= sizeof(sbi_memory_map.entries) /
                                          sizeof(sbi_memory_map.entries[0])) {
        return;
    }

    sbi_memory_map.entries[sbi_memory_map.entry_count++] =
        (boot_memory_map_entry_t){
            .addr = addr,
            .len = len,
            .type = type,
        };
}

static bool sbi_append_memory_entry(boot_memory_map_t *map,
                                    boot_memory_map_entry_t entry) {
    if (entry.len == 0)
        return true;

    if (map->entry_count >= sizeof(map->entries) / sizeof(map->entries[0]))
        return false;

    map->entries[map->entry_count++] = entry;
    return true;
}

static void sbi_add_reserved_range(uintptr_t start, uintptr_t end) {
    if (start >= end)
        return;

    start = align_down(start, PAGE_SIZE);
    end = align_up(end, PAGE_SIZE);

    boot_memory_map_t *new_map = &sbi_memory_map_scratch;
    new_map->entry_count = 0;

    for (size_t i = 0; i < sbi_memory_map.entry_count; i++) {
        boot_memory_map_entry_t entry = sbi_memory_map.entries[i];
        uintptr_t entry_start = entry.addr;
        uintptr_t entry_end = entry.addr + entry.len;

        if (entry.type != USABLE || end <= entry_start || start >= entry_end) {
            if (!sbi_append_memory_entry(new_map, entry))
                return;
            continue;
        }

        uintptr_t reserved_start = MAX(start, entry_start);
        uintptr_t reserved_end = MIN(end, entry_end);

        if (entry_start < reserved_start) {
            if (!sbi_append_memory_entry(
                    new_map, (boot_memory_map_entry_t){
                                 .addr = entry_start,
                                 .len = reserved_start - entry_start,
                                 .type = USABLE,
                             })) {
                return;
            }
        }

        if (!sbi_append_memory_entry(new_map,
                                     (boot_memory_map_entry_t){
                                         .addr = reserved_start,
                                         .len = reserved_end - reserved_start,
                                         .type = RESERVED,
                                     })) {
            return;
        }

        if (reserved_end < entry_end) {
            if (!sbi_append_memory_entry(new_map,
                                         (boot_memory_map_entry_t){
                                             .addr = reserved_end,
                                             .len = entry_end - reserved_end,
                                             .type = USABLE,
                                         })) {
                return;
            }
        }
    }

    sbi_memory_map.entry_count = new_map->entry_count;
    for (size_t i = 0; i < new_map->entry_count; i++) {
        sbi_memory_map.entries[i] = new_map->entries[i];
    }
}

static uint64_t fdt_cells_read64(const fdt32_t *cells, int cell_count) {
    uint64_t value = 0;
    for (int i = 0; i < cell_count; i++) {
        value = (value << 32) | fdt32_to_cpu(cells[i]);
    }
    return value;
}

static bool sbi_hart_seen(const uint64_t *harts, uint64_t count,
                          uint64_t hartid) {
    for (uint64_t i = 0; i < count; i++) {
        if (harts[i] == hartid)
            return true;
    }

    return false;
}

static bool sbi_cpu_node_enabled(const void *fdt, int node) {
    int len = 0;
    const char *status = fdt_getprop(fdt, node, "status", &len);
    if (!status)
        return true;

    return strcmp(status, "disabled") != 0;
}

static bool sbi_read_cpu_hartid(const void *fdt, int cpus, int cpu_node,
                                uint64_t *hartid) {
    int len = 0;
    const char *device_type = fdt_getprop(fdt, cpu_node, "device_type", &len);
    if (!device_type || strcmp(device_type, "cpu") != 0)
        return false;

    if (!sbi_cpu_node_enabled(fdt, cpu_node))
        return false;

    int address_cells = 1;
    const fdt32_t *prop = fdt_getprop(fdt, cpus, "#address-cells", &len);
    if (prop && len >= 4)
        address_cells = (int)fdt32_to_cpu(*prop);

    if (address_cells <= 0 || address_cells > 2)
        return false;

    const fdt32_t *reg = fdt_getprop(fdt, cpu_node, "reg", &len);
    if (!reg || len < address_cells * (int)sizeof(fdt32_t))
        return false;

    *hartid = fdt_cells_read64(reg, address_cells);
    return true;
}

static uint64_t sbi_discover_harts_from_dtb(uint64_t *harts,
                                            uint64_t max_harts) {
    uint64_t count = 0;
    uint64_t bsp = sbi_bsp_hartid();

    if (max_harts == 0)
        return 0;

    harts[count++] = bsp;

    const void *fdt = sbi_dtb_early_ptr();
    if (!fdt || fdt_check_header(fdt) != 0)
        return count;

    int cpus = fdt_path_offset(fdt, "/cpus");
    if (cpus < 0)
        return count;

    int cpu_node = -1;
    fdt_for_each_subnode(cpu_node, fdt, cpus) {
        uint64_t hartid = 0;
        if (!sbi_read_cpu_hartid(fdt, cpus, cpu_node, &hartid))
            continue;

        if (sbi_hart_seen(harts, count, hartid))
            continue;

        if (count >= max_harts)
            break;

        harts[count++] = hartid;
    }

    return count;
}

static void sbi_build_memory_map_from_dtb(void) {
    if (sbi_memory_map_ready)
        return;

    sbi_memory_map.entry_count = 0;

    uint64_t dtb_phys = sbi_dtb_phys();
    if (dtb_phys)
        sbi_map_hhdm_2m(dtb_phys);

    const void *fdt = sbi_dtb_early_ptr();
    if (fdt && fdt_check_header(fdt) == 0) {
        int root = fdt_path_offset(fdt, "/");
        int address_cells = 2;
        int size_cells = 2;
        if (root >= 0) {
            int len = 0;
            const fdt32_t *prop =
                fdt_getprop(fdt, root, "#address-cells", &len);
            if (prop && len >= 4)
                address_cells = (int)fdt32_to_cpu(*prop);

            prop = fdt_getprop(fdt, root, "#size-cells", &len);
            if (prop && len >= 4)
                size_cells = (int)fdt32_to_cpu(*prop);
        }

        int node = -1;
        while ((node = fdt_node_offset_by_prop_value(fdt, node, "device_type",
                                                     "memory", 7)) >= 0) {
            int len = 0;
            const fdt32_t *reg = fdt_getprop(fdt, node, "reg", &len);
            int tuple_cells = address_cells + size_cells;
            if (!reg || tuple_cells <= 0)
                continue;

            int tuples = len / (int)(tuple_cells * sizeof(fdt32_t));
            for (int i = 0; i < tuples; i++) {
                const fdt32_t *tuple = reg + i * tuple_cells;
                uint64_t base = fdt_cells_read64(tuple, address_cells);
                uint64_t size =
                    fdt_cells_read64(tuple + address_cells, size_cells);
                sbi_add_memory_entry((uintptr_t)base, (size_t)size, USABLE);
                sbi_map_hhdm_range(base, size);
            }
        }
    }

    if (sbi_memory_map.entry_count == 0) {
        sbi_add_memory_entry(0x80000000ULL, 128 * 1024 * 1024ULL, USABLE);
        sbi_map_hhdm_range(0x80000000ULL, 128 * 1024 * 1024ULL);
    }

    sbi_add_reserved_range(0x80000000ULL, 0x80200000ULL);
    sbi_add_reserved_range((uintptr_t)&__sbi_boot_start_virt,
                           (uintptr_t)&__sbi_boot_end_virt);
    sbi_add_reserved_range(
        high_virt_to_loaded_phys((uintptr_t)&__kernel_image_start),
        high_virt_to_loaded_phys((uintptr_t)&__kernel_image_end));

    if (dtb_phys && fdt && fdt_check_header(fdt) == 0) {
        sbi_add_reserved_range((uintptr_t)dtb_phys,
                               (uintptr_t)dtb_phys + fdt_totalsize(fdt));
    }

    sbi_memory_map_ready = true;
}

void boot_init(void) { sbi_build_memory_map_from_dtb(); }

uint64_t boot_get_hhdm_offset(void) { return SBI_HHDM_OFFSET; }

boot_memory_map_t *boot_get_memory_map(void) {
    sbi_build_memory_map_from_dtb();
    return &sbi_memory_map;
}

uintptr_t boot_get_acpi_rsdp(void) { return 0; }

void boot_get_smbios_entries(void **entry32, void **entry64) {
    if (entry32)
        *entry32 = NULL;
    if (entry64)
        *entry64 = NULL;
}

uint64_t boot_get_boottime(void) { return 0; }

extern uint64_t cpu_count;
extern uint64_t cpuid_to_hartid[MAX_CPU_NUM];
extern spinlock_t ap_startup_lock;

uintptr_t ap_entry_point;

void sbi_ap_entry(uint64_t hartid) {
    ((void (*)(uint64_t))ap_entry_point)(hartid);
}

void boot_smp_init(uintptr_t entry) {
    ap_entry_point = entry;

    uint64_t discovered_harts[MAX_CPU_NUM];
    uint64_t discovered_count =
        sbi_discover_harts_from_dtb(discovered_harts, MAX_CPU_NUM);
    if (discovered_count == 0) {
        discovered_harts[0] = sbi_bsp_hartid();
        discovered_count = 1;
    }

    cpu_count = 1;
    cpuid_to_hartid[0] = sbi_bsp_hartid();

    uint64_t satp =
        riscv64_make_satp((uint64_t)virt_to_phys(get_kernel_page_dir()));
    uint64_t trampoline_phys =
        high_virt_to_loaded_phys((uintptr_t)&__sbi_ap_trampoline_virt);
    size_t map_size = align_up((uintptr_t)&__sbi_boot_end_virt -
                                   (uintptr_t)&__sbi_boot_start_virt,
                               PAGE_SIZE);
    if (map_page_range(get_kernel_page_dir(), 0x80200000ULL, 0x80200000ULL,
                       map_size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_X) != 0) {
        printk("SBI SMP: cannot map AP trampoline\n");
        return;
    }

    for (uint64_t i = 0; i < discovered_count; i++) {
        uint64_t hartid = discovered_harts[i];
        if (hartid == sbi_bsp_hartid())
            continue;

        if (cpu_count >= MAX_CPU_NUM)
            break;

        uint64_t stack_phys = alloc_frames(STACK_SIZE / PAGE_SIZE);
        uint64_t data_phys = alloc_frames(1);
        if (!stack_phys || !data_phys) {
            printk("SBI SMP: cannot allocate startup state for hart %llu\n",
                   hartid);
            continue;
        }

        sbi_ap_startup_data_t *data =
            (sbi_ap_startup_data_t *)phys_to_virt(data_phys);
        memset(data, 0, PAGE_SIZE);
        data->satp = satp;
        data->stack_top =
            (uint64_t)(uintptr_t)phys_to_virt(stack_phys + STACK_SIZE);
        data->entry = (uint64_t)(uintptr_t)sbi_ap_entry;
        memory_barrier();

        uint64_t cpu_id = cpu_count;
        cpuid_to_hartid[cpu_id] = hartid;
        cpu_count = cpu_id + 1;
        memory_barrier();

        raw_spin_lock(&ap_startup_lock);

        int64_t err = sbi_hart_start(hartid, trampoline_phys, data_phys);
        if (err != 0) {
            raw_spin_unlock(&ap_startup_lock);
            cpu_count = cpu_id;
            printk("SBI SMP: hart_start failed for hart %llu: %lld\n", hartid,
                   err);
            continue;
        }
    }
}

boot_framebuffer_t *boot_get_framebuffer(void) { return NULL; }

char *boot_get_cmdline(void) { return sbi_cmdline; }

void *boot_get_executable_file(size_t *size) {
    if (size)
        *size = 0;
    return NULL;
}

extern char __initramfs_start[];
extern char __initramfs_end[];

static boot_module_t boot_modules[1];

void boot_get_modules(boot_module_t **modules, size_t *count) {
    if (count)
        *count = 0;

    if (modules == NULL)
        return;

    size_t initramfs_size =
        (size_t)((uintptr_t)&__initramfs_end - (uintptr_t)&__initramfs_start);
    if (initramfs_size == 0)
        return;

    boot_modules[0] = (boot_module_t){
        .path = "initramfs.img",
        .data = (const void *)&__initramfs_start,
        .size = initramfs_size,
    };
    modules[0] = &boot_modules[0];
    if (count)
        *count = 1;
}

uint64_t boot_get_firmware_type(void) { return LIMINE_FIRMWARE_TYPE_SBI; }

uint64_t boot_get_dtb(void) { return (uint64_t)sbi_dtb_early_ptr(); }

uint64_t boot_get_bsp_hartid(void) { return sbi_bsp_hartid(); }

uint64_t boot_get_paging_mode(void) { return SBI_PAGING_MODE; }

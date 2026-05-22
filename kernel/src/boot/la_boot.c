#include <boot/boot.h>
#include <boot/efi.h>
#include <arch/loongarch64/csr.h>
#include <drivers/fdt/fdt.h>
#include <drivers/logger.h>
#include <limine.h>
#include <mm/hhdm.h>
#include <mm/mm.h>

extern char __kernel_phys_start[];
extern char __kernel_phys_end[];
extern char __kernel_virt_start[];
extern char __kernel_virt_end[];
extern char __boot_start_virt[];
extern char __boot_end_virt[];

extern char __ap_startup_info_virt[];

#define LABOOT_PAGE_DIRTY ((uint64_t)1 << 1)
#define LABOOT_PAGE_CACHE_CC ((uint64_t)1 << 4)
#define LABOOT_PAGE_GLOBAL ((uint64_t)1 << 6)
#define LABOOT_PAGE_PRESENT ((uint64_t)1 << 7)
#define LABOOT_PAGE_WRITE ((uint64_t)1 << 8)
#define LABOOT_PAGE_MODIFIED ((uint64_t)1 << 9)
#define LABOOT_PAGE_VALID ((uint64_t)1 << 0)
#define LABOOT_PTE_FLAGS                                                       \
    (LABOOT_PAGE_PRESENT | LABOOT_PAGE_GLOBAL | LABOOT_PAGE_CACHE_CC |         \
     LABOOT_PAGE_MODIFIED | LABOOT_PAGE_WRITE | LABOOT_PAGE_DIRTY |            \
     LABOOT_PAGE_VALID)

#define EFI_SUCCESS 0
#define EFI_BUFFER_TOO_SMALL 5

#define EFI_RESERVED_MEMORY_TYPE 0
#define EFI_LOADER_CODE 1
#define EFI_LOADER_DATA 2
#define EFI_BOOT_SERVICES_CODE 3
#define EFI_BOOT_SERVICES_DATA 4
#define EFI_CONVENTIONAL_MEMORY 7
#define EFI_PERSISTENT_MEMORY 14
#define EFI_MEMORY_RUNTIME ((uint64_t)1 << 63)
#define LABOOT_KERNEL_VIRT_OFFSET (0xffffffff80300000ULL - 0x00300000ULL)
#define LABOOT_HHDM_L2_TABLE_COUNT 254
#define LABOOT_IPI_BOOT_CPU 0x0U

struct boot_info {
    uint64_t bsp_phys_id;
    uint64_t dtb_phys;
    uint64_t dtb_virt;
    uint64_t hhdm_base;
    uint64_t kernel_phys_base;
    uint64_t kernel_virt_base;
    uint64_t kernel_phys_end;
    uint64_t kernel_virt_end;
    uint64_t root_page_table_phys;
    uint64_t root_page_table_virt;
    uint64_t cmdline_phys;
    uint64_t system_table_phys;
    uint64_t cmdline_virt;
    uint64_t system_table_virt;
};

static const efi_guid_t EFI_DTB_TABLE_GUID = {
    0xb1b621d5,
    0xf19c,
    0x41a5,
    {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0},
};

static const efi_guid_t LINUX_EFI_BOOT_MEMMAP_GUID = {
    0x800f683f,
    0xd08b,
    0x423a,
    {0xa2, 0x93, 0x96, 0x5c, 0x3c, 0x6f, 0xe2, 0xb4},
};

typedef struct efi_boot_memmap {
    size_t map_size;
    size_t desc_size;
    uint32_t desc_ver;
    size_t map_key;
    size_t buff_size;
    efi_memory_descriptor_t map[];
} efi_boot_memmap_t;

static struct boot_info laboot_boot_info;

static bool laboot_memory_map_ready = false;
static boot_memory_map_t laboot_memory_map_scratch;
static boot_memory_map_t laboot_memory_map;
static uint64_t laboot_valen = 39;
static uint64_t laboot_boottime = 0;

typedef struct laboot_ap_startup_data {
    uint64_t pwctl0;
    uint64_t pwctl1;
    uint64_t stlbpgsize;
    uint64_t pgdl;
    uint64_t pgdh;
    uint64_t dmw0;
    uint64_t dmw1;
    uint64_t dmw2;
    uint64_t dmw3;
    uint64_t tlbrentry;
    uint64_t stack_top;
    uint64_t entry;
} laboot_ap_startup_data_t;

extern char __kernel_image_start[];
extern char __kernel_image_end[];
extern char __boot_start_virt[];
extern char __boot_end_virt[];
extern uint64_t __boot_root_pt_virt[];
extern uint64_t __boot_high_l2_pt_virt[];
extern uint64_t __boot_hhdm_l3_pt_virt[];
extern uint64_t __boot_hhdm_pt_pages_virt[];
extern void laboot_ap_entry(void);

static void laboot_build_memory_map(void);
static void laboot_find_dtb_from_system_table(void);

static uintptr_t align_down(uintptr_t value, uintptr_t align) {
    return value & ~(align - 1);
}

static uintptr_t align_up(uintptr_t value, uintptr_t align) {
    return align_down(value + align - 1, align);
}

static uintptr_t high_virt_to_loaded_phys(uintptr_t addr) {
    return addr - LABOOT_KERNEL_VIRT_OFFSET;
}

static uint64_t laboot_hhdm_l2_index_start(void) {
    return (laboot_boot_info.hhdm_base >> 30) & 511;
}

static uint64_t *laboot_hhdm_l3_table(uint64_t l2_index) {
    uint64_t start = laboot_hhdm_l2_index_start();
    if (l2_index < start || l2_index >= start + LABOOT_HHDM_L2_TABLE_COUNT)
        return NULL;

    return __boot_hhdm_l3_pt_virt +
           (l2_index - start) * (PAGE_SIZE / sizeof(uint64_t));
}

static void laboot_map_hhdm_2m(uint64_t phys) {
    uint64_t phys_2m = align_down(phys, 1ULL << 21);
    uint64_t virt = laboot_boot_info.hhdm_base + phys_2m;
    uint64_t root_index = (virt >> 39) & 511;
    uint64_t l2_index = (virt >> 30) & 511;
    uint64_t *l3 = laboot_hhdm_l3_table(l2_index);
    if (!l3)
        return;

    if (__boot_root_pt_virt[root_index] == 0) {
        uint64_t high_l2_phys =
            high_virt_to_loaded_phys((uintptr_t)__boot_high_l2_pt_virt);
        __boot_root_pt_virt[root_index] = high_l2_phys;
    }

    if (__boot_high_l2_pt_virt[l2_index] == 0) {
        uint64_t l3_phys = high_virt_to_loaded_phys((uintptr_t)l3);
        __boot_high_l2_pt_virt[l2_index] = l3_phys;
    }

    uint64_t entry_index = (virt >> 21) & 511;
    l3[entry_index] = phys_2m | LABOOT_PTE_FLAGS;
    arch_flush_tlb(virt);
}

static void laboot_map_hhdm_range(uint64_t start, uint64_t len) {
    if (len == 0)
        return;

    uint64_t cur = align_down(start, 1ULL << 21);
    uint64_t end = align_up(start + len, 1ULL << 21);
    while (cur < end) {
        laboot_map_hhdm_2m(cur);
        cur += 1ULL << 21;
    }
}

static void *laboot_hhdm_ptr_from_phys(uintptr_t phys, size_t size) {
    if (!phys)
        return NULL;

    laboot_map_hhdm_range(phys, size ? size : PAGE_SIZE);
    return (void *)(uintptr_t)(laboot_boot_info.hhdm_base + phys);
}

void boot_init() { (void)boot_get_memory_map(); }

uint64_t boot_get_hhdm_offset() { return laboot_boot_info.hhdm_base; }

boot_memory_map_t *boot_get_memory_map() {
    laboot_build_memory_map();
    return &laboot_memory_map;
}

boot_framebuffer_t *boot_get_framebuffer() { return NULL; }

uintptr_t boot_get_acpi_rsdp() { return 0; }

uint64_t boot_get_dtb() { return laboot_boot_info.dtb_virt; }

void boot_get_smbios_entries(void **entry32, void **entry64) {
    if (entry32)
        *entry32 = NULL;
    if (entry64)
        *entry64 = NULL;
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

char *boot_get_cmdline() {
    return (char *)(uintptr_t)laboot_boot_info.cmdline_virt;
}

uint64_t boot_get_boottime() { return laboot_boottime; }

uint64_t boot_get_firmware_type(void) { return LIMINE_FIRMWARE_TYPE_EFI64; }

uint64_t boot_get_system_table(void) {
    return laboot_boot_info.system_table_virt;
}

static void
laboot_add_memory_entry(uintptr_t addr, size_t len,
                        typeof(laboot_memory_map.entries[0].type) type) {
    if (len == 0 || laboot_memory_map.entry_count >=
                        sizeof(laboot_memory_map.entries) /
                            sizeof(laboot_memory_map.entries[0])) {
        return;
    }

    laboot_memory_map.entries[laboot_memory_map.entry_count++] =
        (boot_memory_map_entry_t){
            .addr = addr,
            .len = len,
            .type = type,
        };
}

static bool laboot_append_memory_entry(boot_memory_map_t *map,
                                       boot_memory_map_entry_t entry) {
    if (entry.len == 0)
        return true;

    if (map->entry_count >= sizeof(map->entries) / sizeof(map->entries[0]))
        return false;

    map->entries[map->entry_count++] = entry;
    return true;
}

static bool laboot_phys_id_seen(const uint64_t *phys_ids, uint64_t count,
                                uint64_t phys_id) {
    for (uint64_t i = 0; i < count; i++) {
        if (phys_ids[i] == phys_id)
            return true;
    }

    return false;
}

static bool laboot_cpu_node_enabled(const void *fdt, int node) {
    int len = 0;
    const char *status = fdt_getprop(fdt, node, "status", &len);
    if (!status)
        return true;

    return strcmp(status, "disabled") != 0;
}

static uint64_t fdt_cells_read64(const fdt32_t *cells, int cell_count);

static bool laboot_read_cpu_phys_id(const void *fdt, int cpus, int cpu_node,
                                    uint64_t *phys_id) {
    int len = 0;
    const char *device_type = fdt_getprop(fdt, cpu_node, "device_type", &len);
    if (!device_type || strcmp(device_type, "cpu") != 0)
        return false;

    if (!laboot_cpu_node_enabled(fdt, cpu_node))
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

    *phys_id = fdt_cells_read64(reg, address_cells);
    return true;
}

static uint64_t laboot_discover_phys_ids_from_dtb(uint64_t *phys_ids,
                                                  uint64_t max_phys_ids) {
    if (max_phys_ids == 0)
        return 0;

    uint64_t count = 0;
    uint64_t bsp = laboot_boot_info.bsp_phys_id;
    phys_ids[count++] = bsp;

    laboot_find_dtb_from_system_table();
    const void *fdt = (void *)laboot_boot_info.dtb_virt;
    if (!fdt || fdt_check_header(fdt) != 0)
        return count;

    int cpus = fdt_path_offset(fdt, "/cpus");
    if (cpus < 0)
        return count;

    int cpu_node = -1;
    fdt_for_each_subnode(cpu_node, fdt, cpus) {
        uint64_t phys_id = 0;
        if (!laboot_read_cpu_phys_id(fdt, cpus, cpu_node, &phys_id))
            continue;

        if (laboot_phys_id_seen(phys_ids, count, phys_id))
            continue;

        if (count >= max_phys_ids)
            break;

        phys_ids[count++] = phys_id;
    }

    return count;
}

static void laboot_add_reserved_range(uintptr_t start, uintptr_t end) {
    if (start >= end)
        return;

    start = align_down(start, PAGE_SIZE);
    end = align_up(end, PAGE_SIZE);

    boot_memory_map_t *new_map = &laboot_memory_map_scratch;
    new_map->entry_count = 0;

    for (size_t i = 0; i < laboot_memory_map.entry_count; i++) {
        boot_memory_map_entry_t entry = laboot_memory_map.entries[i];
        uintptr_t entry_start = entry.addr;
        uintptr_t entry_end = entry.addr + entry.len;

        if (entry.type != USABLE || end <= entry_start || start >= entry_end) {
            if (!laboot_append_memory_entry(new_map, entry))
                return;
            continue;
        }

        uintptr_t reserved_start = MAX(start, entry_start);
        uintptr_t reserved_end = MIN(end, entry_end);

        if (entry_start < reserved_start) {
            if (!laboot_append_memory_entry(
                    new_map, (boot_memory_map_entry_t){
                                 .addr = entry_start,
                                 .len = reserved_start - entry_start,
                                 .type = USABLE,
                             })) {
                return;
            }
        }

        if (!laboot_append_memory_entry(
                new_map, (boot_memory_map_entry_t){
                             .addr = reserved_start,
                             .len = reserved_end - reserved_start,
                             .type = RESERVED,
                         })) {
            return;
        }

        if (reserved_end < entry_end) {
            if (!laboot_append_memory_entry(new_map,
                                            (boot_memory_map_entry_t){
                                                .addr = reserved_end,
                                                .len = entry_end - reserved_end,
                                                .type = USABLE,
                                            })) {
                return;
            }
        }
    }

    laboot_memory_map.entry_count = new_map->entry_count;
    for (size_t i = 0; i < new_map->entry_count; i++) {
        laboot_memory_map.entries[i] = new_map->entries[i];
    }
}

static bool laboot_efi_memory_type_usable(uint32_t type, uint64_t attr) {
    if (attr & EFI_MEMORY_RUNTIME)
        return false;

    return type == EFI_LOADER_CODE || type == EFI_LOADER_DATA ||
           type == EFI_BOOT_SERVICES_CODE || type == EFI_BOOT_SERVICES_DATA ||
           type == EFI_CONVENTIONAL_MEMORY || type == EFI_PERSISTENT_MEMORY;
}

static bool laboot_guid_equal(const efi_guid_t *a, const efi_guid_t *b) {
    return a && b && memcmp(a, b, sizeof(*a)) == 0;
}

static efi_configuration_table_t *laboot_config_tables(size_t *count) {
    efi_system_table_t *system_table =
        (efi_system_table_t *)(uintptr_t)laboot_boot_info.system_table_virt;
    if (count)
        *count = 0;
    if (!system_table || !system_table->configuration_table ||
        system_table->number_of_table_entries == 0 ||
        system_table->number_of_table_entries > 4096) {
        return NULL;
    }

    size_t table_count = system_table->number_of_table_entries;
    efi_configuration_table_t *tables = laboot_hhdm_ptr_from_phys(
        (uintptr_t)system_table->configuration_table,
        table_count * sizeof(efi_configuration_table_t));
    if (!tables)
        return NULL;

    if (count)
        *count = table_count;
    return tables;
}

static void *laboot_find_config_table(const efi_guid_t *guid) {
    size_t table_count = 0;
    efi_configuration_table_t *tables = laboot_config_tables(&table_count);
    if (!tables)
        return NULL;

    for (size_t i = 0; i < table_count; i++) {
        if (laboot_guid_equal(&tables[i].vendor_guid, guid))
            return tables[i].vendor_table;
    }

    return NULL;
}

static void laboot_find_dtb_from_system_table(void) {
    if (laboot_boot_info.dtb_virt)
        return;

    uintptr_t dtb_phys =
        (uintptr_t)laboot_find_config_table(&EFI_DTB_TABLE_GUID);
    if (!dtb_phys)
        return;

    laboot_map_hhdm_2m(dtb_phys);
    uintptr_t dtb_virt = laboot_boot_info.hhdm_base + dtb_phys;
    const void *fdt = (const void *)dtb_virt;
    if (fdt_check_header(fdt) != 0)
        return;

    laboot_boot_info.dtb_phys = dtb_phys;
    laboot_boot_info.dtb_virt = dtb_virt;
    laboot_map_hhdm_range(dtb_phys, fdt_totalsize(fdt));
}

static bool laboot_build_memory_map_from_efi(void) {
    uintptr_t boot_memmap_phys =
        (uintptr_t)laboot_find_config_table(&LINUX_EFI_BOOT_MEMMAP_GUID);
    if (!boot_memmap_phys)
        return false;

    efi_boot_memmap_t *boot_memmap =
        laboot_hhdm_ptr_from_phys(boot_memmap_phys, PAGE_SIZE);
    if (!boot_memmap || boot_memmap->map_size == 0 ||
        boot_memmap->desc_size < sizeof(efi_memory_descriptor_t)) {
        return false;
    }

    size_t total_size = sizeof(*boot_memmap) + boot_memmap->map_size;
    boot_memmap = laboot_hhdm_ptr_from_phys(boot_memmap_phys, total_size);
    if (!boot_memmap)
        return false;

    laboot_memory_map.entry_count = 0;
    uint8_t *pos = (uint8_t *)boot_memmap->map;
    uint8_t *end = pos + boot_memmap->map_size;
    while (pos + sizeof(efi_memory_descriptor_t) <= end) {
        efi_memory_descriptor_t *desc = (efi_memory_descriptor_t *)pos;
        uint64_t base = desc->physical_start;
        uint64_t size = desc->number_of_pages * PAGE_SIZE;
        laboot_add_memory_entry(
            (uintptr_t)base, (size_t)size,
            laboot_efi_memory_type_usable(desc->type, desc->attribute)
                ? USABLE
                : RESERVED);
        laboot_map_hhdm_range(base, size);
        pos += boot_memmap->desc_size;
    }

    return laboot_memory_map.entry_count != 0;
}

static uint64_t fdt_cells_read64(const fdt32_t *cells, int cell_count) {
    uint64_t value = 0;
    for (int i = 0; i < cell_count; i++) {
        value = (value << 32) | fdt32_to_cpu(cells[i]);
    }
    return value;
}

static void laboot_build_memory_map_from_dtb(void) {
    if (laboot_memory_map_ready)
        return;

    laboot_memory_map.entry_count = 0;

    const void *fdt = (void *)laboot_boot_info.dtb_virt;
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
                laboot_add_memory_entry((uintptr_t)base, (size_t)size, USABLE);
                laboot_map_hhdm_range(base, size);
            }
        }
    }

    if (fdt && fdt_check_header(fdt) == 0) {
        laboot_add_reserved_range((uintptr_t)laboot_boot_info.dtb_phys,
                                  (uintptr_t)laboot_boot_info.dtb_phys +
                                      fdt_totalsize(fdt));
    }

    laboot_memory_map_ready = true;
}

static void laboot_reserve_loaded_ranges(void) {
    laboot_add_reserved_range(
        high_virt_to_loaded_phys((uintptr_t)&__boot_start_virt),
        high_virt_to_loaded_phys((uintptr_t)&__boot_end_virt));
    laboot_add_reserved_range(
        high_virt_to_loaded_phys((uintptr_t)&__kernel_virt_start),
        high_virt_to_loaded_phys((uintptr_t)&__kernel_virt_end));

    const void *fdt = (void *)laboot_boot_info.dtb_virt;
    if (fdt && fdt_check_header(fdt) == 0) {
        laboot_add_reserved_range((uintptr_t)laboot_boot_info.dtb_phys,
                                  (uintptr_t)laboot_boot_info.dtb_phys +
                                      fdt_totalsize(fdt));
    }
}

static void laboot_build_memory_map(void) {
    if (laboot_memory_map_ready)
        return;

    laboot_find_dtb_from_system_table();

    if (!laboot_build_memory_map_from_efi()) {
        laboot_build_memory_map_from_dtb();
        laboot_memory_map_ready = false;
    }

    laboot_reserve_loaded_ranges();
    laboot_memory_map_ready = true;
}

extern uint64_t cpu_count;
extern uint64_t cpuid_to_physid[MAX_CPU_NUM];
extern spinlock_t ap_startup_lock;

static void laboot_fill_ap_startup_data(laboot_ap_startup_data_t *data,
                                        uintptr_t stack_top, uintptr_t entry) {
    data->pwctl0 = csr_read(LOONGARCH_CSR_PWCTL0);
    data->pwctl1 = csr_read(LOONGARCH_CSR_PWCTL1);
    data->stlbpgsize = csr_read(LOONGARCH_CSR_STLBPGSIZE);
    data->pgdl = csr_read(LOONGARCH_CSR_PGDL);
    data->pgdh = csr_read(LOONGARCH_CSR_PGDH);
    data->dmw0 = csr_read(LOONGARCH_CSR_DMWIN0);
    data->dmw1 = csr_read(LOONGARCH_CSR_DMWIN1);
    data->dmw2 = csr_read(LOONGARCH_CSR_DMWIN2);
    data->dmw3 = csr_read(LOONGARCH_CSR_DMWIN3);
    data->tlbrentry = csr_read(LOONGARCH_CSR_TLBRENTRY);
    data->stack_top = stack_top;
    data->entry = entry;
}

void boot_smp_init(uintptr_t entry) {
    uint64_t discovered_phys_ids[MAX_CPU_NUM];
    uint64_t discovered_count =
        laboot_discover_phys_ids_from_dtb(discovered_phys_ids, MAX_CPU_NUM);
    if (discovered_count == 0) {
        discovered_phys_ids[0] = laboot_boot_info.bsp_phys_id;
        discovered_count = 1;
    }

    cpu_count = 1;
    cpuid_to_physid[0] = laboot_boot_info.bsp_phys_id;

    for (uint64_t i = 0; i < discovered_count; i++) {
        uint64_t phys_id = discovered_phys_ids[i];
        if (phys_id == laboot_boot_info.bsp_phys_id)
            continue;

        loongarch_iocsr_clear_mbuf((uint32_t)phys_id, 0);

        if (cpu_count >= MAX_CPU_NUM)
            break;

        uint64_t stack_phys = alloc_frames(STACK_SIZE / PAGE_SIZE);
        raw_spin_lock(&ap_startup_lock);

        laboot_ap_startup_data_t *data =
            (laboot_ap_startup_data_t *)&__ap_startup_info_virt;
        laboot_fill_ap_startup_data(
            data, (uintptr_t)phys_to_virt(stack_phys + STACK_SIZE), entry);
        memory_barrier();

        uint64_t cpu_id = cpu_count;
        cpuid_to_physid[cpu_id] = phys_id;
        cpu_count = cpu_id + 1;
        memory_barrier();

        loongarch_iocsr_send_mbuf64((uint32_t)phys_id, 0,
                                    (uint64_t)laboot_ap_entry);
        loongarch_iocsr_send_ipi((uint32_t)phys_id, LABOOT_IPI_BOOT_CPU);
    }
}

extern void kmain();

void laboot_main(uint64_t phys_id, void *dtb, const struct boot_info *boot) {
    (void)phys_id;
    (void)dtb;
    memcpy(&laboot_boot_info, boot, sizeof(struct boot_info));
    laboot_valen = 65 - __builtin_clzll(~laboot_boot_info.hhdm_base);
    if (laboot_valen < 39)
        laboot_valen = 39;
    physical_memory_offset = laboot_boot_info.hhdm_base;
    kmain();
}

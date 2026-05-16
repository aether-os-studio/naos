#include <boot/boot.h>
#include <drivers/fdt/fdt.h>
#include <limine.h>
#include <mm/hhdm.h>
#include <mm/mm.h>

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

typedef uint64_t efi_status_t;
typedef uint64_t efi_physical_address_t;
typedef uint64_t efi_virtual_address_t;
typedef void *efi_handle_t;

typedef struct efi_table_header {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
} efi_table_header_t;

typedef struct efi_guid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
} efi_guid_t;

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

typedef struct efi_configuration_table {
    efi_guid_t vendor_guid;
    void *vendor_table;
} efi_configuration_table_t;

typedef struct efi_memory_descriptor {
    uint32_t type;
    uint32_t pad;
    efi_physical_address_t physical_start;
    efi_virtual_address_t virtual_start;
    uint64_t number_of_pages;
    uint64_t attribute;
} efi_memory_descriptor_t;

typedef struct efi_boot_memmap {
    size_t map_size;
    size_t desc_size;
    uint32_t desc_ver;
    size_t map_key;
    size_t buff_size;
    efi_memory_descriptor_t map[];
} efi_boot_memmap_t;

typedef efi_status_t (*efi_get_memory_map_t)(
    size_t *memory_map_size, efi_memory_descriptor_t *memory_map,
    size_t *map_key, size_t *descriptor_size, uint32_t *descriptor_version);

typedef struct efi_boot_services {
    efi_table_header_t hdr;
    char _pad1[240 - sizeof(efi_table_header_t)];
    efi_get_memory_map_t get_memory_map;
} efi_boot_services_t;

typedef struct efi_system_table {
    efi_table_header_t hdr;
    uint16_t *firmware_vendor;
    uint32_t firmware_revision;
    efi_handle_t console_in_handle;
    void *con_in;
    efi_handle_t console_out_handle;
    void *con_out;
    efi_handle_t standard_error_handle;
    void *std_err;
    void *runtime_services;
    efi_boot_services_t *boot_services;
    size_t number_of_table_entries;
    efi_configuration_table_t *configuration_table;
} efi_system_table_t;

static struct boot_info laboot_boot_info;

static bool laboot_memory_map_ready = false;
static boot_memory_map_t laboot_memory_map_scratch;
static boot_memory_map_t laboot_memory_map;
static uint8_t laboot_efi_mmap_buffer[256 * 1024] __attribute__((aligned(16)));
static uint64_t laboot_valen = 39;
static uint64_t laboot_boottime = 0;

extern char __kernel_image_start[];
extern char __kernel_image_end[];
extern char __boot_start_virt[];
extern char __boot_end_virt[];
extern uint64_t __boot_root_pt_virt[];
extern uint64_t __boot_high_l2_pt_virt[];
extern uint64_t __boot_hhdm_l3_pt_virt[];
extern uint64_t __boot_hhdm_pt_pages_virt[];

static void laboot_build_memory_map(void);

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
        high_virt_to_loaded_phys((uintptr_t)&__kernel_image_start),
        high_virt_to_loaded_phys((uintptr_t)&__kernel_image_end));
    laboot_add_reserved_range(
        high_virt_to_loaded_phys((uintptr_t)&__boot_start_virt),
        high_virt_to_loaded_phys((uintptr_t)&__boot_end_virt));

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

extern void kmain();

void laboot_main(uint64_t phys_id, void *dtb, const struct boot_info *boot) {
    (void)phys_id;
    (void)dtb;
    laboot_boot_info = *boot;
    laboot_valen = 65 - __builtin_clzll(~laboot_boot_info.hhdm_base);
    if (laboot_valen < 39)
        laboot_valen = 39;
    physical_memory_offset = laboot_boot_info.hhdm_base;
    kmain();
}

#include <boot/boot.h>
#include <boot/sbi/mm.h>
#include <libs/fdt/libfdt.h>

static uint64_t bsp_hartid = 0;
static uint64_t sbi_dtb_paddr = 0;
static uint64_t sbi_dtb_vaddr = 0;
static boot_memory_map_t sbi_memory_map;
static bool sbi_memory_map_ready = false;

extern void kmain();
extern char kernel_virt_start[];
extern char kernel_virt_end[];

uint64_t boot_get_bsp_hartid() { return bsp_hartid; }

uint64_t boot_get_paging_mode() {
    return 0; // Only SV39 paging mode
}

uintptr_t boot_get_acpi_rsdp() { return 0; }

uint64_t boot_get_hhdm_offset() { return SBI_HHDM_OFFSET; }

uint64_t boot_get_dtb() { return sbi_dtb_vaddr; }

boot_framebuffer_t *boot_get_framebuffer() { return NULL; }

uint64_t boot_get_boottime() {
    return 0; // TODO
}

char *boot_get_cmdline() { return NULL; }

void boot_init() {}

static uint64_t read_fdt_cells(const fdt32_t *cells, int count) {
    uint64_t value = 0;

    for (int i = 0; i < count; i++)
        value = (value << 32) | fdt32_to_cpu(cells[i]);

    return value;
}

static void memory_map_append(uint64_t addr, uint64_t len, int type) {
    if (len == 0 ||
        sbi_memory_map.entry_count >=
            sizeof(sbi_memory_map.entries) / sizeof(sbi_memory_map.entries[0]))
        return;

    sbi_memory_map.entries[sbi_memory_map.entry_count++] =
        (boot_memory_map_entry_t){
            .addr = addr,
            .len = len,
            .type = type,
        };
}

static void memory_map_add_usable(uint64_t addr, uint64_t len) {
    memory_map_append(addr, len, USABLE);
    boot_mm_map_hhdm_range(addr, len);
}

static void memory_map_reserve_range(uint64_t reserve_start,
                                     uint64_t reserve_len) {
    if (reserve_len == 0)
        return;

    uint64_t reserve_end =
        PADDING_UP(reserve_start + reserve_len, SBI_PAGE_SIZE);
    reserve_start = PADDING_DOWN(reserve_start, SBI_PAGE_SIZE);
    size_t entry_count = sbi_memory_map.entry_count;

    for (size_t i = 0; i < entry_count; i++) {
        boot_memory_map_entry_t entry = sbi_memory_map.entries[i];

        if (entry.type != USABLE)
            continue;

        uint64_t entry_start = entry.addr;
        uint64_t entry_end = entry.addr + entry.len;

        if (reserve_end <= entry_start || reserve_start >= entry_end)
            continue;

        uint64_t overlap_start =
            reserve_start > entry_start ? reserve_start : entry_start;
        uint64_t overlap_end =
            reserve_end < entry_end ? reserve_end : entry_end;

        sbi_memory_map.entries[i].addr = entry_start;
        sbi_memory_map.entries[i].len = overlap_start - entry_start;

        if (entry_end > overlap_end)
            memory_map_append(overlap_end, entry_end - overlap_end, USABLE);

        memory_map_append(overlap_start, overlap_end - overlap_start, RESERVED);
    }
}

static int memory_map_entry_compare(const void *a, const void *b) {
    const boot_memory_map_entry_t *lhs = a;
    const boot_memory_map_entry_t *rhs = b;

    if (lhs->addr < rhs->addr)
        return -1;
    if (lhs->addr > rhs->addr)
        return 1;
    if (lhs->type < rhs->type)
        return -1;
    if (lhs->type > rhs->type)
        return 1;
    return 0;
}

static void memory_map_compact(void) {
    size_t out = 0;

    for (size_t i = 0; i < sbi_memory_map.entry_count; i++) {
        boot_memory_map_entry_t entry = sbi_memory_map.entries[i];

        if (entry.len == 0)
            continue;

        sbi_memory_map.entries[out++] = entry;
    }

    sbi_memory_map.entry_count = out;
    if (sbi_memory_map.entry_count == 0)
        return;

    qsort(sbi_memory_map.entries, sbi_memory_map.entry_count,
          sizeof(sbi_memory_map.entries[0]), memory_map_entry_compare);

    out = 0;
    for (size_t i = 0; i < sbi_memory_map.entry_count; i++) {
        boot_memory_map_entry_t entry = sbi_memory_map.entries[i];

        if (out > 0) {
            boot_memory_map_entry_t *prev = &sbi_memory_map.entries[out - 1];
            if (prev->type == entry.type &&
                prev->addr + prev->len == entry.addr) {
                prev->len += entry.len;
                continue;
            }
        }

        sbi_memory_map.entries[out++] = entry;
    }

    sbi_memory_map.entry_count = out;
}

static void memory_map_build_from_dtb(void) {
    const void *fdt = (const void *)(uintptr_t)sbi_dtb_vaddr;

    memset(&sbi_memory_map, 0, sizeof(sbi_memory_map));
    if (!fdt || fdt_check_header(fdt) != 0)
        return;

    for (int node = fdt_next_node(fdt, -1, NULL); node >= 0;
         node = fdt_next_node(fdt, node, NULL)) {
        int len = 0;
        const char *device_type = fdt_getprop(fdt, node, "device_type", &len);

        if (!device_type || len < (int)sizeof("memory") ||
            strcmp(device_type, "memory") != 0)
            continue;

        int parent = fdt_parent_offset(fdt, node);
        int address_cells = parent >= 0 ? fdt_address_cells(fdt, parent) : 2;
        int size_cells = parent >= 0 ? fdt_size_cells(fdt, parent) : 1;

        if (address_cells <= 0 || address_cells > 2 || size_cells <= 0 ||
            size_cells > 2)
            continue;

        const fdt32_t *reg = fdt_getprop(fdt, node, "reg", &len);
        int tuple_cells = address_cells + size_cells;

        if (!reg || len <= 0 || len % (int)(tuple_cells * sizeof(fdt32_t)) != 0)
            continue;

        int tuple_count = len / (int)(tuple_cells * sizeof(fdt32_t));
        for (int i = 0; i < tuple_count; i++) {
            const fdt32_t *tuple = reg + i * tuple_cells;
            uint64_t addr = read_fdt_cells(tuple, address_cells);
            uint64_t size = read_fdt_cells(tuple + address_cells, size_cells);

            memory_map_add_usable(addr, size);
        }
    }

    uint64_t kernel_start =
        (uint64_t)(uintptr_t)kernel_virt_start - SBI_KERNEL_VMA;
    uint64_t kernel_end = (uint64_t)(uintptr_t)kernel_virt_end - SBI_KERNEL_VMA;

    memory_map_reserve_range(kernel_start, kernel_end - kernel_start);
    memory_map_reserve_range(sbi_dtb_paddr, fdt_totalsize(fdt));
    memory_map_reserve_range(boot_mm_pt_pool_paddr(), boot_mm_pt_pool_size());

    int reserved = fdt_num_mem_rsv(fdt);
    for (int i = 0; i < reserved; i++) {
        uint64_t addr = 0;
        uint64_t size = 0;

        if (fdt_get_mem_rsv(fdt, i, &addr, &size) == 0)
            memory_map_reserve_range(addr, size);
    }

    memory_map_compact();
}

boot_memory_map_t *boot_get_memory_map() {
    if (!sbi_memory_map_ready) {
        memory_map_build_from_dtb();
        sbi_memory_map_ready = true;
    }

    return &sbi_memory_map;
}

void boot_get_modules(boot_module_t **modules, size_t *count) { *count = 0; }

void boot_get_smbios_entries(void **entry32, void **entry64) {
    if (entry32)
        *entry32 = NULL;
    if (entry64)
        *entry64 = NULL;
}

void *boot_get_executable_file(size_t *size) {
    if (size != NULL) {
        *size = 0;
    }
    return NULL;
}

void boot_smp_init(uintptr_t entry) {
    // TODO
}

void sbi_main(size_t hartid, size_t device_tree_paddr) {
    bsp_hartid = hartid;
    sbi_dtb_paddr = device_tree_paddr;
    boot_mm_init();
    sbi_dtb_vaddr = boot_mm_map_dtb(sbi_dtb_paddr);

    kmain();
    while (true) {
        __asm__ volatile("wfi" ::: "memory");
    }
}

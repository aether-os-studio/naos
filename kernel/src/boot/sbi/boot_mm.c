#include <boot/sbi/mm.h>
#include <libs/fdt/libfdt.h>
#include <libs/klibc.h>

#define SV39_PT_ENTRY_COUNT 512
#define SV39_SATP_PPN_MASK ((1ULL << 44) - 1)
#define BOOT_MM_PT_POOL_PAGES 16

typedef uint64_t pte_t;

#define PTE_V ((uint64_t)1 << 0)
#define PTE_R ((uint64_t)1 << 1)
#define PTE_W ((uint64_t)1 << 2)
#define PTE_X ((uint64_t)1 << 3)
#define PTE_A ((uint64_t)1 << 6)
#define PTE_D ((uint64_t)1 << 7)
#define PTE_LEAF_FLAGS (PTE_R | PTE_W | PTE_X)
#define PTE_PPN(paddr) ((((uint64_t)(paddr)) >> 12) << 10)
#define PTE_PADDR(pte) ((((uint64_t)(pte)) >> 10) << 12)
#define PTE_RO (PTE_V | PTE_R | PTE_A | PTE_D)
#define PTE_RW (PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)

#define SIZE_2M (2ULL * 1024 * 1024)
#define SIZE_1G (1024ULL * 1024 * 1024)

static uint8_t boot_mm_pt_pool[BOOT_MM_PT_POOL_PAGES * SBI_PAGE_SIZE]
    __attribute__((aligned(SBI_PAGE_SIZE)));
static size_t boot_mm_pt_next = 0;

static uint64_t align_down(uint64_t value, uint64_t alignment) {
    return value & ~(alignment - 1);
}

static uint64_t align_up(uint64_t value, uint64_t alignment) {
    return align_down(value + alignment - 1, alignment);
}

static void *boot_identity_ptr(uint64_t paddr) {
    return (void *)(uintptr_t)paddr;
}

static uint64_t boot_virt_to_phys(const void *vaddr) {
    return (uint64_t)(uintptr_t)vaddr - SBI_KERNEL_VMA;
}

static uint64_t boot_alloc_pt_page(void) {
    ASSERT(boot_mm_pt_next < BOOT_MM_PT_POOL_PAGES);

    void *page = boot_mm_pt_pool + boot_mm_pt_next * SBI_PAGE_SIZE;
    boot_mm_pt_next++;
    memset(page, 0, SBI_PAGE_SIZE);
    return boot_virt_to_phys(page);
}

static pte_t *boot_current_root_table(void) {
    uint64_t satp;
    asm volatile("csrr %0, satp" : "=r"(satp));
    return boot_identity_ptr((satp & SV39_SATP_PPN_MASK) << 12);
}

static pte_t *boot_next_table(pte_t *table, size_t index) {
    pte_t entry = table[index];

    ASSERT((entry & PTE_LEAF_FLAGS) == 0);
    if (entry & PTE_V)
        return boot_identity_ptr(PTE_PADDR(entry));

    uint64_t next_paddr = boot_alloc_pt_page();
    table[index] = PTE_PPN(next_paddr) | PTE_V;
    return boot_identity_ptr(next_paddr);
}

static bool boot_pte_is_leaf(pte_t entry) {
    return (entry & PTE_V) && (entry & PTE_LEAF_FLAGS);
}

static void boot_map_4k(uint64_t vaddr, uint64_t paddr, uint64_t flags) {
    ASSERT((vaddr & (SBI_PAGE_SIZE - 1)) == 0);
    ASSERT((paddr & (SBI_PAGE_SIZE - 1)) == 0);

    pte_t *root = boot_current_root_table();
    size_t vpn2 = (vaddr >> 30) & (SV39_PT_ENTRY_COUNT - 1);
    size_t vpn1 = (vaddr >> 21) & (SV39_PT_ENTRY_COUNT - 1);
    size_t vpn0 = (vaddr >> 12) & (SV39_PT_ENTRY_COUNT - 1);

    pte_t *level1 = boot_next_table(root, vpn2);
    pte_t *level0 = boot_next_table(level1, vpn1);
    level0[vpn0] = PTE_PPN(paddr) | flags;

    asm volatile("sfence.vma %0, zero" : : "r"(vaddr) : "memory");
}

static void boot_map_2m(uint64_t vaddr, uint64_t paddr, uint64_t flags) {
    ASSERT((vaddr & (SIZE_2M - 1)) == 0);
    ASSERT((paddr & (SIZE_2M - 1)) == 0);

    pte_t *root = boot_current_root_table();
    size_t vpn2 = (vaddr >> 30) & (SV39_PT_ENTRY_COUNT - 1);
    size_t vpn1 = (vaddr >> 21) & (SV39_PT_ENTRY_COUNT - 1);

    pte_t *level1 = boot_next_table(root, vpn2);
    level1[vpn1] = PTE_PPN(paddr) | flags;

    asm volatile("sfence.vma %0, zero" : : "r"(vaddr) : "memory");
}

static void boot_map_1g(uint64_t vaddr, uint64_t paddr, uint64_t flags) {
    ASSERT((vaddr & (SIZE_1G - 1)) == 0);
    ASSERT((paddr & (SIZE_1G - 1)) == 0);

    pte_t *root = boot_current_root_table();
    size_t vpn2 = (vaddr >> 30) & (SV39_PT_ENTRY_COUNT - 1);
    root[vpn2] = PTE_PPN(paddr) | flags;

    asm volatile("sfence.vma %0, zero" : : "r"(vaddr) : "memory");
}

static uint64_t next_boundary(uint64_t value, uint64_t size) {
    return align_up(value + 1, size);
}

static void boot_map_range(uint64_t vaddr, uint64_t paddr, uint64_t size,
                           uint64_t flags) {
    if (size == 0)
        return;

    uint64_t va = align_down(vaddr, SBI_PAGE_SIZE);
    uint64_t pa = align_down(paddr, SBI_PAGE_SIZE);
    uint64_t end = align_up(vaddr + size, SBI_PAGE_SIZE);

    while (va < end) {
        pte_t *root = boot_current_root_table();
        size_t vpn2 = (va >> 30) & (SV39_PT_ENTRY_COUNT - 1);
        pte_t root_entry = root[vpn2];

        if (boot_pte_is_leaf(root_entry)) {
            uint64_t next = next_boundary(va, SIZE_1G);
            uint64_t step = (next < end) ? next - va : end - va;
            va += step;
            pa += step;
            continue;
        }

        if ((va & (SIZE_1G - 1)) == 0 && (pa & (SIZE_1G - 1)) == 0 &&
            end - va >= SIZE_1G && root_entry == 0) {
            boot_map_1g(va, pa, flags);
            va += SIZE_1G;
            pa += SIZE_1G;
            continue;
        }

        if ((va & (SIZE_2M - 1)) == 0 && (pa & (SIZE_2M - 1)) == 0 &&
            end - va >= SIZE_2M) {
            pte_t *level1 = boot_next_table(root, vpn2);
            size_t vpn1 = (va >> 21) & (SV39_PT_ENTRY_COUNT - 1);
            pte_t level1_entry = level1[vpn1];

            if (boot_pte_is_leaf(level1_entry)) {
                va += SIZE_2M;
                pa += SIZE_2M;
                continue;
            }

            if (level1_entry == 0) {
                boot_map_2m(va, pa, flags);
                va += SIZE_2M;
                pa += SIZE_2M;
                continue;
            }
        }

        boot_map_4k(va, pa, flags);
        va += SBI_PAGE_SIZE;
        pa += SBI_PAGE_SIZE;
    }
}

void boot_mm_init(void) { boot_mm_pt_next = 0; }

uint64_t boot_mm_map_dtb(uint64_t dtb_paddr) {
    if (dtb_paddr == 0)
        return 0;

    uint64_t dtb_vaddr = SBI_HHDM_OFFSET + dtb_paddr;
    boot_map_range(dtb_vaddr, dtb_paddr, sizeof(struct fdt_header), PTE_RO);

    void *dtb = (void *)(uintptr_t)dtb_vaddr;
    if (fdt_check_header(dtb) != 0)
        return 0;

    boot_map_range(dtb_vaddr, dtb_paddr, fdt_totalsize(dtb), PTE_RO);
    return dtb_vaddr;
}

void boot_mm_map_hhdm_range(uint64_t paddr, uint64_t size) {
    boot_map_range(SBI_HHDM_OFFSET + paddr, paddr, size, PTE_RW);
}

uint64_t boot_mm_pt_pool_paddr(void) {
    return boot_virt_to_phys(boot_mm_pt_pool);
}

uint64_t boot_mm_pt_pool_size(void) { return sizeof(boot_mm_pt_pool); }

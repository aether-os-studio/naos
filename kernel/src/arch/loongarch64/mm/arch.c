#include <arch/loongarch64/mm/arch.h>
#include <arch/loongarch64/csr.h>
#include <mm/mm.h>

extern void loongarch64_tlb_refill_entry(void);

uint64_t arch_page_table_levels() { return ARCH_MAX_PT_LEVEL; }

uint64_t arch_user_va_limit(void) {
    uint64_t va_bits = ARCH_PT_OFFSET_BASE +
                       arch_page_table_levels() * ARCH_PT_OFFSET_PER_LEVEL;
    return (1ULL << (va_bits - 1)) - 1;
}

uint64_t *get_current_page_dir(bool user) {
    uint64_t pgd =
        user ? csr_read(LOONGARCH_CSR_PGDL) : csr_read(LOONGARCH_CSR_PGDH);
    return (uint64_t *)phys_to_virt(pgd & ARCH_PTE_ADDR_MASK);
}

void loongarch64_set_user_page_table_root(uint64_t root_paddr) {
    csr_write(LOONGARCH_CSR_PGDL, root_paddr & ARCH_PTE_ADDR_MASK);
    arch_flush_tlb_all();
}

void set_current_page_dir(bool user, uint64_t pgdir) {
    if (user)
        csr_write(LOONGARCH_CSR_PGDL, pgdir & ARCH_PTE_ADDR_MASK);
    else
        csr_write(LOONGARCH_CSR_PGDH, pgdir & ARCH_PTE_ADDR_MASK);
    arch_flush_tlb_all();
}

void loongarch64_init_mmu(void) {
    uint64_t handler_phys = virt_to_phys(loongarch64_tlb_refill_entry);
    uint64_t old_dmwin1 = csr_read(LOONGARCH_CSR_DMWIN1);

    csr_write(LOONGARCH_CSR_DMWIN1, LOONGARCH_DMW0_CONFIG);
    asm volatile("ibar 0\n\t"
                 "dbar 0" ::
                     : "memory");

    csr_write(LOONGARCH_CSR_TLBRENTRY, LOONGARCH_DMW0_BASE | handler_phys);
    csr_write(LOONGARCH_CSR_PWCTL0, LOONGARCH_PWCTL0_4LEVEL);
    csr_write(LOONGARCH_CSR_PWCTL1, LOONGARCH_PWCTL1_4LEVEL);
    csr_write(LOONGARCH_CSR_STLBPGSIZE, LOONGARCH_STLBPGSIZE_4K);
    csr_write(LOONGARCH_CSR_DMWIN0, LOONGARCH_DMW0_CONFIG);
    csr_write(LOONGARCH_CSR_DMWIN1, old_dmwin1);
    arch_flush_tlb_all();
}

void arch_page_table_init(void) {}

uint64_t arch_page_table_root_entries(int level) {
    (void)level;
    return (1UL << ARCH_PT_OFFSET_PER_LEVEL);
}

uint64_t arch_make_page_table_entry(uint64_t paddr, uint64_t flags) {
    return ARCH_MAKE_PDE(paddr, flags);
}

void arch_page_table_prepare_new(uint64_t *root) { memset(root, 0, PAGE_SIZE); }

void arch_page_table_copy_kernel(uint64_t *dst, uint64_t *src) {
    (void)dst;
    (void)src;
}

bool arch_page_table_flags_writable(uint64_t flags) {
    return (flags & ARCH_PT_FLAG_WRITEABLE) != 0;
}

uint64_t arch_page_table_flags_make_cow(uint64_t flags) {
    return (flags | ARCH_PT_FLAG_COW) &
           ~(ARCH_PT_FLAG_WRITEABLE | ARCH_PT_FLAG_DIRTY);
}

uint64_t arch_page_table_flags_make_writable(uint64_t flags) {
    return (flags | ARCH_PT_FLAG_WRITEABLE | ARCH_PT_FLAG_DIRTY) &
           ~ARCH_PT_FLAG_COW;
}

uint64_t get_arch_page_table_flags(uint64_t flags) {
    uint64_t attr = ARCH_PT_FLAG_PRESENT | ARCH_PT_FLAG_VALID |
                    ARCH_PT_FLAG_CACHE_CC | ARCH_PT_FLAG_MODIFIED;

    if ((flags & PT_FLAG_U) == 0)
        attr |= ARCH_PT_FLAG_GLOBAL;

    if (flags & PT_FLAG_W)
        attr |= ARCH_PT_FLAG_WRITE | ARCH_PT_FLAG_DIRTY;
    if ((flags & PT_FLAG_R) == 0)
        attr |= ARCH_PT_FLAG_NO_READ;
    if ((flags & PT_FLAG_X) == 0)
        attr |= ARCH_PT_FLAG_NO_EXEC;
    if (flags & PT_FLAG_U)
        attr |= ARCH_PT_FLAG_USER;
    if (flags & PT_FLAG_COW)
        attr |= ARCH_PT_FLAG_COW;

    return attr;
}

void arch_flush_tlb(uint64_t vaddr) {
    asm volatile("dbar 0\n\t"
                 "invtlb 0x6, $zero, %0\n\t"
                 "ibar 0"
                 :
                 : "r"(vaddr)
                 : "memory");
}

void arch_flush_tlb_all() {
    asm volatile("dbar 0\n\t"
                 "invtlb 0x0, $zero, $zero\n\t"
                 "ibar 0" ::
                     : "memory");
}

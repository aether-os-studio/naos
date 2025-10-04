#include "arch.h"
#include <drivers/kernel_logger.h>
#include <drivers/fb.h>
#include <libs/klibc.h>
#include <mm/mm.h>
#include <task/task.h>

// SV48模式下的SATP寄存器位字段定义
#define SATP_MODE_SHIFT 60
#define SATP_ASID_SHIFT 44
#define SATP_PPN_MASK 0x00000FFFFFFFFFFFULL  // 44位PPN
#define SATP_ASID_MASK 0x0FFFF00000000000ULL // 16位ASID
#define SATP_MODE_MASK 0xF000000000000000ULL // 4位MODE

// 页表模式
#define SATP_MODE_BARE 0
#define SATP_MODE_SV39 8
#define SATP_MODE_SV48 9
#define SATP_MODE_SV57 10

// SV48虚拟地址空间划分（48位地址空间）
#define SV48_VA_BITS 48
#define SV48_USER_END 0x0000800000000000ULL     // 用户空间结束地址
#define SV48_KERNEL_START 0xFFFF800000000000ULL // 内核空间起始地址（符号扩展）

// 读取SATP寄存器
static inline uint64_t read_satp(void) {
    uint64_t satp;
    __asm__ volatile("csrr %0, satp" : "=r"(satp) : : "memory");
    return satp;
}

// 写入SATP寄存器
static inline void write_satp(uint64_t satp) {
    __asm__ volatile("csrw satp, %0" : : "r"(satp) : "memory");

    // 刷新TLB以确保新的页表生效
    __asm__ volatile("sfence.vma" : : : "memory");
}

uint64_t *get_current_page_dir(bool user) {
    (void)user;
    uint64_t satp = read_satp();
    uint64_t root_ppn = satp & SATP_PPN_MASK;

    uint64_t page_table_base = root_ppn << 12;

    return (uint64_t *)phys_to_virt(page_table_base);
}

uint64_t get_arch_page_table_flags(uint64_t flags) {
    uint64_t result = ARCH_PT_FLAG_VALID;

    if ((flags & PT_FLAG_R) != 0) {
        result |= ARCH_PT_FLAG_READ;
    }

    if ((flags & PT_FLAG_W) != 0) {
        result |= ARCH_PT_FLAG_WRITE;
    }

    if ((flags & PT_FLAG_U) != 0) {
        result |= ARCH_PT_FLAG_USER;
    }

    if ((flags & PT_FLAG_X) != 0) {
        result |= ARCH_PT_FLAG_EXEC;
    }

    return result;
}

void arch_flush_tlb(uint64_t vaddr) {
    __asm__ volatile("sfence.vma %0, zero" : : "r"(vaddr) : "memory");
}

// RISC-V 页表相关常量定义
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
#define PTE_PPN_SHIFT 10
#define PTE_FLAGS_MASK 0x3FF

// Sv48 虚拟地址布局 (48位)
#define PGDIR_SHIFT 39 // PGD level
#define PUD_SHIFT 30   // PUD level
#define PMD_SHIFT 21   // PMD level
#define PTE_SHIFT 12   // PTE level

#define PTRS_PER_PGD 512
#define PTRS_PER_PUD 512
#define PTRS_PER_PMD 512
#define PTRS_PER_PTE 512

// 虚拟地址索引提取宏 (Sv48)
#define PGD_INDEX(addr) (((addr) >> PGDIR_SHIFT) & 0x1FF)
#define PUD_INDEX(addr) (((addr) >> PUD_SHIFT) & 0x1FF)
#define PMD_INDEX(addr) (((addr) >> PMD_SHIFT) & 0x1FF)
#define PTE_INDEX(addr) (((addr) >> PTE_SHIFT) & 0x1FF)

// 虚拟地址掩码 (48位)
#define VA_MASK 0xFFFFFFFFFFFFUL

// 页表项类型定义
typedef uint64_t pte_t;
typedef uint64_t pmd_t;
typedef uint64_t pud_t;
typedef uint64_t pgd_t;

// 辅助函数：从页表项获取物理页帧号
static inline uint64_t pte_to_pfn(pte_t pte) {
    return (pte >> PTE_PPN_SHIFT) & 0xFFFFFFFFFFUL;
}

// 辅助函数：从物理页帧号创建页表项
static inline pte_t pfn_to_pte(uint64_t pfn, uint64_t flags) {
    return (pfn << PTE_PPN_SHIFT) | (flags & PTE_FLAGS_MASK);
}

// 辅助函数：检查页表项是否有效
static inline bool pte_present(pte_t pte) { return pte & ARCH_PT_FLAG_VALID; }

// 辅助函数：检查页表项是否为叶子节点
static inline bool pte_is_leaf(pte_t pte) { return ARCH_PT_IS_LARGE(pte); }

// 辅助函数：将虚拟地址转换为规范形式 (符号扩展到64位)
static inline uint64_t canonicalize_va(uint64_t vaddr) {
    // Sv48使用48位地址，需要进行符号扩展
    if (vaddr & (1UL << 47)) {
        return vaddr | (~VA_MASK); // 符号扩展高位
    }
    return vaddr & VA_MASK;
}

uint64_t map_page(uint64_t *pgdir, uint64_t vaddr, uint64_t paddr,
                  uint64_t flags, bool force) {
    // 规范化虚拟地址并确保地址按页对齐
    vaddr = canonicalize_va(vaddr) & ~(PAGE_SIZE - 1);
    paddr &= ~(PAGE_SIZE - 1);

    // 确保Valid位被设置
    flags |= ARCH_PT_FLAG_VALID;

    // 获取各级页表索引
    uint64_t pgd_idx = PGD_INDEX(vaddr);
    uint64_t pud_idx = PUD_INDEX(vaddr);
    uint64_t pmd_idx = PMD_INDEX(vaddr);
    uint64_t pte_idx = PTE_INDEX(vaddr);

    pgd_t *pgd_entry = phys_to_virt(&pgdir[pgd_idx]);
    pud_t *pud_table;

    if (!pte_present(*pgd_entry)) {
        // 分配新的PUD页表
        pud_table = (pud_t *)alloc_frames(1);
        if (!pud_table) {
            return 0; // 内存分配失败
        }

        // 清零新分配的页表
        for (int i = 0; i < PTRS_PER_PUD; i++) {
            phys_to_virt(pud_table)[i] = 0;
        }

        // 设置PGD项指向新的PUD表
        uint64_t pud_pfn = ((uint64_t)pud_table) >> PAGE_SHIFT;
        *pgd_entry = pfn_to_pte(pud_pfn, ARCH_PT_FLAG_VALID);
    } else {
        // 获取现有PUD表地址
        uint64_t pud_pfn = pte_to_pfn(*pgd_entry);
        pud_table = (pud_t *)(pud_pfn << PAGE_SHIFT);
    }

    pud_t *pud_entry = phys_to_virt(&pud_table[pud_idx]);
    pmd_t *pmd_table;

    if (!pte_present(*pud_entry)) {
        // 分配新的PMD页表
        pmd_table = (pmd_t *)alloc_frames(1);
        if (!pmd_table) {
            return 0; // 内存分配失败
        }

        // 清零新分配的页表
        for (int i = 0; i < PTRS_PER_PMD; i++) {
            phys_to_virt(pmd_table)[i] = 0;
        }

        // 设置PUD项指向新的PMD表
        uint64_t pmd_pfn = ((uint64_t)pmd_table) >> PAGE_SHIFT;
        *pud_entry = pfn_to_pte(pmd_pfn, ARCH_PT_FLAG_VALID);
    } else {
        // 检查是否为1GB大页映射
        if (pte_is_leaf(*pud_entry)) {
            return 0; // 已存在1GB大页映射，冲突
        }

        // 获取现有PMD表地址
        uint64_t pmd_pfn = pte_to_pfn(*pud_entry);
        pmd_table = (pmd_t *)(pmd_pfn << PAGE_SHIFT);
    }

    pmd_t *pmd_entry = phys_to_virt(&pmd_table[pmd_idx]);
    pte_t *pte_table;

    if (!pte_present(*pmd_entry)) {
        // 分配新的PTE页表
        pte_table = (pte_t *)alloc_frames(1);
        if (!pte_table) {
            return 0; // 内存分配失败
        }

        // 清零新分配的页表
        for (int i = 0; i < PTRS_PER_PTE; i++) {
            phys_to_virt(pte_table)[i] = 0;
        }

        // 设置PMD项指向新的PTE表
        uint64_t pte_pfn = ((uint64_t)pte_table) >> PAGE_SHIFT;
        *pmd_entry = pfn_to_pte(pte_pfn, ARCH_PT_FLAG_VALID);
    } else {
        // 检查是否为2MB大页映射
        if (pte_is_leaf(*pmd_entry)) {
            return 0; // 已存在2MB大页映射，冲突
        }

        // 获取现有PTE表地址
        uint64_t pte_pfn = pte_to_pfn(*pmd_entry);
        pte_table = (pte_t *)(pte_pfn << PAGE_SHIFT);
    }

    pte_t *pte_entry = phys_to_virt(&pte_table[pte_idx]);

    if (pte_present(*pte_entry) && !force) {
        return 0; // 页面已被映射
    }

    // 创建页表项映射
    uint64_t pfn = paddr >> PAGE_SHIFT;
    *pte_entry = pfn_to_pte(pfn, flags);

    arch_flush_tlb(vaddr);

    return 0;
}

uint64_t map_change_attribute(uint64_t *pgdir, uint64_t vaddr, uint64_t flags) {

    // 规范化虚拟地址并确保地址按页对齐
    vaddr = canonicalize_va(vaddr) & ~(PAGE_SIZE - 1);

    // 确保Valid位被设置
    flags |= ARCH_PT_FLAG_VALID;

    // 获取各级页表索引
    uint64_t pgd_idx = PGD_INDEX(vaddr);
    uint64_t pud_idx = PUD_INDEX(vaddr);
    uint64_t pmd_idx = PMD_INDEX(vaddr);
    uint64_t pte_idx = PTE_INDEX(vaddr);

    pgd_t *pgd_entry = phys_to_virt(&pgdir[pgd_idx]);
    pud_t *pud_table;

    if (!pte_present(*pgd_entry)) {
        return 0;
    } else {
        // 获取现有PUD表地址
        uint64_t pud_pfn = pte_to_pfn(*pgd_entry);
        pud_table = (pud_t *)(pud_pfn << PAGE_SHIFT);
    }

    pud_t *pud_entry = phys_to_virt(&pud_table[pud_idx]);
    pmd_t *pmd_table;

    if (!pte_present(*pud_entry)) {
        return 0;
    } else {
        // 检查是否为1GB大页映射
        if (pte_is_leaf(*pud_entry)) {
            return 0; // 已存在1GB大页映射，冲突
        }

        // 获取现有PMD表地址
        uint64_t pmd_pfn = pte_to_pfn(*pud_entry);
        pmd_table = (pmd_t *)(pmd_pfn << PAGE_SHIFT);
    }

    pmd_t *pmd_entry = phys_to_virt(&pmd_table[pmd_idx]);
    pte_t *pte_table;

    if (!pte_present(*pmd_entry)) {
        return 0;
    } else {
        // 检查是否为2MB大页映射
        if (pte_is_leaf(*pmd_entry)) {
            return 0; // 已存在2MB大页映射，冲突
        }

        // 获取现有PTE表地址
        uint64_t pte_pfn = pte_to_pfn(*pmd_entry);
        pte_table = (pte_t *)(pte_pfn << PAGE_SHIFT);
    }

    pte_t *pte_entry = phys_to_virt(&pte_table[pte_idx]);

    // 创建页表项映射
    uint64_t pfn = pte_to_pfn(*pte_entry);
    *pte_entry = pfn_to_pte(pfn, flags);

    arch_flush_tlb(vaddr);

    return 0;
}

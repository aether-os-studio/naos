#pragma once

#define ARCH_MAX_PT_LEVEL 4

#define ARCH_PT_OFFSET_BASE 12
#define ARCH_PT_OFFSET_PER_LEVEL 9

#include <mm/page_table.h>

#define ARCH_PT_FLAG_VALID (0x1UL << 0)
#define ARCH_PT_FLAG_READ (0x1UL << 1)
#define ARCH_PT_FLAG_WRITE (0x1UL << 2)
#define ARCH_PT_FLAG_EXEC (0x1UL << 3)
#define ARCH_PT_FLAG_USER (0x1UL << 4)
#define ARCH_PT_FLAG_ACCESSED (0x1UL << 6)
#define ARCH_PT_FLAG_DIRTY (0x1UL << 7)
#define ARCH_PT_FLAG_PBMT_NC (0x1UL << 62)
#define ARCH_ADDR_MASK ((uint64_t)0x003ffffffffffc00)

#define ARCH_PT_TABLE_FLAGS ARCH_PT_FLAG_VALID

#define ARCH_PT_FLAG_RWX                                                       \
    (ARCH_PT_FLAG_READ | ARCH_PT_FLAG_WRITE | ARCH_PT_FLAG_EXEC)

#define ARCH_PT_IS_TABLE(x)                                                    \
    (((x) & (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_RWX)) == ARCH_PT_FLAG_VALID)
#define ARCH_PT_IS_LARGE(x)                                                    \
    (((x) & (ARCH_PT_FLAG_VALID | ARCH_PT_FLAG_RWX)) > ARCH_PT_FLAG_VALID)

uint64_t get_arch_page_table_flags(uint64_t flags);
void arch_flush_tlb(uint64_t vaddr);

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

// 构建 SATP 值
#define MAKE_SATP(mode, asid, ppn)                                             \
    (((uint64_t)(mode) << SATP_MODE_SHIFT) |                                   \
     ((uint64_t)(asid) << SATP_ASID_SHIFT) |                                   \
     ((uint64_t)(ppn) & SATP_PPN_MASK))

// 从物理地址构建 SATP
#define MAKE_SATP_PADDR(mode, asid, paddr) MAKE_SATP(mode, asid, (paddr) >> 12)

// 读取SATP寄存器
static inline uint64_t read_satp(void) {
    uint64_t satp;
    asm volatile("csrr %0, satp" : "=r"(satp) : : "memory");
    return satp;
}

// 写入SATP寄存器
static inline void write_satp(uint64_t satp) {
    asm volatile("csrw satp, %0" : : "r"(satp) : "memory");

    // 刷新TLB以确保新的页表生效
    asm volatile("sfence.vma" : : : "memory");
}

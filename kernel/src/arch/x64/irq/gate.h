#pragma once

#include <libs/klibc.h>

// 描述符表的结构体
struct desc_struct
{
    unsigned char x[8];
};

// 门的结构体
struct gate_struct
{
    unsigned char x[16];
};

#define IOBITMAP_SIZE (65536 / 8)

typedef struct tss
{
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iomapbaseaddr;
    uint8_t iomap[IOBITMAP_SIZE];
} __attribute__((packed)) tss_t;

#define SELECTOR_KERNEL_CS (0x08)
#define SELECTOR_KERNEL_DS (0x10)
#define SELECTOR_USER_CS (0x20 | 0x3)
#define SELECTOR_USER_DS (0x18 | 0x3)

extern struct desc_struct GDT_Table[]; // GDT_Table是entry.S中的GDT_Table
extern struct gate_struct IDT_Table[]; // IDT_Table是entry.S中的IDT_Table
extern unsigned int TSS64_Table[26];

#define _set_gate(gate_selector_addr, attr, ist, code_addr)                                    \
    do                                                                                         \
    {                                                                                          \
        uint64_t __d0, __d1;                                                                   \
        asm volatile("movw	%%dx,	%%ax	\n\t"                                                    \
                     "andq	$0x7,	%%rcx	\n\t"                                                   \
                     "addq	%4,	%%rcx	\n\t"                                                     \
                     "shlq	$32,	%%rcx	\n\t"                                                    \
                     "addq	%%rcx,	%%rax	\n\t"                                                  \
                     "xorq	%%rcx,	%%rcx	\n\t"                                                  \
                     "movl	%%edx,	%%ecx	\n\t"                                                  \
                     "shrq	$16,	%%rcx	\n\t"                                                    \
                     "shlq	$48,	%%rcx	\n\t"                                                    \
                     "addq	%%rcx,	%%rax	\n\t"                                                  \
                     "movq	%%rax,	%0	\n\t"                                                     \
                     "shrq	$32,	%%rdx	\n\t"                                                    \
                     "movq	%%rdx,	%1	\n\t"                                                     \
                     : "=m"(*((uint64_t *)(gate_selector_addr))),                              \
                       "=m"(*(1 + (uint64_t *)(gate_selector_addr))), "=&a"(__d0), "=&d"(__d1) \
                     : "i"(attr << 8),                                                         \
                       "3"((uint64_t *)(code_addr)), "2"(0x8 << 16), "c"(ist)                  \
                     : "memory");                                                              \
    } while (0)

static inline void set_tss_descriptor(unsigned int n, void *addr)
{
    uint64_t limit = sizeof(tss_t);
    *(uint64_t *)(&GDT_Table[n]) = (limit & 0xffff) | (((uint64_t)addr & 0xffff) << 16) | ((((uint64_t)addr >> 16) & 0xff) << 32) | ((uint64_t)0x89 << 40) | ((limit >> 16 & 0x0f) << 48) | (((uint64_t)addr >> 24 & 0xff) << 56); /////89 is attribute
    *(uint64_t *)(&GDT_Table[n + 1]) = (((uint64_t)addr >> 32) & 0xffffffff) | 0;
}

/**
 * @brief 加载任务状态段寄存器
 * @param n TSS基地址在GDT中的第几项
 * 左移3位的原因是GDT每项占8字节
 */
#define load_TR(n)                                \
    do                                            \
    {                                             \
        asm volatile("ltr %%ax" ::"a"((n) << 3)); \
    } while (0)

/**
 * @brief 设置中断门
 *
 * @param n 中断号
 * @param ist ist
 * @param addr 服务程序的地址
 */
static inline void set_intr_gate(unsigned int n, unsigned char ist, void *addr)
{
    _set_gate((IDT_Table + n), 0x8E, ist, addr); // p=1，DPL=0, type=E
}

/**
 * @brief 设置64位，DPL=0的陷阱门
 *
 * @param n 中断号
 * @param ist ist
 * @param addr 服务程序的地址
 */
static inline void set_trap_gate(unsigned int n, unsigned char ist, void *addr)
{
    _set_gate((IDT_Table + n), 0x8F, ist, addr); // p=1，DPL=0, type=F
}

/**
 * @brief 设置64位，DPL=3的陷阱门
 *
 * @param n 中断号
 * @param ist ist
 * @param addr 服务程序的地址
 */
static inline void set_system_trap_gate(unsigned int n, unsigned char ist, void *addr)
{
    _set_gate((IDT_Table + n), 0xEF, ist, addr); // p=1，DPL=3, type=F
}

/**
 * @brief 初始化TSS表的内容
 *
 */

static inline void set_tss64(uint32_t *Table, uint64_t rsp0, uint64_t rsp1, uint64_t rsp2, uint64_t ist1, uint64_t ist2, uint64_t ist3,
                             uint64_t ist4, uint64_t ist5, uint64_t ist6, uint64_t ist7)
{
    *(uint64_t *)(Table + 1) = rsp0;
    *(uint64_t *)(Table + 3) = rsp1;
    *(uint64_t *)(Table + 5) = rsp2;

    *(uint64_t *)(Table + 9) = ist1;
    *(uint64_t *)(Table + 11) = ist2;
    *(uint64_t *)(Table + 13) = ist3;
    *(uint64_t *)(Table + 15) = ist4;
    *(uint64_t *)(Table + 17) = ist5;
    *(uint64_t *)(Table + 19) = ist6;
    *(uint64_t *)(Table + 21) = ist7;
}

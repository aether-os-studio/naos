#pragma once

#include <libs/klibc.h>

#define close_interrupt asm volatile("cli" ::: "memory")
#define open_interrupt asm volatile("sti" ::: "memory")

static inline void io_out8(uint16_t port, uint8_t data)
{
    asm volatile("outb %b0, %w1" : : "a"(data), "Nd"(port));
}

static inline uint8_t io_in8(uint16_t port)
{
    uint8_t data;
    asm volatile("inb %w1, %b0" : "=a"(data) : "Nd"(port));
    return data;
}

static inline uint16_t io_in16(uint16_t port)
{
    uint16_t data;
    asm volatile("inw %w1, %w0" : "=a"(data) : "Nd"(port));
    return data;
}

static inline void io_out16(uint16_t port, uint16_t data)
{
    asm volatile("outw %w0, %w1" : : "a"(data), "Nd"(port));
}

static inline uint32_t io_in32(uint16_t port)
{
    uint32_t data;
    asm volatile("inl %1, %0" : "=a"(data) : "Nd"(port));
    return data;
}

static inline void io_out32(uint16_t port, uint32_t data)
{
    asm volatile("outl %0, %1" : : "a"(data), "Nd"(port));
}

static inline void flush_tlb(uint64_t addr)
{
    asm volatile("invlpg (%0)" ::"r"(addr) : "memory");
}

static inline uint64_t get_cr0(void)
{
    uint64_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    return cr0;
}

static inline void set_cr0(uint64_t cr0)
{
    asm volatile("mov %0, %%cr0" : : "r"(cr0));
}

static inline uint64_t get_cr3(void)
{
    uint64_t cr0;
    asm volatile("mov %%cr3, %0" : "=r"(cr0));
    return cr0;
}

static inline uint64_t get_rsp(void)
{
    uint64_t rsp;
    asm volatile("mov %%rsp, %0" : "=r"(rsp));
    return rsp;
}

static inline uint64_t get_rflags()
{
    uint64_t rflags;
    asm volatile("pushfq\n"
                     "pop %0\n"
                     : "=r"(rflags)
                     :
                     : "memory");
    return rflags;
}

static inline void insl(uint32_t port, uint32_t *addr, int cnt)
{
    asm volatile("cld\n\t"
                     "repne\n\t"
                     "insl\n\t"
                     : "=D"(addr), "=c"(cnt)
                     : "d"(port), "0"(addr), "1"(cnt)
                     : "memory", "cc");
}

static inline void mmio_write32(uint32_t *addr, uint32_t data)
{
    *(volatile uint32_t *)addr = data;
}

static inline uint32_t mmio_read32(void *addr)
{
    return *(volatile uint32_t *)addr;
}

// static inline uint64_t mmio_read64(void *addr) {
//     return *(volatile uint64_t *)addr;
// }
//
// static inline void mmio_write64(void *addr, uint64_t data) {
//     *(volatile uint64_t *)addr = data;
// }

static inline uint64_t rdmsr(uint32_t msr)
{
    uint32_t eax, edx;
    asm volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(msr));
    return ((uint64_t)edx << 32) | eax;
}

static inline void wrmsr(uint32_t msr, uint64_t value)
{
    uint32_t eax = (uint32_t)value;
    uint32_t edx = value >> 32;
    asm volatile("wrmsr" : : "c"(msr), "a"(eax), "d"(edx));
}

// static uint64_t load(uint64_t *addr)
// {
//     uint64_t ret = 0;
//     asm volatile("lock xadd %[ret], %[addr];"
//                      : [addr] "+m"(*addr), [ret] "+r"(ret)
//                      :
//                      : "memory");
//     return ret;
// }

// static void store(uint64_t *addr, uint32_t value)
// {
//     asm volatile("lock xchg %[value], %[addr];"
//                      : [addr] "+m"(*addr), [value] "+r"(value)
//                      :
//                      : "memory");
// }

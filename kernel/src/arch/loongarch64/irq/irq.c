#include "irq.h"

void arch_enable_interrupt() {
    uint64_t __crmd;
    __asm__ __volatile__("csrrd %0, 0x1\n\t" : "=r"(__crmd));
    __crmd |= 0x4UL;
    __asm__ __volatile__("csrwr %0, 0x1" : : "r"(__crmd));
}

void arch_disable_interrupt() {
    uint64_t __crmd;
    __asm__ __volatile__("csrrd %0, 0x1\n\t" : "=r"(__crmd));
    __crmd &= ~0x4UL;
    __asm__ __volatile__("csrwr %0, 0x1" : : "r"(__crmd));
}

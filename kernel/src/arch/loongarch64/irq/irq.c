#include "irq.h"

void arch_enable_interrupt()
{
    unsigned long tmp;
    asm volatile(
        "csrrd  %0, 0x0\n"      // Read current CRMD value into tmp
        "ori    %0, $zero, 1\n" // Set tmp to 1 (CRMD_IE)
        "csrxchg %0, %0, 0x0"   // Set IE bit (bit 0) in CRMD
        : "=&r"(tmp)::"memory");
}

void arch_disable_interrupt()
{
    unsigned long tmp;
    asm volatile(
        "csrrd  %0, 0x0\n"    // Read current CRMD value into tmp
        "li.w   %0, -0x2\n"   // Create mask ~CRMD_IE (0xFFFFFFFE)
        "csrxchg %0, %0, 0x0" // Clear IE bit (bit 0) in CRMD
        : "=&r"(tmp)::"memory");
}
#include <arch/arch.h>

uint64_t read_fsbase_msr() { return rdmsr(IA32_FS_BASE); }

void write_fsbase_msr(uint64_t value) { wrmsr(IA32_FS_BASE, value); }

uint64_t read_gsbase_msr() { return rdmsr(IA32_GS_BASE); }

void write_gsbase_msr(uint64_t value) { wrmsr(IA32_GS_BASE, value); }

uint64_t (*read_fsbase)() = read_fsbase_msr;
void (*write_fsbase)(uint64_t value) = write_fsbase_msr;
uint64_t (*read_gsbase)() = read_gsbase_msr;
void (*write_gsbase)(uint64_t value) = write_gsbase_msr;

uint64_t rdfsbase() {
    uint64_t ret;
    asm volatile("rdfsbase %0" : "=r"(ret));
    return ret;
}

void wrfsbase(uint64_t value) { asm volatile("wrfsbase %0" ::"r"(value)); }

uint64_t rdgsbase() {
    uint64_t ret;
    asm volatile("rdgsbase %0" : "=r"(ret));
    return ret;
}

void wrgsbase(uint64_t value) { asm volatile("wrgsbase %0" ::"r"(value)); }

uint64_t fsgsbase_init() {
    uint32_t support = has_fsgsbase();
    if (support) {
        uint64_t cr4 = 0;
        asm volatile("movq %%cr4, %0" : "=r"(cr4));
        cr4 |= (1 << 16);
        asm volatile("movq %0, %%cr4" ::"r"(cr4));

        read_fsbase = rdfsbase;
        write_fsbase = wrfsbase;
        read_gsbase = rdgsbase;
        write_gsbase = wrgsbase;
    }

    return 0;
}

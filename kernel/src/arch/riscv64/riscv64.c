#include <arch/arch.h>
#include <boot/boot.h>

#define RISCV_SSTATUS_SUM (1UL << 18)

void fast_copy_16(void *dst, const void *src, size_t size) {
    memcpy(dst, src, size);
}

void arch_early_init() {
    smp_init();
    int bsp_hartid = boot_get_bsp_hartid();
    riscv64_cpu_local_init(get_cpuid_by_hartid(bsp_hartid), bsp_hartid);
    irq_init();
    init_serial();
}

void arch_init() {
    timer_init();
    rtc_goldfish_init();
    timer_init_percpu();
    syscall_handler_init();
}

void arch_init_after_thread() {}

void arch_init_after_acpi_pci() {}

void arch_input_dev_init() {}

typedef struct sbi_ret {
    int64_t error;
    uint64_t value;
} sbi_ret_t;

static sbi_ret_t sbi_ecall(uint64_t eid, uint64_t fid, uint64_t arg0,
                           uint64_t arg1, uint64_t arg2, uint64_t arg3,
                           uint64_t arg4, uint64_t arg5) {
    register uint64_t a0 asm("a0") = arg0;
    register uint64_t a1 asm("a1") = arg1;
    register uint64_t a2 asm("a2") = arg2;
    register uint64_t a3 asm("a3") = arg3;
    register uint64_t a4 asm("a4") = arg4;
    register uint64_t a5 asm("a5") = arg5;
    register uint64_t a6 asm("a6") = fid;
    register uint64_t a7 asm("a7") = eid;

    asm volatile("ecall"
                 : "+r"(a0), "+r"(a1)
                 : "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7)
                 : "memory");

    return (sbi_ret_t){.error = (int64_t)a0, .value = a1};
}

void arch_shutdown() { sbi_ecall(0x53525354, 0x0, 0, 0, 0, 0, 0, 0); }

void arch_pause() { asm volatile("nop" ::: "memory"); }

void arch_wait_for_interrupt() { asm volatile("wfi" ::: "memory"); }

size_t get_cache_line_size() { return 64; }

void dcache_clean_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
    asm volatile("fence rw, rw" ::: "memory");
}

void dcache_invalidate_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
    asm volatile("fence rw, rw" ::: "memory");
}

void dcache_flush_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
    asm volatile("fence rw, rw" ::: "memory");
}

void sync_instruction_memory_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
    asm volatile("fence.i" ::: "memory");
}

void memory_barrier(void) { asm volatile("fence rw, rw" ::: "memory"); }

void read_barrier(void) { asm volatile("fence ir, ir" ::: "memory"); }

void write_barrier(void) { asm volatile("fence ow, ow" ::: "memory"); }

void arch_enable_user_access(void) {
    uint64_t sum = RISCV_SSTATUS_SUM;
    asm volatile("csrs sstatus, %0" : : "r"(sum) : "memory");
}

void arch_disable_user_access(void) {
    uint64_t sum = RISCV_SSTATUS_SUM;
    asm volatile("csrc sstatus, %0" : : "r"(sum) : "memory");
}

bool arch_memory_region_usable(uint64_t addr, uint64_t len) {
    (void)addr;
    (void)len;
    return true;
}

uintptr_t arch_get_return_address(uint32_t level) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
#endif
    switch (level) {
    case 0:
        return (uintptr_t)__builtin_return_address(0);
    case 1:
        return (uintptr_t)__builtin_return_address(1);
    case 2:
        return (uintptr_t)__builtin_return_address(2);
    case 3:
        return (uintptr_t)__builtin_return_address(3);
    case 4:
        return (uintptr_t)__builtin_return_address(4);
    case 5:
        return (uintptr_t)__builtin_return_address(5);
    case 6:
        return (uintptr_t)__builtin_return_address(6);
    case 7:
        return (uintptr_t)__builtin_return_address(7);
    case 8:
        return (uintptr_t)__builtin_return_address(8);
    case 9:
        return (uintptr_t)__builtin_return_address(9);
    default:
        return 0;
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
}

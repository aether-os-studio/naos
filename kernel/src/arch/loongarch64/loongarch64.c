#include "loongarch64.h"
#include <boot/boot.h>
#include <boot/efi.h>
#include <drivers/fdt/syscon_poweroff.h>
#include <mm/hhdm.h>

void fast_copy_16(void *dst, const void *src, size_t size) {
    memcpy(dst, src, size);
}

void arch_early_init() {
    init_serial();
    loongarch64_init_mmu();
    smp_init();
    loongarch64_cpu_local_init(
        get_cpuid_by_physid(csr_read(LOONGARCH_CSR_CPUID)));
}

void arch_init() {
    irq_init();
    timer_init();
    timer_init_percpu();
    syscall_handler_init();
}

void arch_init_after_thread() { syscon_poweroff_init(); }

void arch_init_after_acpi_pci() {}

void arch_input_dev_init() {}

void arch_shutdown() {
    efi_system_table_t *system_table =
        (efi_system_table_t *)(uintptr_t)boot_get_system_table();
    if (!system_table || !system_table->runtime_services) {
        goto fdt_poweroff;
    }

    efi_runtime_services_t *runtime_services =
        (efi_runtime_services_t *)phys_to_virt(
            (uint64_t)(uintptr_t)system_table->runtime_services);
    if (!runtime_services || !runtime_services->reset_system) {
        goto fdt_poweroff;
    }

    efi_reset_system_t reset_system = (efi_reset_system_t)phys_to_virt(
        (uint64_t)(uintptr_t)runtime_services->reset_system);
    if (!reset_system) {
        goto fdt_poweroff;
    }

    reset_system(EFI_RESET_SHUTDOWN, 0, 0, NULL);

fdt_poweroff:
    syscon_poweroff_shutdown();

    while (1)
        arch_wait_for_interrupt();
}

size_t get_cache_line_size() { return 64; }

void dcache_clean_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
}

void dcache_invalidate_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
}

void dcache_flush_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
}

void sync_instruction_memory_range(void *addr, size_t size) {
    (void)addr;
    (void)size;
}

void memory_barrier(void) { __sync_synchronize(); }

void read_barrier(void) { __asm__ volatile("" ::: "memory"); }

void write_barrier(void) { __asm__ volatile("" ::: "memory"); }

void arch_enable_user_access() {}

void arch_disable_user_access() {}

bool arch_memory_region_usable(uint64_t addr, uint64_t len) {
    (void)addr;
    (void)len;
    return true;
}

uintptr_t arch_get_return_address(uint32_t level) {
    if (level != 0)
        return 0;
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
#endif
    return (uintptr_t)__builtin_return_address(0);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
}

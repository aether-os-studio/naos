#include <boot/boot.h>
#include <arch/arch.h>
#include <acpi/uacpi/acpi.h>

extern bool x2apic_mode;

uint32_t cpuid_to_acpiuid[MAX_CPU_NUM];
extern uint32_t cpuid_to_lapicid[MAX_CPU_NUM];
extern uint64_t cpu_count;

void apic_handle_lapic(struct acpi_madt_lapic *lapic) {
    if (lapic->flags & ACPI_PIC_ENABLED) {
        cpuid_to_acpiuid[cpu_count] = lapic->uid;
        cpuid_to_lapicid[cpu_count] = lapic->id;
        cpu_count++;
    }
}

void apic_handle_lx2apic(struct acpi_madt_x2apic *lapic) {
    if (!x2apic_mode)
        return;

    if (lapic->flags & ACPI_PIC_ENABLED) {
        cpuid_to_acpiuid[cpu_count] = lapic->uid;
        cpuid_to_lapicid[cpu_count] = lapic->id;
        cpu_count++;
    }
}

static void lapic_init(void) {
    // 启用 LAPIC
    lapic_write(LAPIC_SVR, lapic_read(LAPIC_SVR) | LAPIC_SVR_ENABLE);

    // 清除错误状态
    lapic_write(LAPIC_ESR, 0);
    lapic_write(LAPIC_ESR, 0);

    // 清除任务优先级
    lapic_write(LAPIC_TPR, 0);
}

static void lapic_send_ipi(uint32_t dest_apic_id, uint32_t flags) {
    if (x2apic_mode) {
        // x2APIC 模式使用单个 64 位 ICR
        uint64_t icr = ((uint64_t)dest_apic_id << 32) | flags;
        wrmsr(0x830, icr); // ICR MSR
    } else {
        // xAPIC 模式使用两个 32 位寄存器
        // 等待上一个 IPI 完成
        while (lapic_read(LAPIC_ICR_LOW) & (1 << 12)) {
            arch_pause();
        }

        // 写入目标 APIC ID
        lapic_write(LAPIC_ICR_HIGH, (uint32_t)dest_apic_id << 24);

        // 写入命令（触发发送）
        lapic_write(LAPIC_ICR_LOW, flags);

        // 等待发送完成
        while (lapic_read(LAPIC_ICR_LOW) & (1 << 12)) {
            arch_pause();
        }
    }
}

static void delay(uint64_t ns) {
    uint64_t start = nano_time();
    while (nano_time() - start < ns) {
        arch_pause();
    }
}

#define AP_STARTUP_ADDR 0x8000ULL

extern uint64_t _apu_boot_start, _apu_boot_end;

extern spinlock_t ap_startup_lock;

void multiboot2_smp_init(uintptr_t entry) {
    uint64_t stack_base = (uint64_t)alloc_frames_bytes(cpu_count * STACK_SIZE);

    uint8_t *ap_code = (uint8_t *)phys_to_virt(AP_STARTUP_ADDR);
    size_t ap_code_size = (uint64_t)&_apu_boot_end - (uint64_t)&_apu_boot_start;

    for (size_t i = 0; i < ap_code_size; i++) {
        ap_code[i] = ((uint8_t *)&_apu_boot_start)[i];
    }

    // 启动每个 AP
    int ap_index = 0;
    for (int i = 0; i < cpu_count; i++) {
        if (cpuid_to_lapicid[i] == lapic_id()) {
            continue; // 跳过 BSP
        }

        spin_lock(&ap_startup_lock);

        uint8_t apic_id = cpuid_to_lapicid[i];

        // 为每个 AP 设置不同的栈
        uint64_t stack_buttom =
            stack_base + ap_index * STACK_SIZE; // 64KB per CPU
        uint64_t stack_top = stack_buttom + STACK_SIZE;

        // 发送 INIT IPI
        lapic_send_ipi(apic_id, ICR_DELIVERY_INIT | ICR_DEST_PHYSICAL |
                                    ICR_LEVEL_ASSERT | ICR_DEST_NOSHORTHAND);

        delay(10ULL * 1000000ULL); // 等待 10ms

        // 发送 INIT de-assert (某些系统需要)
        lapic_send_ipi(apic_id, ICR_DELIVERY_INIT | ICR_DEST_PHYSICAL |
                                    ICR_LEVEL_DEASSERT | ICR_DEST_NOSHORTHAND);

        delay(10ULL * 1000000ULL); // 等待 10ms

        // 发送第一个 SIPI
        uint8_t vector = AP_STARTUP_ADDR >> 12; // 启动向量 = 地址 / 4096
        lapic_send_ipi(apic_id, ICR_DELIVERY_STARTUP | ICR_DEST_PHYSICAL |
                                    ICR_DEST_NOSHORTHAND | vector);

        delay(200ULL * 1000ULL); // 等待 10ms

        // 发送第二个 SIPI
        lapic_send_ipi(apic_id, ICR_DELIVERY_STARTUP | ICR_DEST_PHYSICAL |
                                    ICR_DEST_NOSHORTHAND | vector);

        delay(200ULL * 1000ULL); // 等待 10ms

        ap_index++;
    }
}

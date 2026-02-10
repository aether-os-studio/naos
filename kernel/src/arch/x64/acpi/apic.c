#include <drivers/kernel_logger.h>
#include <boot/boot.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <task/task.h>
#include <uacpi/acpi.h>
#include <uacpi/tables.h>

bool x2apic_mode = false;
uint64_t lapic_address;

tss_t tss[MAX_CPU_NUM];

void tss_init() {
    uint64_t sp =
        phys_to_virt(alloc_frames(STACK_SIZE / DEFAULT_PAGE_SIZE)) + STACK_SIZE;
    uint64_t offset = 10 + current_cpu_id * 2;
    set_tss64(&tss[current_cpu_id], 0, 0, 0, sp, 0, 0, 0, 0, 0, 0);
    set_tss_descriptor(offset, &tss[current_cpu_id]);
    load_TR(offset);
}

void disable_pic() {
    io_out8(0x21, 0xff);
    io_out8(0xa1, 0xff);

    io_out8(0x20, 0x20);
    io_out8(0xa0, 0x20);

    printk("8259A Masked\n");

    io_out8(0x22, 0x70);
    io_out8(0x23, 0x01);
}

void lapic_write(uint32_t reg, uint32_t value) {
    if (x2apic_mode) {
        wrmsr(0x800 + (reg >> 4), value);
        return;
    }
    *(volatile uint32_t *)((uint64_t)lapic_address + reg) = value;
}

uint32_t lapic_read(uint32_t reg) {
    if (x2apic_mode) {
        return rdmsr(0x800 + (reg >> 4));
    }
    return *(volatile uint32_t *)((uint64_t)lapic_address + reg);
}

uint64_t lapic_id() {
    uint32_t phy_id = lapic_read(LAPIC_ID);
    return x2apic_mode ? phy_id : (phy_id >> 24);
}

uint64_t calibrated_timer_initial = 0;

void lapic_timer_stop();

void local_apic_init() {
    x2apic_mode = boot_cpu_support_x2apic();

    uint64_t value = rdmsr(0x1b);
    value |= (1UL << 11);
    if (x2apic_mode)
        value |= (1UL << 10);
    wrmsr(0x1b, value);

    lapic_timer_stop();

    lapic_write(LAPIC_SVR, 0xff | (1 << 8));
    lapic_write(LAPIC_TIMER_DIV, 11);
    lapic_write(LAPIC_TIMER, APIC_TIMER_INTERRUPT_VECTOR);

    uint64_t b = nano_time();
    lapic_write(LAPIC_TIMER_INIT, ~((uint32_t)0));
    for (;;)
        if (nano_time() - b >= 100000000 / SCHED_HZ)
            break;
    uint64_t lapic_timer = (~(uint32_t)0) - lapic_read(LAPIC_TIMER_CURRENT);
    calibrated_timer_initial = (uint64_t)((uint64_t)(lapic_timer * 1000) / 250);
    lapic_write(LAPIC_TIMER, lapic_read(LAPIC_TIMER) | (1 << 17));
    lapic_write(LAPIC_TIMER_INIT, calibrated_timer_initial);
}

#define MAX_IOAPICS_NUM 64

typedef struct ioapic {
    uint8_t id;
    uint64_t mmio_base;
    uint32_t gsi_start;
    uint8_t count;
} ioapic_t;

ioapic_t ioapics[MAX_IOAPICS_NUM];
uint64_t ioapic_count = 0;

static void ioapic_write(ioapic_t *ioapic, uint32_t reg, uint32_t value) {
    *(volatile uint32_t *)(ioapic->mmio_base) = reg;
    *(volatile uint32_t *)((uint64_t)ioapic->mmio_base + 0x10) = value;
}

static uint32_t ioapic_read(ioapic_t *ioapic, uint32_t reg) {
    *(volatile uint32_t *)(ioapic->mmio_base) = reg;
    return *(volatile uint32_t *)((uint64_t)ioapic->mmio_base + 0x10);
}

void apic_handle_ioapic(struct acpi_madt_ioapic *ioapic_madt) {
    ioapic_t *ioapic = &ioapics[ioapic_count];
    ioapic_count++;

    uint64_t mmio_phys = ioapic_madt->address;
    uint64_t mmio_virt = phys_to_virt(mmio_phys);
    map_page_range(get_current_page_dir(false), mmio_virt, mmio_phys,
                   DEFAULT_PAGE_SIZE, PT_FLAG_R | PT_FLAG_W);
    ioapic->mmio_base = mmio_virt;

    ioapic->gsi_start = ioapic_madt->gsi_base;
    ioapic->count = (ioapic_read(ioapic, 0x01) & 0x00FF0000) >> 16;

    printk("IOAPIC found: MMIO %#018lx, GSI base %d, IRQs %d\n",
           (void *)ioapic->mmio_base, ioapic->gsi_start, ioapic->count);

    ioapic->id = ioapic_madt->id;
}

typedef struct override {
    uint8_t bus_irq;
    uint32_t gsi;
} override_t;

override_t overrides[ARCH_MAX_IRQ_NUM];
uint64_t overrides_count = 0;

void apic_handle_override(
    struct acpi_madt_interrupt_source_override *override_madt) {
    override_t *override = &overrides[overrides_count];
    overrides_count++;

    override->bus_irq = override_madt->source;
    override->gsi = override_madt->gsi;
}

bool apic_vector_to_gsi(uint8_t vector, uint32_t *out) {
    uint32_t irq = vector - 32;
    override_t *override = NULL;
    for (uint64_t i = 0; i < overrides_count; i++) {
        if (overrides[i].bus_irq == irq) {
            override = &overrides[i];
            break;
        }
    }

    bool found = (override != NULL);
    *out = found ? override->gsi : irq;
    return found;
}

ioapic_t *apic_find_ioapic_by_vector(uint8_t vector) {
    uint32_t gsi;
    bool found_override = apic_vector_to_gsi(vector, &gsi);

    ioapic_t *ioapic = found_override ? NULL : &ioapics[0];
    for (uint64_t i = 0; i < ioapic_count; i++) {
        if (gsi >= ioapics[i].gsi_start &&
            gsi < (ioapics[i].gsi_start + ioapics[i].count)) {
            ioapic = &ioapics[i];
            break;
        }
    }

    return ioapic;
}

void ioapic_add(uint8_t vector, uint32_t irq) {
    ioapic_t *ioapic = apic_find_ioapic_by_vector(vector);
    if (!ioapic) {
        printk("Cannot find ioapic for vector %d\n", vector);
        return;
    }
    uint32_t ioredtbl =
        (uint32_t)(0x10 + (uint32_t)((irq - ioapic->gsi_start) * 2));
    uint64_t redirect = (uint64_t)vector;
    redirect |= lapic_id() << 56;
    ioapic_write(ioapic, ioredtbl, (uint32_t)redirect);
    ioapic_write(ioapic, ioredtbl + 1, (uint32_t)(redirect >> 32));
}

void io_apic_init() {}

void ioapic_enable(uint8_t vector) {
    ioapic_t *ioapic = apic_find_ioapic_by_vector(vector);
    if (!ioapic) {
        printk("Cannot find ioapic for vector %d\n", vector);
        return;
    }

    uint32_t gsi;
    bool found = apic_vector_to_gsi(vector, &gsi);
    uint64_t index = 0x10 + (((found ? (gsi - ioapic->gsi_start) : gsi)) * 2);
    uint64_t value = (uint64_t)ioapic_read(ioapic, index + 1) << 32 |
                     (uint64_t)ioapic_read(ioapic, index);
    value &= (~0x10000UL);
    ioapic_write(ioapic, index, (uint32_t)(value & 0xFFFFFFFF));
    ioapic_write(ioapic, index + 1, (uint32_t)(value >> 32));
}

void ioapic_disable(uint8_t vector) {
    ioapic_t *ioapic = apic_find_ioapic_by_vector(vector);
    if (!ioapic) {
        printk("Cannot find ioapic for vector %d\n", vector);
        return;
    }

    uint32_t gsi;
    bool found = apic_vector_to_gsi(vector, &gsi);
    uint64_t index = 0x10 + (((found ? (gsi - ioapic->gsi_start) : gsi)) * 2);
    uint64_t value = (uint64_t)ioapic_read(ioapic, index + 1) << 32 |
                     (uint64_t)ioapic_read(ioapic, index);
    value |= 0x10000UL;
    ioapic_write(ioapic, index, (uint32_t)(value & 0xFFFFFFFF));
    ioapic_write(ioapic, index + 1, (uint32_t)(value >> 32));
}

void send_eoi(uint32_t irq) {
    // ioapic_t *ioapic = apic_find_ioapic_by_vector(irq);
    // *(uint32_t *)(ioapic->mmio_base + 0x40) = irq;
    lapic_write(0xb0, 0);
}

void lapic_timer_stop() {
    lapic_write(LAPIC_TIMER_INIT, 0);
    lapic_write(LAPIC_TIMER, (1 << 16));
}

extern void apic_handle_lapic(struct acpi_madt_lapic *lapic);
extern void apic_handle_lx2apic(struct acpi_madt_x2apic *lapic);

void apic_init() {
    struct uacpi_table madt_table;
    uacpi_status status = uacpi_table_find_by_signature("APIC", &madt_table);

    if (status == UACPI_STATUS_OK) {
        struct acpi_madt *madt = (struct acpi_madt *)madt_table.ptr;

        lapic_address =
            phys_to_virt((uint64_t)madt->local_interrupt_controller_address);
        map_page_range(get_current_page_dir(false), lapic_address,
                       madt->local_interrupt_controller_address,
                       DEFAULT_PAGE_SIZE, PT_FLAG_R | PT_FLAG_W);

        printk("Setup Local apic: %#018lx\n", lapic_address);

        memset(ioapics, 0, sizeof(ioapics));
        memset(overrides, 0, sizeof(overrides));

        uint64_t current = 0;
        for (;;) {
            if (current + ((uint32_t)sizeof(struct acpi_madt) - 1) >=
                madt->hdr.length) {
                break;
            }
            struct acpi_entry_hdr *header =
                (struct acpi_entry_hdr *)((uint64_t)(&madt->entries) + current);
            if (header->type == ACPI_MADT_ENTRY_TYPE_IOAPIC) {
                struct acpi_madt_ioapic *ioapic =
                    (struct acpi_madt_ioapic *)((uint64_t)(&madt->entries) +
                                                current);
                apic_handle_ioapic(ioapic);
            } else if (header->type ==
                       ACPI_MADT_ENTRY_TYPE_INTERRUPT_SOURCE_OVERRIDE) {
                struct acpi_madt_interrupt_source_override *override =
                    (struct acpi_madt_interrupt_source_override
                         *)((uint64_t)(&madt->entries) + current);
                apic_handle_override(override);
            } else if (header->type == ACPI_MADT_ENTRY_TYPE_LAPIC) {
                struct acpi_madt_lapic *lapic =
                    (struct acpi_madt_lapic *)((uint64_t)(&madt->entries) +
                                               current);
                apic_handle_lapic(lapic);
            } else if (header->type == ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC) {
                struct acpi_madt_x2apic *x2apic =
                    (struct acpi_madt_x2apic *)((uint64_t)(&madt->entries) +
                                                current);
                apic_handle_lx2apic(x2apic);
            }
            current += (uint64_t)header->length;
        }

        disable_pic();
        io_apic_init();
    }
}

void sse_init() {
    asm volatile("movq %cr0, %rax\n\t"
                 "and $0xFFF3, %ax	\n\t" // clear coprocessor emulation
                                              // CR0.EM and CR0.TS
                 "or $0x2, %ax\n\t" // set coprocessor monitoring  CR0.MP
                 "movq %rax, %cr0\n\t"
                 "movq %cr4, %rax\n\t"
                 "or $(3 << 9), %ax\n\t" // set CR4.OSFXSR and CR4.OSXMMEXCPT at
                                         // the same time
                 "movq %rax, %cr4\n\t");
}

spinlock_t ap_startup_lock = SPIN_INIT;

extern bool task_initialized;

uint64_t general_ap_entry() {
    close_interrupt;

    uint64_t cr3 = (uint64_t)virt_to_phys(get_kernel_page_dir());
    asm volatile("movq %0, %%cr3" ::"r"(cr3) : "memory");

    sse_init();

    gdtidt_setup();

    tss_init();

    fsgsbase_init();

    local_apic_init();

    syscall_init();

    spin_unlock(&ap_startup_lock);

    while (!task_initialized) {
        arch_pause();
    }

    arch_set_current(idle_tasks[current_cpu_id]);

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}

#if defined(MULTIBOOT2)
void multiboot2_ap_entry() {
    asm volatile("movq %0, %%cr3" ::"r"(virt_to_phys(get_kernel_page_dir())));
    void *new_stack = alloc_frames_bytes(STACK_SIZE);
    asm volatile("movq %0, %%rsp" ::"r"(new_stack));
    asm volatile("movq %0, %%rbp" ::"r"(new_stack));
    general_ap_entry();
}
#else
void limine_ap_entry(struct limine_mp_info *cpu) { general_ap_entry(); }
#endif

uint64_t cpu_count;

uint32_t cpuid_to_lapicid[MAX_CPU_NUM];

uint32_t get_cpuid_by_lapic_id(uint32_t lapic_id) {
    for (uint32_t cpu_id = 0; cpu_id < cpu_count; cpu_id++) {
        if (cpuid_to_lapicid[cpu_id] == lapic_id) {
            return cpu_id;
        }
    }

    printk("Cannot get cpu id, lapic id = %d\n", lapic_id);

    return 0;
}

void smp_init() {
#if defined(MULTIBOOT2)
    boot_smp_init((uintptr_t)multiboot2_ap_entry);
#else
    boot_smp_init((uintptr_t)limine_ap_entry);
#endif
}

int64_t apic_mask(uint64_t irq, uint64_t flags) {
    if (flags & IRQ_FLAGS_MSIX)
        return 0;

    ioapic_disable((uint8_t)irq);

    return 0;
}

int64_t apic_unmask(uint64_t irq, uint64_t flags) {
    if (flags & IRQ_FLAGS_MSIX)
        return 0;

    ioapic_enable((uint8_t)irq);

    return 0;
}

int64_t apic_install(uint64_t irq, uint64_t arg, uint64_t flags) {
    if (flags & IRQ_FLAGS_MSIX)
        return 0;

    ioapic_add(irq, arg);

    return 0;
}

int64_t apic_ack(uint64_t irq) {
    send_eoi((uint32_t)irq);
    return 0;
}

irq_controller_t apic_controller = {
    .mask = apic_mask,
    .unmask = apic_unmask,
    .install = apic_install,
    .ack = apic_ack,
};

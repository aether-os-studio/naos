#include <drivers/kernel_logger.h>
#include <boot/boot.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <irq/irq_manager.h>
#include <task/task.h>
#include <uacpi/acpi.h>
#include <uacpi/tables.h>
#include <libs/klibc.h>
#include <arch/x64/irq/irq.h>
#include <libs/llist_queue.h>

bool x2apic_mode = false;
uint64_t lapic_address;
extern irq_controller_t apic_controller;

tss_t tss[MAX_CPU_NUM];

#define IA32_TSC_DEADLINE 0x6E0

static bool lapic_use_tsc_deadline;
static uint64_t lapic_tsc_deadline_interval;
static uint32_t lapic_periodic_ticks;
static uint64_t lapic_next_deadline[MAX_CPU_NUM];

void tss_init() {
    uint64_t paddr = alloc_frames(STACK_SIZE / PAGE_SIZE);
    uint64_t sp = phys_to_virt(paddr) + STACK_SIZE;
    uint64_t offset = 10 + current_cpu_id * 2;
    set_tss64(&tss[current_cpu_id], sp, 0, 0, sp, 0, 0, 0, 0, 0, 0);
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

extern uint32_t cpuid_to_lapicid[MAX_CPU_NUM];
spinlock_t ipi_send_lock = SPIN_INIT;

void apic_send_ipi(uint32_t cpu_id, uint64_t irq_num) {
    if (cpu_id >= cpu_count || irq_num >= ARCH_MAX_IRQ_NUM ||
        cpu_id == current_cpu_id) {
        return;
    }

    bool irq_state = arch_interrupt_enabled();

    arch_disable_interrupt();

    spin_lock(&ipi_send_lock);

    uint32_t flags = ICR_DELIVERY_FIXED | ICR_DEST_PHYSICAL |
                     ICR_DEST_NOSHORTHAND | ICR_TRIGGER_LEVEL |
                     ICR_LEVEL_ASSERT | (uint32_t)irq_num;
    uint32_t target_lapic_id = cpuid_to_lapicid[cpu_id];

    if (x2apic_mode) {
        uint64_t icr = ((uint64_t)target_lapic_id << 32) | flags;
        wrmsr(0x800 + (LAPIC_ICR_LOW >> 4), icr);
    } else {
        while (lapic_read(LAPIC_ICR_LOW) & (1 << 12)) {
            arch_pause();
        }

        lapic_write(LAPIC_ICR_HIGH, target_lapic_id << 24);
        lapic_write(LAPIC_ICR_LOW, flags);

        while (lapic_read(LAPIC_ICR_LOW) & (1 << 12)) {
            arch_pause();
        }
    }

    spin_unlock(&ipi_send_lock);

    if (irq_state) {
        arch_enable_interrupt();
    }
}

void local_apic_init() {
    arch_disable_interrupt();

    x2apic_mode = boot_cpu_support_x2apic();

    uint64_t value = rdmsr(0x1b);
    value |= (1UL << 11);
    wrmsr(0x1b, value);

    if (x2apic_mode) {
        value |= (1UL << 10);
        wrmsr(0x1b, value);
    }

    lapic_write(LAPIC_SVR, 0xff | (1 << 8));
    if (tsc_deadline_mode_available()) {
        lapic_use_tsc_deadline = true;
        lapic_tsc_deadline_interval = tsc_cycles_per_sec() / SCHED_HZ;
        if (lapic_tsc_deadline_interval == 0)
            lapic_tsc_deadline_interval = 1;

        lapic_write(LAPIC_TIMER, APIC_TIMER_INTERRUPT_VECTOR | (2U << 17));
        wrmsr(IA32_TSC_DEADLINE, 0);
        apic_timer_rearm();
        return;
    }

    lapic_write(LAPIC_TIMER_DIV, 11);
    lapic_write(LAPIC_TIMER, APIC_TIMER_INTERRUPT_VECTOR);

    uint64_t begin = hpet_nano_time();
    lapic_write(LAPIC_TIMER_INIT, ~((uint32_t)0));
    while (hpet_nano_time() - begin < 1000000000ULL / SCHED_HZ) {
        arch_pause();
    }

    lapic_periodic_ticks = (~(uint32_t)0) - lapic_read(LAPIC_TIMER_CURRENT);
    lapic_write(LAPIC_TIMER_INIT, lapic_periodic_ticks);
    lapic_write(LAPIC_TIMER, lapic_read(LAPIC_TIMER) | (1 << 17));
}

void apic_timer_rearm(void) {
    if (!lapic_use_tsc_deadline)
        return;

    uint32_t cpu_id = current_cpu_id;
    uint64_t now = rdtsc_ordered();
    uint64_t next = lapic_next_deadline[cpu_id];

    if (next <= now) {
        next = now + lapic_tsc_deadline_interval;
    } else {
        next += lapic_tsc_deadline_interval;
    }

    lapic_next_deadline[cpu_id] = next;
    wrmsr(IA32_TSC_DEADLINE, next);
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
    map_page_range(get_current_page_dir(false), mmio_virt, mmio_phys, PAGE_SIZE,
                   PT_FLAG_R | PT_FLAG_W);
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

void send_eoi(uint32_t irq) { lapic_write(0xb0, 0); }

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
                       madt->local_interrupt_controller_address, PAGE_SIZE,
                       PT_FLAG_R | PT_FLAG_W);

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
    uint32_t eax, ebx, ecx, edx;
    uint32_t features_ecx = 0;
    uint64_t cr0 = get_cr0();
    uint64_t cr4 = get_cr4();
    uint64_t xcr0_mask = X64_XSTATE_X87 | X64_XSTATE_SSE;
    uint64_t xsave_area_size = sizeof(fpu_context_t);
    bool xsave_enabled = false;

    cr0 &= ~((1ULL << 2) | (1ULL << 3));
    cr0 |= (1ULL << 1);
    set_cr0(cr0);

    cr4 |= (1ULL << 9) | (1ULL << 10);

    cpuid_count(1, 0, &eax, &ebx, &ecx, &edx);
    features_ecx = ecx;
    if (ecx & (1U << 26)) {
        cr4 |= (1ULL << 18);
        set_cr4(cr4);

        cpuid_count(0xD, 0, &eax, &ebx, &ecx, &edx);
        uint64_t supported_mask = ((uint64_t)edx << 32) | eax;

        xcr0_mask &= supported_mask;
        if ((features_ecx & (1U << 28)) && (supported_mask & X64_XSTATE_AVX))
            xcr0_mask |= X64_XSTATE_AVX;

        xsetbv(0, xcr0_mask);
        cpuid_count(0xD, 0, &eax, &ebx, &ecx, &edx);
        xsave_area_size = ebx ? ebx : sizeof(fpu_context_t);
        xsave_enabled = true;
    } else {
        cr4 &= ~(1ULL << 18);
        set_cr4(cr4);
    }

    x64_fpu_configure_xsave(xsave_enabled, xcr0_mask, xsave_area_size);
}

spinlock_t ap_startup_lock = SPIN_INIT;

extern bool task_initialized;

uint64_t general_ap_entry() {
    arch_disable_interrupt();

    uint64_t cr3 = (uint64_t)virt_to_phys(get_kernel_page_dir());
    asm volatile("movq %0, %%cr3" ::"r"(cr3) : "memory");

    sse_init();

    gdtidt_setup();

    fsgsbase_init();

    tss_init();

    local_apic_init();

    x64_cpu_local_init(get_cpuid_by_lapic_id((uint32_t)lapic_id()),
                       (uint32_t)lapic_id());

    syscall_init();

    spin_unlock(&ap_startup_lock);

    while (!task_initialized) {
        arch_pause();
    }

    arch_set_current(idle_tasks[current_cpu_id]);
    task_mark_on_cpu(idle_tasks[current_cpu_id], true);
    task_mm_mark_cpu_active(idle_tasks[current_cpu_id]->mm, current_cpu_id);

    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}

#if defined(MULTIBOOT2)
void multiboot2_ap_entry() {
    asm volatile("movq %0, %%cr3" ::"r"(virt_to_phys(get_kernel_page_dir())));
    uint8_t *new_stack_base = alloc_frames_bytes(STACK_SIZE);
    uint8_t *new_stack_top = new_stack_base + STACK_SIZE;
    asm volatile("movq %0, %%rsp" ::"r"(new_stack_top));
    asm volatile("movq %0, %%rbp" ::"r"(new_stack_top));
    general_ap_entry();
}
#else
void limine_ap_entry() { general_ap_entry(); }
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

static void apic_resched_ipi_handler(uint64_t irq_num, void *data,
                                     struct pt_regs *regs) {
    (void)irq_num;
    (void)data;
    (void)regs;
}

static void apic_tlb_shootdown_ipi_handler(uint64_t irq_num, void *data,
                                           struct pt_regs *regs) {
    arch_flush_tlb_all();
}

irq_controller_t apic_controller = {
    .mask = apic_mask,
    .unmask = apic_unmask,
    .install = apic_install,
    .ack = apic_ack,
};

void apic_ipi_init() {
    irq_regist_ipi(APIC_RESCHED_IPI_VECTOR, apic_resched_ipi_handler, 0, NULL,
                   &apic_controller, "RESCHED_IPI", IRQ_FLAGS_LAPIC,
                   apic_send_ipi);
    irq_regist_ipi(APIC_TLB_SHOOTDOWN_VECTOR, apic_tlb_shootdown_ipi_handler, 0,
                   NULL, &apic_controller, "TLB_SHOOTDOWN", IRQ_FLAGS_LAPIC,
                   apic_send_ipi);
    irq_set_sched_ipi(APIC_RESCHED_IPI_VECTOR);
}

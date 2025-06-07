#include <drivers/kernel_logger.h>
#include <arch/x64/acpi/acpi.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <interrupt/irq_manager.h>
#include <task/task.h>

bool x2apic_mode;
uint64_t lapic_address;
uint64_t ioapic_address;

tss_t tss[MAX_CPU_NUM];

void tss_init()
{
    uint64_t sp = phys_to_virt(alloc_frames(STACK_SIZE / DEFAULT_PAGE_SIZE)) + STACK_SIZE;
    uint64_t offset = 10 + current_cpu_id * 2;
    set_tss64((uint32_t *)&tss[current_cpu_id], sp, sp, sp, sp, sp, sp, sp, sp, sp, sp);
    set_tss_descriptor(offset, &tss[current_cpu_id]);
    load_TR(offset);
}

__attribute__((used, section(".limine_requests"))) static volatile struct limine_mp_request mp_request = {
    .id = LIMINE_MP_REQUEST,
    .revision = 0,
};

void disable_pic()
{
    io_out8(0x21, 0xff);
    io_out8(0xa1, 0xff);

    io_out8(0x20, 0x20);
    io_out8(0xa0, 0x20);

    printk("8259A Masked\n");

    io_out8(0x22, 0x70);
    io_out8(0x23, 0x01);
}

static void ioapic_write(uint32_t reg, uint32_t value)
{
    *(uint32_t *)(ioapic_address) = reg;
    *(uint32_t *)((uint64_t)ioapic_address + 0x10) = value;
}

static uint32_t ioapic_read(uint32_t reg)
{
    *(uint32_t *)(ioapic_address) = reg;
    return *(uint32_t *)((uint64_t)ioapic_address + 0x10);
}

void ioapic_add(uint8_t vector, uint32_t irq)
{
    uint32_t ioredtbl = (uint32_t)(0x10 + (uint32_t)(irq * 2));
    uint64_t redirect = (uint64_t)vector;
    redirect |= lapic_id() << 56;
    ioapic_write(ioredtbl, (uint32_t)redirect);
    ioapic_write(ioredtbl + 1, (uint32_t)(redirect >> 32));
}

void lapic_write(uint32_t reg, uint32_t value)
{
    if (x2apic_mode)
    {
        wrmsr(0x800 + (reg >> 4), value);
        return;
    }
    *(uint32_t *)((uint64_t)lapic_address + reg) = value;
}

uint32_t lapic_read(uint32_t reg)
{
    if (x2apic_mode)
    {
        return rdmsr(0x800 + (reg >> 4));
    }
    return *(uint32_t *)((uint64_t)lapic_address + reg);
}

uint64_t lapic_id()
{
    uint32_t phy_id = lapic_read(LAPIC_REG_ID);
    return x2apic_mode ? phy_id : (phy_id >> 24);
}

uint64_t calibrated_timer_initial;

void lapic_timer_stop();

void local_apic_init(bool is_print)
{
    x2apic_mode = ((mp_request.flags & LIMINE_MP_X2APIC) != 0);

    uint64_t value = rdmsr(0x1b);
    value |= (1UL << 11);
    if (x2apic_mode)
        value |= (1UL << 10);
    wrmsr(0x1b, value);

    lapic_timer_stop();

    lapic_write(LAPIC_REG_SPURIOUS, 0xff | (1 << 8));
    lapic_write(LAPIC_REG_TIMER_DIV, 11);
    lapic_write(LAPIC_REG_TIMER, APIC_TIMER_INTERRUPT_VECTOR);

    uint64_t b = nanoTime();
    lapic_write(LAPIC_REG_TIMER_INITCNT, ~((uint32_t)0));
    for (;;)
        if (nanoTime() - b >= 10000000)
            break;
    uint64_t lapic_timer = (~(uint32_t)0) - lapic_read(LAPIC_REG_TIMER_CURCNT);
    calibrated_timer_initial = (uint64_t)((uint64_t)(lapic_timer * 1000) / 250);
    if (is_print)
    {
        printk("Calibrated LAPIC timer: %d ticks per second\n", calibrated_timer_initial);
    }
    lapic_write(LAPIC_REG_TIMER, lapic_read(LAPIC_REG_TIMER) | (1 << 17));
    lapic_write(LAPIC_REG_TIMER_INITCNT, calibrated_timer_initial);
    if (is_print)
    {
        printk("Setup local %s\n", x2apic_mode ? "x2APIC" : "xAPIC");
    }
}

void local_apic_ap_init()
{
    uint64_t value = rdmsr(0x1b);
    value |= (1 << 11);
    if (x2apic_mode)
        value |= (1 << 10);
    wrmsr(0x1b, value);

    lapic_timer_stop();

    lapic_write(LAPIC_REG_SPURIOUS, 0xff | (1 << 8));
    lapic_write(LAPIC_REG_TIMER_DIV, 11);
    lapic_write(LAPIC_REG_TIMER, APIC_TIMER_INTERRUPT_VECTOR);

    lapic_write(LAPIC_REG_TIMER, lapic_read(LAPIC_REG_TIMER) | (1 << 17));
    lapic_write(LAPIC_REG_TIMER_INITCNT, calibrated_timer_initial);
}

void io_apic_init()
{
    map_page_range(get_current_page_dir(false), phys_to_virt(ioapic_address), ioapic_address, DEFAULT_PAGE_SIZE, PT_FLAG_R | PT_FLAG_W);
    ioapic_address = (uint64_t)phys_to_virt(ioapic_address);

    printk("Setup I/O apic: %#018lx\n", ioapic_address);
}

void ioapic_enable(uint8_t vector)
{
    uint64_t index = 0x10 + ((vector - 32) * 2);
    uint64_t value = (uint64_t)ioapic_read(index + 1) << 32 | (uint64_t)ioapic_read(index);
    value &= (~0x10000UL);
    ioapic_write(index, (uint32_t)(value & 0xFFFFFFFF));
    ioapic_write(index + 1, (uint32_t)(value >> 32));
}

void ioapic_disable(uint8_t vector)
{
    uint64_t index = 0x10 + ((vector - 32) * 2);
    uint64_t value = (uint64_t)ioapic_read(index + 1) << 32 | (uint64_t)ioapic_read(index);
    value |= 0x10000UL;
    ioapic_write(index, (uint32_t)(value & 0xFFFFFFFF));
    ioapic_write(index + 1, (uint32_t)(value >> 32));
}

void send_eoi(uint32_t irq)
{
    lapic_write(0xb0, 0);
    *(uint32_t *)(ioapic_address + 0x40) = irq;
}

void lapic_timer_stop()
{
    lapic_write(LAPIC_REG_TIMER_INITCNT, 0);
    lapic_write(LAPIC_REG_TIMER, (1 << 16));
}

void apic_setup(MADT *madt)
{
    lapic_address = phys_to_virt((uint64_t)madt->local_apic_address);
    map_page_range(get_current_page_dir(false), lapic_address, madt->local_apic_address, DEFAULT_PAGE_SIZE, PT_FLAG_R | PT_FLAG_W);

    printk("Setup Local apic: %#018lx\n", lapic_address);

    uint64_t current = 0;
    for (;;)
    {
        if (current + ((uint32_t)sizeof(MADT) - 1) >= madt->h.length)
        {
            break;
        }
        Madtheader *header = (Madtheader *)((uint64_t)(&madt->entries) + current);
        if (header->entry_type == MADT_APIC_IO)
        {
            MadtIOApic *ioapic = (MadtIOApic *)((uint64_t)(&madt->entries) + current);
            ioapic_address = ioapic->address;
            break;
        }
        current += (uint64_t)header->length;
    }

    disable_pic();
    local_apic_init(true);
    io_apic_init();
}

void sse_init()
{
    __asm__ __volatile__("movq %cr0, %rax\n\t"
                         "and $0xFFF3, %ax	\n\t" // clear coprocessor emulation CR0.EM and CR0.TS
                         "or $0x2, %ax\n\t"       // set coprocessor monitoring  CR0.MP
                         "movq %rax, %cr0\n\t"
                         "movq %cr4, %rax\n\t"
                         "or $(3 << 9), %ax\n\t" // set CR4.OSFXSR and CR4.OSXMMEXCPT at the same time
                         "movq %rax, %cr4\n\t");
}

extern bool task_initialized;

void ap_entry(struct limine_mp_info *cpu)
{
    close_interrupt;

    uint64_t cr3 = (uint64_t)virt_to_phys(get_current_page_dir(false));
    __asm__ __volatile__("movq %0, %%cr3" ::"r"(cr3) : "memory");

    sse_init();

    gdtidt_setup();

    tss_init();

    fsgsbase_init();

    local_apic_ap_init();

    syscall_init();

    while (!task_initialized)
    {
        arch_pause();
    }

    arch_set_current(idle_tasks[current_cpu_id]);

    while (1)
    {
        arch_enable_interrupt();
        arch_pause();
    }
}

uint64_t cpu_count;

uint32_t cpuid_to_lapicid[MAX_CPU_NUM];

uint32_t get_cpuid_by_lapic_id(uint32_t lapic_id)
{
    for (uint32_t cpu_id = 0; cpu_id < cpu_count; cpu_id++)
    {
        if (cpuid_to_lapicid[cpu_id] == lapic_id)
        {
            return cpu_id;
        }
    }

    printk("Cannot get cpu id, lapic id = %d\n", lapic_id);

    return 0;
}

void apu_startup(struct limine_mp_response *mp_response)
{
    cpu_count = mp_response->cpu_count;

    for (uint64_t i = 0; i < mp_response->cpu_count; i++)
    {
        struct limine_mp_info *cpu = mp_response->cpus[i];
        cpuid_to_lapicid[cpu->processor_id] = cpu->lapic_id;

        if (cpu->lapic_id == mp_response->bsp_lapic_id)
            continue;

        cpu->goto_address = ap_entry;
    }
}

void smp_init()
{
    apu_startup(mp_request.response);
}

int64_t apic_mask(uint64_t irq)
{
    ioapic_disable((uint8_t)irq);

    return 0;
}

int64_t apic_unmask(uint64_t irq)
{
    ioapic_enable((uint8_t)irq);

    return 0;
}

int64_t apic_install(uint64_t irq, uint64_t arg)
{
    ioapic_add(irq, arg);
    return 0;
}

int64_t apic_ack(uint64_t irq)
{
    send_eoi((uint32_t)irq);
    return 0;
}

irq_controller_t apic_controller = {
    .mask = apic_mask,
    .unmask = apic_unmask,
    .install = apic_install,
    .ack = apic_ack,
};

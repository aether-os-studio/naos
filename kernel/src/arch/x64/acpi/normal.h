#pragma once

#include <libs/klibc.h>

void apic_init();

void hpet_init();
uint64_t nanoTime();

#define LAPIC_ID 0x020
#define LAPIC_VERSION 0x030
#define LAPIC_TPR 0x080
#define LAPIC_EOI 0x0B0
#define LAPIC_SVR 0x0F0
#define LAPIC_ESR 0x280
#define LAPIC_ICR_LOW 0x300
#define LAPIC_ICR_HIGH 0x310
#define LAPIC_TIMER 0x320
#define LAPIC_TIMER_INIT 0x380
#define LAPIC_TIMER_CURRENT 0x390
#define LAPIC_TIMER_DIV 0x3E0

// ICR 位定义
#define ICR_DELIVERY_INIT 0x00000500
#define ICR_DELIVERY_STARTUP 0x00000600
#define ICR_DELIVERY_FIXED 0x00000000
#define ICR_DEST_PHYSICAL 0x00000000
#define ICR_LEVEL_ASSERT 0x00004000
#define ICR_LEVEL_DEASSERT 0x00000000
#define ICR_TRIGGER_EDGE 0x00000000
#define ICR_TRIGGER_LEVEL 0x00008000
#define ICR_DEST_NOSHORTHAND 0x00000000
#define ICR_DEST_SELF 0x00040000
#define ICR_DEST_ALL 0x00080000
#define ICR_DEST_ALLBUTSELF 0x000C0000

// SVR 位定义
#define LAPIC_SVR_ENABLE 0x00000100

void send_eoi(uint32_t irq);
uint64_t lapic_id();

void lapic_write(uint32_t reg, uint32_t value);
uint32_t lapic_read(uint32_t reg);

uint32_t get_cpuid_by_lapic_id(uint32_t lapic_id);

void local_apic_init();

void ioapic_enable(uint8_t vector);
void ioapic_disable(uint8_t vector);
void ioapic_add(uint8_t vector, uint32_t irq);

int64_t apic_mask(uint64_t irq, uint64_t flags);
int64_t apic_unmask(uint64_t irq, uint64_t flags);
int64_t apic_install(uint64_t irq, uint64_t arg, uint64_t flags);
int64_t apic_ack(uint64_t irq);

struct irq_controller;
extern struct irq_controller apic_controller;

#define current_cpu_id get_cpuid_by_lapic_id(lapic_id())

extern volatile struct limine_rsdp_request rsdp_request;

void smp_init();
void tss_init();

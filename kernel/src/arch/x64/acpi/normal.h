#pragma once

#include <libs/klibc.h>

void apic_init();

void hpet_init();
uint64_t nanoTime();

#define LAPIC_REG_ID 0x20
#define LAPIC_REG_TIMER_CURCNT 0x390
#define LAPIC_REG_TIMER_INITCNT 0x380
#define LAPIC_REG_TIMER 0x320
#define LAPIC_REG_SPURIOUS 0xf0
#define LAPIC_REG_TIMER_DIV 0x3e0

#define APIC_ICR_LOW 0x300
#define APIC_ICR_HIGH 0x310

void send_eoi(uint32_t irq);
uint64_t lapic_id();

void lapic_write(uint32_t reg, uint32_t value);
uint32_t lapic_read(uint32_t reg);

uint32_t get_cpuid_by_lapic_id(uint32_t lapic_id);

void ioapic_enable(uint8_t vector);
void ioapic_add(uint8_t vector, uint32_t irq);

int64_t apic_mask(uint64_t irq);
int64_t apic_unmask(uint64_t irq);
int64_t apic_install(uint64_t irq, uint64_t arg);
int64_t apic_ack(uint64_t irq);

struct irq_controller;
extern struct irq_controller apic_controller;

#define current_cpu_id get_cpuid_by_lapic_id(lapic_id())

extern volatile struct limine_rsdp_request rsdp_request;

void smp_init();
void tss_init();

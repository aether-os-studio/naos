#pragma once

#include <libs/klibc.h>

struct pt_regs;

typedef struct irq_controller {
    int64_t (*unmask)(uint64_t irq, uint64_t flags);
    int64_t (*mask)(uint64_t irq, uint64_t flags);
    int64_t (*install)(uint64_t irq, uint64_t arg, uint64_t flags);
    int64_t (*ack)(uint64_t irq);
} irq_controller_t;

typedef struct irq_action {
    char *name;
    void *data;
    irq_controller_t *irq_controller;
    void (*handler)(uint64_t irq_num, void *data, struct pt_regs *regs);
    uint64_t flags;
    bool used;
} irq_action_t;

#define IRQ_FLAGS_MSIX (1UL << 0)
#if defined(__x86_64__)
#define IRQ_FLAGS_LAPIC IRQ_FLAGS_MSIX
#endif

void irq_regist_irq(uint64_t irq_num,
                    void (*handler)(uint64_t irq_num, void *data,
                                    struct pt_regs *regs),
                    uint64_t arg, void *data, irq_controller_t *controller,
                    char *name, uint64_t flags);

void irq_manager_init();

int irq_allocate_irqnum();
void irq_deallocate_irqnum(int irq_num);

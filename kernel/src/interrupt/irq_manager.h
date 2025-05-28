#pragma once

#include <libs/klibc.h>

struct pt_regs;

typedef struct irq_controller
{
    err_t (*unmask)(uint64_t irq);
    err_t (*mask)(uint64_t irq);
    err_t (*install)(uint64_t irq, uint64_t arg);
    err_t (*ack)(uint64_t irq);
} irq_controller_t;

typedef struct irq_action
{
    char *name;
    void *data;
    irq_controller_t *irq_controller;
    void (*handler)(uint64_t irq_num, void *data, struct pt_regs *regs);
} irq_action_t;

void irq_regist_irq(uint64_t irq_num, void (*handler)(uint64_t irq_num, void *data, struct pt_regs *regs), uint64_t arg, void *data, irq_controller_t *controller, char *name);

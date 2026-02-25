#include <irq/irq_manager.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>
#include <task/task.h>
#include <mm/bitmap.h>

irq_action_t actions[ARCH_MAX_IRQ_NUM] = {0};

extern bool can_schedule;

void do_irq(struct pt_regs *regs, uint64_t irq_num) {
    irq_action_t *action = &actions[irq_num];

    if (action->irq_controller && action->irq_controller->ack) {
        action->irq_controller->ack(irq_num);
    } else {
        printk("Intr vector [%d] does not have an ack\n", irq_num);
    }

    if (action->handler) {
        action->handler(irq_num, action->data, regs);
    } else {
        printk("Intr vector [%d] does not have a handler\n", irq_num);
    }

    task_t *self = current_task;

    if ((irq_num == ARCH_TIMER_IRQ) && can_schedule && self) {
        if (self->cpu_id == 0) {
            sched_check_wakeup();
        }

        schedule(0);
    }
}

void irq_regist_irq(uint64_t irq_num,
                    void (*handler)(uint64_t irq_num, void *data,
                                    struct pt_regs *regs),
                    uint64_t arg, void *data, irq_controller_t *controller,
                    char *name, uint64_t flags) {
    irq_action_t *action = &actions[irq_num];
    memset(action, 0, sizeof(irq_action_t));

    action->handler = handler;
    action->data = data;
    action->irq_controller = controller;
    action->name = name;

    if (action->irq_controller && action->irq_controller->install) {
        action->irq_controller->install(irq_num, arg, flags);
    }

    if (action->irq_controller && action->irq_controller->unmask) {
        action->irq_controller->unmask(irq_num, flags);
    }

    action->flags = flags;

    action->used = true;
}

uint64_t irq = IRQ_ALLOCATE_NUM_BASE;
spinlock_t irq_lock = SPIN_INIT;

void irq_manager_init() {}

int irq_allocate_irqnum() {
    spin_lock(&irq_lock);
    uint64_t idx = irq++;
    spin_unlock(&irq_lock);
    return idx;
}

void irq_deallocate_irqnum(int irq_num) {}

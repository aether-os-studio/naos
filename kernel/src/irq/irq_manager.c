#include <irq/irq_manager.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>
#include <task/task.h>
#include <mm/bitmap.h>
#include <irq/softirq.h>

irq_action_t actions[ARCH_MAX_IRQ_NUM] = {0};
irq_ipi_send_fn_t ipi_send_fns[ARCH_MAX_IRQ_NUM] = {0};
uint64_t sched_ipi_irq = ARCH_MAX_IRQ_NUM;

extern bool can_schedule;

void do_irq(struct pt_regs *regs, uint64_t irq_num) {
    if (irq_num >= ARCH_MAX_IRQ_NUM) {
        printk("Invalid IRQ vector %lu\n", irq_num);
        return;
    }

    irq_action_t *action = &actions[irq_num];

    if (action->handler) {
        action->handler(irq_num, action->data, regs);
    } else {
        printk("Intr vector [%d] does not have a handler\n", irq_num);
    }

    if (action->irq_controller && action->irq_controller->ack) {
        action->irq_controller->ack(irq_num);
    } else {
        printk("Intr vector [%d] does not have an ack\n", irq_num);
    }

    task_t *self = current_task;

    if (irq_num == ARCH_TIMER_IRQ && self->cpu_id == 0) {
        sched_check_wakeup();
    }

    softirq_handle_pending();

    uint64_t current_sched_ipi =
        __atomic_load_n(&sched_ipi_irq, __ATOMIC_ACQUIRE);
    if ((irq_num == ARCH_TIMER_IRQ || irq_num == current_sched_ipi) &&
        can_schedule && self) {
        schedule(0);
    }
}

void irq_regist_irq(uint64_t irq_num,
                    void (*handler)(uint64_t irq_num, void *data,
                                    struct pt_regs *regs),
                    uint64_t arg, void *data, irq_controller_t *controller,
                    char *name, uint64_t flags) {
    if (irq_num >= ARCH_MAX_IRQ_NUM) {
        printk("irq_regist_irq: invalid irq_num %lu\n", irq_num);
        return;
    }

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

void irq_regist_ipi(uint64_t irq_num,
                    void (*handler)(uint64_t irq_num, void *data,
                                    struct pt_regs *regs),
                    uint64_t arg, void *data, irq_controller_t *controller,
                    char *name, uint64_t flags, irq_ipi_send_fn_t send_fn) {
    irq_regist_irq(irq_num, handler, arg, data, controller, name, flags);
    if (irq_num >= ARCH_MAX_IRQ_NUM)
        return;

    __atomic_store_n(&ipi_send_fns[irq_num], send_fn, __ATOMIC_RELEASE);
}

bool irq_send_ipi(uint32_t cpu_id, uint64_t irq_num) {
    if (irq_num >= ARCH_MAX_IRQ_NUM || cpu_id >= cpu_count)
        return false;

    irq_ipi_send_fn_t send_fn =
        __atomic_load_n(&ipi_send_fns[irq_num], __ATOMIC_ACQUIRE);
    if (!send_fn)
        return false;

    send_fn(cpu_id, irq_num);
    return true;
}

void irq_set_sched_ipi(uint64_t irq_num) {
    if (irq_num >= ARCH_MAX_IRQ_NUM) {
        printk("irq_set_sched_ipi: invalid irq_num %lu\n", irq_num);
        return;
    }

    __atomic_store_n(&sched_ipi_irq, irq_num, __ATOMIC_RELEASE);
}

bool irq_trigger_sched_ipi(uint32_t cpu_id) {
    uint64_t irq_num = __atomic_load_n(&sched_ipi_irq, __ATOMIC_ACQUIRE);
    if (irq_num >= ARCH_MAX_IRQ_NUM)
        return false;

    return irq_send_ipi(cpu_id, irq_num);
}

uint64_t irq = IRQ_ALLOCATE_NUM_BASE;
spinlock_t irq_lock = SPIN_INIT;

void irq_manager_init() { softirq_init(); }

int irq_allocate_irqnum() {
    spin_lock(&irq_lock);
    uint64_t idx = irq++;
    spin_unlock(&irq_lock);
    return idx;
}

void irq_deallocate_irqnum(int irq_num) {}

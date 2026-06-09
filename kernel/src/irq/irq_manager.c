#include <irq/irq_manager.h>
#include <drivers/logger.h>
#include <arch/arch.h>
#include <task/task.h>
#include <task/sched.h>
#include <mm/bitmap.h>
#include <irq/softirq.h>
#include <init/callbacks.h>
#include <drivers/deadline.h>
#include <task/watchdog.h>

irq_action_t actions[ARCH_MAX_IRQ_NUM] = {0};
irq_ipi_send_fn_t ipi_send_fns[ARCH_MAX_IRQ_NUM] = {0};
uint64_t sched_ipi_irq = ARCH_MAX_IRQ_NUM;
static uint64_t irq_counts[MAX_CPU_NUM][ARCH_MAX_IRQ_NUM] = {0};

extern bool system_initialized;
extern bool can_schedule;
extern sched_rq_t schedulers[MAX_CPU_NUM];

static inline bool irq_is_sched_ipi(uint64_t irq_num) {
    uint64_t sched_irq = __atomic_load_n(&sched_ipi_irq, __ATOMIC_ACQUIRE);
    return irq_num == sched_irq && sched_irq < ARCH_MAX_IRQ_NUM;
}

void do_irq(struct pt_regs *regs, uint64_t irq_num) {
    arch_disable_interrupt();

    if (irq_num >= ARCH_MAX_IRQ_NUM) {
        printk("Invalid IRQ vector %lu\n", irq_num);
        return;
    }

    uint64_t cpu_id = current_cpu_id;
    uint64_t stat_cpu = cpu_id < MAX_CPU_NUM ? cpu_id : 0;
    __atomic_fetch_add(&irq_counts[stat_cpu][irq_num], 1, __ATOMIC_RELAXED);

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
    if (self) {
        task_membarrier_checkpoint(self);
    }

    uint64_t now_ns = nano_time();

    if (irq_num == ARCH_TIMER_IRQ && self) {
        sched_check_wakeup();
        if (cpu_id == 0) {
            on_sched_update_call();
        }
    }

    if (irq_is_sched_ipi(irq_num)) {
        deadline_reprogram_local();
        sched_check_wakeup();
    }

    if (can_schedule) {
        if (self &&
            sched_should_preempt(&schedulers[self->cpu_id], self, now_ns))
            sched_request_resched(self);

        sched_resched_if_needed();
    }

    if (irq_num == ARCH_TIMER_IRQ || irq_is_sched_ipi(irq_num)) {
        sched_refresh_preempt_deadline(cpu_id, self, nano_time());
        deadline_reprogram_local();
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

bool irq_is_registered(uint64_t irq_num) {
    if (irq_num >= ARCH_MAX_IRQ_NUM)
        return false;

    return __atomic_load_n(&actions[irq_num].used, __ATOMIC_ACQUIRE);
}

void irq_stat_read(uint64_t *counts, size_t count, uint64_t *total) {
    size_t limit = counts ? MIN(count, (size_t)ARCH_MAX_IRQ_NUM) : 0;
    size_t online_cpus = cpu_count ? MIN(cpu_count, (uint64_t)MAX_CPU_NUM) : 1;
    uint64_t sum = 0;

    for (size_t irq_num = 0; irq_num < ARCH_MAX_IRQ_NUM; irq_num++) {
        uint64_t irq_total = 0;

        for (size_t cpu = 0; cpu < online_cpus; cpu++) {
            irq_total +=
                __atomic_load_n(&irq_counts[cpu][irq_num], __ATOMIC_RELAXED);
        }

        if (irq_num < limit)
            counts[irq_num] = irq_total;
        sum += irq_total;
    }

    if (counts && count > limit)
        memset(counts + limit, 0, sizeof(*counts) * (count - limit));
    if (total)
        *total = sum;
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

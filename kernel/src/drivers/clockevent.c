#include <arch/arch.h>
#include <drivers/clockevent.h>
#include <drivers/logger.h>
#include <irq/softirq.h>
#include <task/task.h>

static clockevent_device_t *active_clockevent;
static spinlock_t clockevent_lock = SPIN_INIT;
static uint64_t clockevent_deadline_ns = UINT64_MAX;

static uint64_t clockevent_clamp_delta(clockevent_device_t *dev,
                                       uint64_t delta_ns) {
    if (dev->min_delta_ns && delta_ns < dev->min_delta_ns)
        delta_ns = dev->min_delta_ns;
    if (dev->max_delta_ns && delta_ns > dev->max_delta_ns)
        delta_ns = dev->max_delta_ns;
    return delta_ns;
}

int clockevent_register_device(clockevent_device_t *dev) {
    if (!dev || !dev->ops || !dev->ops->set_next_event)
        return -EINVAL;

    spin_lock(&clockevent_lock);
    if (!active_clockevent || dev->rating > active_clockevent->rating)
        active_clockevent = dev;
    spin_unlock(&clockevent_lock);

    printk("clockevent: registered %s\n", dev->name ? dev->name : "unknown");
    return 0;
}

void clockevent_shutdown(void) {
    clockevent_device_t *dev;

    spin_lock(&clockevent_lock);
    dev = active_clockevent;
    clockevent_deadline_ns = UINT64_MAX;
    if (dev && dev->ops->shutdown)
        dev->ops->shutdown(dev);
    spin_unlock(&clockevent_lock);
}

void clockevent_program_event(uint64_t monotonic_deadline_ns) {
    clockevent_device_t *dev;
    uint64_t programmed_ns;
    uint64_t now_ns;
    uint64_t delta_ns;
    int ret;

    if (monotonic_deadline_ns == UINT64_MAX) {
        clockevent_shutdown();
        return;
    }

    spin_lock(&clockevent_lock);
    dev = active_clockevent;
    programmed_ns = clockevent_deadline_ns;
    if (!dev) {
        spin_unlock(&clockevent_lock);
        return;
    }

    if (programmed_ns == monotonic_deadline_ns) {
        spin_unlock(&clockevent_lock);
        return;
    }

    now_ns = nano_time();
    delta_ns =
        monotonic_deadline_ns > now_ns ? monotonic_deadline_ns - now_ns : 1;

    delta_ns = clockevent_clamp_delta(dev, delta_ns);

    ret = dev->ops->set_next_event(dev, delta_ns);
    if (ret == 0)
        clockevent_deadline_ns = monotonic_deadline_ns;
    spin_unlock(&clockevent_lock);
}

void clockevent_handle_irq(void) {
    __atomic_store_n(&clockevent_deadline_ns, UINT64_MAX, __ATOMIC_RELEASE);

    softirq_raise(SOFTIRQ_TIMER);
    sched_wake_worker(current_cpu_id);
}

#include <arch/arch.h>
#include <drivers/deadline.h>
#include <drivers/logger.h>
#include <irq/irq_manager.h>
#include <task/sched.h>
#include <task/task.h>
#include <task/watchdog.h>

#define SCHED_WATCHDOG_PERIOD_NS (100000000ULL)
#define SCHED_WATCHDOG_STALL_NS (2000000000ULL)
#define SCHED_WATCHDOG_WARN_INTERVAL_NS (1000000000ULL)

typedef struct sched_watchdog_cpu {
    deadline_source_t deadline;
    task_t *running_task;
    uint64_t current_pid;
    uint64_t current_sched_in_ns;
    uint64_t resched_since_ns;
    uint64_t preempt_since_ns;
    uint64_t last_warn_ns;
} sched_watchdog_cpu_t;

static sched_watchdog_cpu_t sched_watchdogs[MAX_CPU_NUM];
static bool sched_watchdog_initialized;

extern sched_rq_t schedulers[MAX_CPU_NUM];

static inline bool sched_watchdog_cpu_online(uint32_t cpu_id) {
    return cpu_id < MAX_CPU_NUM && cpu_id < cpu_count;
}

static inline uint64_t sched_watchdog_next_deadline(uint64_t now_ns) {
    if (now_ns > UINT64_MAX - SCHED_WATCHDOG_PERIOD_NS)
        return UINT64_MAX;
    return now_ns + SCHED_WATCHDOG_PERIOD_NS;
}

static void sched_watchdog_arm(uint32_t cpu_id, uint64_t now_ns) {
    if (!sched_watchdog_initialized || !sched_watchdog_cpu_online(cpu_id))
        return;

    deadline_source_update(&sched_watchdogs[cpu_id].deadline,
                           sched_watchdog_next_deadline(now_ns));
}

static void sched_watchdog_update_task_locked(uint32_t cpu_id, task_t *task,
                                              uint64_t now_ns) {
    sched_watchdog_cpu_t *wd = &sched_watchdogs[cpu_id];
    uint64_t preempt_count =
        task ? __atomic_load_n(&task->preempt_count, __ATOMIC_ACQUIRE) : 0;
    bool need_resched = task_need_resched(task);

    wd->running_task = task;
    wd->current_pid = task ? task->pid : 0;
    wd->current_sched_in_ns = now_ns;
    wd->resched_since_ns = task && need_resched ? now_ns : 0;
    wd->preempt_since_ns = task && preempt_count ? now_ns : 0;
    wd->last_warn_ns = 0;
}

static void sched_watchdog_check_cpu(uint32_t cpu_id, uint64_t now_ns) {
    if (!sched_watchdog_cpu_online(cpu_id))
        return;

    task_t *task = NULL;
    sched_watchdog_cpu_t *wd = &sched_watchdogs[cpu_id];

    if (cpu_id == current_cpu_id) {
        task = current_task;
    } else if (idle_tasks[cpu_id]) {
        sched_rq_t *rq = &schedulers[cpu_id];
        if (raw_spin_trylock(&rq->lock)) {
            if (rq->curr && rq->curr->task)
                task = rq->curr->task;
            raw_spin_unlock(&rq->lock);
        } else {
            return;
        }
    }

    if (!task) {
        sched_watchdog_update_task_locked(cpu_id, NULL, now_ns);
        return;
    }

    if (wd->current_pid != task->pid) {
        sched_watchdog_update_task_locked(cpu_id, task, now_ns);
        return;
    }

    uint64_t preempt_count =
        __atomic_load_n(&task->preempt_count, __ATOMIC_ACQUIRE);
    bool need_resched = task_need_resched(task);
    void *preempt_caller =
        __atomic_load_n(&task->preempt_caller, __ATOMIC_ACQUIRE);

    if (need_resched) {
        if (!wd->resched_since_ns)
            wd->resched_since_ns = now_ns ? now_ns : 1;
    } else {
        wd->resched_since_ns = 0;
    }

    if (preempt_count) {
        if (!wd->preempt_since_ns)
            wd->preempt_since_ns = now_ns ? now_ns : 1;
    } else {
        wd->preempt_since_ns = 0;
        wd->last_warn_ns = 0;
    }

    bool stalled = preempt_count && wd->preempt_since_ns &&
                   now_ns >= wd->preempt_since_ns + SCHED_WATCHDOG_STALL_NS;

    if (stalled &&
        (!wd->last_warn_ns ||
         now_ns >= wd->last_warn_ns + SCHED_WATCHDOG_WARN_INTERVAL_NS)) {
        uint64_t preempt_ns =
            now_ns > wd->preempt_since_ns ? now_ns - wd->preempt_since_ns : 0;
        uint64_t resched_ns =
            wd->resched_since_ns && now_ns > wd->resched_since_ns
                ? now_ns - wd->resched_since_ns
                : 0;
        uint64_t sched_in_ns =
            wd->current_sched_in_ns && now_ns > wd->current_sched_in_ns
                ? now_ns - wd->current_sched_in_ns
                : 0;

        wd->last_warn_ns = now_ns;
        printk("sched watchdog: cpu=%u task=%s pid=%lu "
               "preempt_count=%lu preempt_caller=%p "
               "need_resched=%u preempt_ms=%lu resched_ms=%lu "
               "sched_in_ms=%lu\n",
               cpu_id, task->name, task->pid, preempt_count, preempt_caller,
               need_resched ? 1 : 0, preempt_ns / 1000000ULL,
               resched_ns / 1000000ULL, sched_in_ns / 1000000ULL);
    }

    uint64_t next = deadline_cached_next_ns_for_cpu(cpu_id);
    if (next <= now_ns) {
        if (cpu_id == current_cpu_id) {
            deadline_reprogram_local();
        } else {
            deadline_reprogram_cpu(cpu_id);
        }
    } else if (need_resched && cpu_id != current_cpu_id) {
        irq_trigger_sched_ipi(cpu_id);
    }
}

void sched_watchdog_init(void) {
    for (uint32_t cpu = 0; cpu < MAX_CPU_NUM; cpu++) {
        memset(&sched_watchdogs[cpu], 0, sizeof(sched_watchdogs[cpu]));
        deadline_source_init(&sched_watchdogs[cpu].deadline,
                             DEADLINE_SOURCE_SCHED_WATCHDOG, cpu);
    }
    __atomic_store_n(&sched_watchdog_initialized, true, __ATOMIC_RELEASE);
}

void sched_watchdog_init_cpu(uint32_t cpu_id) {
    uint64_t now_ns = nano_time();

    if (!__atomic_load_n(&sched_watchdog_initialized, __ATOMIC_ACQUIRE))
        return;
    if (!sched_watchdog_cpu_online(cpu_id))
        return;

    sched_watchdog_update_task_locked(cpu_id, current_task, now_ns);
    sched_watchdog_arm(cpu_id, now_ns);
}

void sched_watchdog_note_current(uint32_t cpu_id, task_t *task,
                                 uint64_t now_ns) {
    if (!__atomic_load_n(&sched_watchdog_initialized, __ATOMIC_ACQUIRE))
        return;
    if (!sched_watchdog_cpu_online(cpu_id))
        return;

    sched_watchdog_update_task_locked(cpu_id, task, now_ns);
}

void sched_watchdog_task_switch(uint32_t cpu_id, task_t *task,
                                uint64_t now_ns) {
    if (!sched_watchdog_cpu_online(cpu_id))
        return;

    sched_watchdog_update_task_locked(cpu_id, task, now_ns);
    sched_watchdog_arm(cpu_id, now_ns);
}

void sched_watchdog_note_resched(task_t *task, uint64_t now_ns) {
    if (!task || task->cpu_id >= MAX_CPU_NUM)
        return;
    if (!__atomic_load_n(&sched_watchdog_initialized, __ATOMIC_ACQUIRE))
        return;

    sched_watchdog_cpu_t *wd = &sched_watchdogs[task->cpu_id];
    if (wd->current_pid != task->pid)
        return;

    if (!wd->resched_since_ns)
        wd->resched_since_ns = now_ns ? now_ns : 1;
}

void sched_watchdog_tick(uint32_t cpu_id, task_t *task, uint64_t now_ns) {
    (void)task;

    if (!__atomic_load_n(&sched_watchdog_initialized, __ATOMIC_ACQUIRE))
        return;
    if (!sched_watchdog_cpu_online(cpu_id))
        return;

    sched_watchdog_arm(cpu_id, now_ns);

    uint32_t online_cpus = MIN((uint32_t)cpu_count, (uint32_t)MAX_CPU_NUM);
    for (uint32_t scan_cpu = 0; scan_cpu < online_cpus; scan_cpu++)
        sched_watchdog_check_cpu(scan_cpu, now_ns);
}

void sched_watchdog_park_cpu(uint32_t cpu_id) {
    if (cpu_id >= MAX_CPU_NUM)
        return;

    deadline_source_update(&sched_watchdogs[cpu_id].deadline, UINT64_MAX);
}

#include <fs/proc/proc.h>
#include <arch/arch.h>
#include <boot/boot.h>
#include <irq/irq_manager.h>
#include <libs/string_builder.h>
#include <task/task.h>

typedef struct proc_stat_cpu_times {
    uint64_t user_ns;
    uint64_t nice_ns;
    uint64_t system_ns;
} proc_stat_cpu_times_t;

typedef struct proc_stat_snapshot {
    proc_stat_cpu_times_t cpu_times[MAX_CPU_NUM];
    uint64_t irq_counts[ARCH_MAX_IRQ_NUM];
    uint64_t irq_total;
    size_t processes;
    size_t running;
    size_t blocked;
} proc_stat_snapshot_t;

static proc_stat_cpu_times_t proc_stat_last_raw[MAX_CPU_NUM];
static proc_stat_cpu_times_t proc_stat_published[MAX_CPU_NUM];
static bool proc_stat_has_sample[MAX_CPU_NUM];
static spinlock_t proc_stat_lock = SPIN_INIT;

static unsigned long long proc_stat_ns_to_ticks(uint64_t ns) {
    return (unsigned long long)(ns / (1000000000ULL / SCHED_HZ));
}

static uint64_t proc_stat_delta(uint64_t now, uint64_t old) {
    return now > old ? now - old : 0;
}

static void proc_stat_collect(proc_stat_snapshot_t *stat, size_t cpu_slots,
                              uint64_t now_ns) {
    memset(stat, 0, sizeof(*stat));

    spin_lock(&task_queue_lock);
    if (task_pid_map.buckets) {
        for (size_t i = 0; i < task_pid_map.bucket_count; i++) {
            hashmap_entry_t *entry = &task_pid_map.buckets[i];
            if (!hashmap_entry_is_occupied(entry))
                continue;

            task_t *task = (task_t *)entry->value;
            if (!task || task->state == TASK_DIED) {
                continue;
            }

            if (task->pid == task_effective_tgid(task))
                stat->processes++;
            if (task->state == TASK_RUNNING)
                stat->running++;
            if (task->state == TASK_BLOCKING ||
                task->state == TASK_UNINTERRUPTABLE) {
                stat->blocked++;
            }

            if (cpu_slots) {
                uint32_t cpu = task->cpu_id < cpu_slots ? task->cpu_id : 0;
                if (cpu < MAX_CPU_NUM && idle_tasks[cpu] == task)
                    continue;

                uint64_t user_ns = task_self_user_ns(task);
                uint64_t system_ns = task->system_time_ns;

                if (task->last_sched_in_ns && now_ns > task->last_sched_in_ns &&
                    task->current_state == TASK_RUNNING) {
                    user_ns += now_ns - task->last_sched_in_ns;
                }

                if (task->nice > 0)
                    stat->cpu_times[cpu].nice_ns += user_ns;
                else
                    stat->cpu_times[cpu].user_ns += user_ns;
                stat->cpu_times[cpu].system_ns += system_ns;
            }
        }
    }
    spin_unlock(&task_queue_lock);

    irq_stat_read(stat->irq_counts, ARCH_MAX_IRQ_NUM, &stat->irq_total);
}

static void proc_stat_make_cpu_times_monotonic(proc_stat_snapshot_t *stat,
                                               size_t cpu_slots) {
    if (!stat)
        return;

    spin_lock(&proc_stat_lock);
    for (size_t cpu = 0; cpu < cpu_slots && cpu < MAX_CPU_NUM; cpu++) {
        proc_stat_cpu_times_t raw = stat->cpu_times[cpu];

        if (!proc_stat_has_sample[cpu]) {
            proc_stat_published[cpu] = raw;
            proc_stat_has_sample[cpu] = true;
        } else {
            proc_stat_published[cpu].user_ns +=
                proc_stat_delta(raw.user_ns, proc_stat_last_raw[cpu].user_ns);
            proc_stat_published[cpu].nice_ns +=
                proc_stat_delta(raw.nice_ns, proc_stat_last_raw[cpu].nice_ns);
            proc_stat_published[cpu].system_ns += proc_stat_delta(
                raw.system_ns, proc_stat_last_raw[cpu].system_ns);
        }

        proc_stat_last_raw[cpu] = raw;
        stat->cpu_times[cpu] = proc_stat_published[cpu];
    }
    spin_unlock(&proc_stat_lock);
}

static void proc_stat_append_cpu_line(string_builder_t *builder,
                                      const char *name,
                                      proc_stat_cpu_times_t times,
                                      uint64_t total_ns) {
    uint64_t busy_ns = times.user_ns + times.nice_ns + times.system_ns;
    uint64_t idle_ns = total_ns > busy_ns ? total_ns - busy_ns : 0;

    string_builder_append(builder, "%s %llu %llu %llu %llu 0 0 0 0 0 0\n", name,
                          proc_stat_ns_to_ticks(times.user_ns),
                          proc_stat_ns_to_ticks(times.nice_ns),
                          proc_stat_ns_to_ticks(times.system_ns),
                          proc_stat_ns_to_ticks(idle_ns));
}

static char *proc_gen_stat(size_t *content_len) {
    string_builder_t *builder = create_string_builder(8192);
    uint64_t online_cpus =
        cpu_count ? MIN(cpu_count, (uint64_t)MAX_CPU_NUM) : 1;
    proc_stat_snapshot_t *stat = malloc(sizeof(*stat));
    proc_stat_cpu_times_t total = {0};
    uint64_t now_ns = nano_time();
    if (!builder || !stat) {
        if (builder) {
            free(builder->data);
            free(builder);
        }
        if (stat)
            free(stat);
        *content_len = 0;
        return NULL;
    }
    proc_stat_collect(stat, online_cpus, now_ns);
    proc_stat_make_cpu_times_monotonic(stat, online_cpus);

    for (uint64_t cpu = 0; cpu < online_cpus; cpu++) {
        total.user_ns += stat->cpu_times[cpu].user_ns;
        total.nice_ns += stat->cpu_times[cpu].nice_ns;
        total.system_ns += stat->cpu_times[cpu].system_ns;
    }

    proc_stat_append_cpu_line(builder, "cpu", total, now_ns * online_cpus);
    for (uint64_t cpu = 0; cpu < online_cpus; cpu++) {
        char name[16];
        snprintf(name, sizeof(name), "cpu%llu", (unsigned long long)cpu);
        proc_stat_append_cpu_line(builder, name, stat->cpu_times[cpu], now_ns);
    }

    string_builder_append(builder, "intr %llu",
                          (unsigned long long)stat->irq_total);
    for (uint64_t irq_num = 0; irq_num < ARCH_MAX_IRQ_NUM; irq_num++) {
        string_builder_append(builder, " %llu",
                              (unsigned long long)stat->irq_counts[irq_num]);
    }
    string_builder_append(builder, "\n");
    string_builder_append(builder, "ctxt 0\n");
    string_builder_append(builder, "btime %llu\n",
                          (unsigned long long)boot_get_boottime());
    string_builder_append(builder, "processes %llu\n",
                          (unsigned long long)stat->processes);
    string_builder_append(builder, "procs_running %llu\n",
                          (unsigned long long)stat->running);
    string_builder_append(builder, "procs_blocked %llu\n",
                          (unsigned long long)stat->blocked);
    string_builder_append(builder, "softirq 0 0 0 0 0 0 0 0 0 0 0\n");

    *content_len = builder->size;
    char *data = builder->data;
    free(stat);
    free(builder);
    return data;
}

size_t proc_stat_stat(proc_handle_t *handle) {
    size_t content_len = 0;
    char *content = proc_gen_stat(&content_len);
    free(content);
    return content_len;
}

size_t proc_stat_read(proc_handle_t *handle, void *addr, size_t offset,
                      size_t size) {
    size_t content_len = 0;
    char *content = proc_gen_stat(&content_len);
    if (!content) {
        return 0;
    }
    if (offset >= content_len) {
        free(content);
        return 0;
    }

    size_t to_copy = MIN(size, content_len - offset);
    memcpy(addr, content + offset, to_copy);
    free(content);
    return to_copy;
}

#include <fs/proc/proc.h>
#include <arch/arch.h>
#include <boot/boot.h>
#include <libs/string_builder.h>
#include <task/task.h>

static void proc_stat_counts(size_t *processes, size_t *running,
                             size_t *blocked) {
    if (processes)
        *processes = 0;
    if (running)
        *running = 0;
    if (blocked)
        *blocked = 0;

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

            if (processes)
                (*processes)++;
            if (running && task->state == TASK_RUNNING)
                (*running)++;
            if (blocked && (task->state == TASK_BLOCKING ||
                            task->state == TASK_UNINTERRUPTABLE ||
                            task->state == TASK_READING_STDIO)) {
                (*blocked)++;
            }
        }
    }
    spin_unlock(&task_queue_lock);
}

static char *proc_gen_stat(size_t *content_len) {
    string_builder_t *builder = create_string_builder(1024);
    size_t processes = 0;
    size_t running = 0;
    size_t blocked = 0;
    if (!builder) {
        *content_len = 0;
        return NULL;
    }
    proc_stat_counts(&processes, &running, &blocked);

    string_builder_append(builder, "cpu  0 0 0 0 0 0 0 0 0 0\n");
    for (uint64_t cpu = 0; cpu < cpu_count; cpu++) {
        string_builder_append(builder, "cpu%llu 0 0 0 0 0 0 0 0 0 0\n",
                              (unsigned long long)cpu);
    }

    string_builder_append(builder, "ctxt 0\n");
    string_builder_append(builder, "btime %llu\n",
                          (unsigned long long)boot_get_boottime());
    string_builder_append(builder, "processes %llu\n",
                          (unsigned long long)processes);
    string_builder_append(builder, "procs_running %llu\n",
                          (unsigned long long)running);
    string_builder_append(builder, "procs_blocked %llu\n",
                          (unsigned long long)blocked);
    string_builder_append(builder, "softirq 0 0 0 0 0 0 0 0 0 0 0\n");

    *content_len = builder->size;
    char *data = builder->data;
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

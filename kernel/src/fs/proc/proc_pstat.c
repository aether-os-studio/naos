#include <fs/proc/proc.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

static unsigned long long proc_stat_ns_to_ticks(uint64_t ns) {
    return (unsigned long long)(ns / (1000000000ULL / SCHED_HZ));
}

static char proc_stat_task_state(task_t *task) {
    if (!task)
        return 'R';

    switch (task->state) {
    case TASK_RUNNING:
        return 'R';
    case TASK_BLOCKING:
    case TASK_READING_STDIO:
        return 'S';
    case TASK_UNINTERRUPTABLE:
        return 'D';
    case TASK_DIED:
        return 'Z';
    default:
        return 'S';
    }
}

static void proc_stat_signal_masks(task_t *task, unsigned long long *ignored,
                                   unsigned long long *caught) {
    if (ignored)
        *ignored = 0;
    if (caught)
        *caught = 0;
    if (!task || !task->signal || !task->signal->sighand)
        return;

    spin_lock(&task->signal->sighand->siglock);
    for (int sig = MINSIG; sig < MAXSIG; sig++) {
        sigaction_t *action = &task->signal->sighand->actions[sig];
        uint64_t bit = 1ULL << (uint64_t)(sig - 1);
        if (action->sa_handler == SIG_IGN) {
            if (ignored)
                *ignored |= bit;
        } else if (action->sa_handler != SIG_DFL) {
            if (caught)
                *caught |= bit;
        }
    }
    spin_unlock(&task->signal->sighand->siglock);
}

char *proc_gen_stat_file(task_t *task, size_t *content_len) {
    char *buffer = malloc(PAGE_SIZE * 4);
    procfs_task_mem_stats_t mem;
    if (!buffer) {
        *content_len = 0;
        return NULL;
    }
    if (!task) {
        int len = sprintf(buffer, "0 (unknown) Z 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
                                  "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
                                  "0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
        *content_len = len;
        return buffer;
    }
    procfs_task_mem_stats(task, &mem);
    uint64_t tgid = task_effective_tgid(task);
    size_t threads = task_thread_group_count(tgid);
    unsigned long long ignored = 0;
    unsigned long long caught = 0;
    proc_stat_signal_masks(task, &ignored, &caught);
    int len = sprintf(
        buffer,
        "%d "
        "(%s) "
        "%c "
        "%d "
        "%d "
        "%d "
        "%d "
        "%d "
        "%u "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%ld "
        "%ld "
        "%ld "
        "%ld "
        "%ld "
        "%ld "
        "%llu "
        "%lu "
        "%ld "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%d "
        "%d "
        "%u "
        "%u "
        "%llu "
        "%lu "
        "%ld "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%lu "
        "%d\n",
        // args
        task->pid,                  // 1. pid
        task->name,                 // 2. comm
        proc_stat_task_state(task), // 3. state
        task_parent_pid(task),      // 4. ppid
        task->pgid,                 // 5. pgrp
        task->sid,                  // 6. session
        0UL,                        // 7. tty_nr (需从task获取真实值)
        0UL,                        // 8. tpgid (需从task获取真实值)
        0UL,                        // 9. flags (需从task获取真实值)
        0UL,                        // 10. minflt
        0UL,                        // 11. cminflt
        0UL,                        // 12. majflt
        0UL,                        // 13. cmajflt
        proc_stat_ns_to_ticks(task_self_user_ns(task)),          // 14. utime
        proc_stat_ns_to_ticks(task->system_time_ns),             // 15. stime
        (long)proc_stat_ns_to_ticks(task->child_user_time_ns),   // 16
        (long)proc_stat_ns_to_ticks(task->child_system_time_ns), // 17
        20L - task->nice,                                        // 18. priority
        (long)task->nice,                                        // 19. nice
        (long)threads,                                // 20. num_threads
        0L,                                           // 21. itrealvalue
        0ULL,                                         // 22. starttime
        (unsigned long)(mem.size_pages * PAGE_SIZE),  // 23. vsize
        (long)mem.resident_pages,                     // 24. rss (页数)
        task->rlim[RLIMIT_RSS].rlim_cur,              // 25. rsslim
        task->load_start,                             // 26. startcode
        task->load_end,                               // 27. endcode
        task->mm ? task_mm_stack_start(task->mm) : 0, // 28. startstack
        0UL,                                          // 29. kstkesp
        0UL,                                          // 30. kstkeip
        (unsigned long)sigset_kernel_to_user(task->signal->signal),  // 31
        (unsigned long)sigset_kernel_to_user(task->signal->blocked), // 32
        (unsigned long)ignored,       // 33. sigignore
        (unsigned long)caught,        // 34. sigcatch
        0UL,                          // 35. wchan
        0UL,                          // 36. nswap
        0UL,                          // 37. cnswap
        task->is_clone ? 0 : SIGCHLD, // 38. exit_signal
        task->cpu_id,                 // 39. processor
        task->sched_priority > 0 ? (unsigned int)task->sched_priority
                                 : 0U,      // 40
        (unsigned int)task->sched_policy,   // 41. policy
        0ULL,                               // 42. delayacct_blkio_ticks
        0UL,                                // 43. guest_time
        0L,                                 // 44. cguest_time
        0UL,                                // 45. start_data
        0UL,                                // 46. end_data
        task->mm ? task->mm->brk_start : 0, // 47. start_brk
        task->arg_start,                    // 48. arg_start
        task->arg_end,                      // 49. arg_end
        task->env_start,                    // 50. env_start
        task->env_end,                      // 51. env_end
        task->status                        // 52. exit_code
    );

    *content_len = len;

    return buffer;
}

size_t proc_pstat_stat(proc_handle_t *handle) {
    task_t *task;
    task = procfs_handle_task_or_current(handle);
    size_t content_len = 0;
    char *content = proc_gen_stat_file(task, &content_len);
    if (!content)
        return 0;
    free(content);
    return content_len;
}

size_t proc_pstat_read(proc_handle_t *handle, void *addr, size_t offset,
                       size_t size) {
    task_t *task;
    task = procfs_handle_task_or_current(handle);
    size_t content_len = 0;
    char *content = proc_gen_stat_file(task, &content_len);
    if (!content)
        return 0;
    if (offset >= content_len) {
        free(content);
        return 0;
    }
    size_t to_copy = MIN(size, content_len - offset);
    memcpy(addr, content + offset, to_copy);
    free(content);
    return to_copy;
}

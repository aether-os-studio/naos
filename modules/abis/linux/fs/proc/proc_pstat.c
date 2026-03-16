#include <fs/proc/proc.h>
#include <fs/fs_syscall.h>
#include <task/task.h>

#define PROC_STAT_USER_HZ 100

static unsigned long long proc_stat_ns_to_ticks(uint64_t ns) {
    return (unsigned long long)(ns / (1000000000ULL / PROC_STAT_USER_HZ));
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
    char *buffer = malloc(DEFAULT_PAGE_SIZE * 4);
    uint64_t tgid = task_effective_tgid(task);
    size_t threads = task_thread_group_count(tgid);
    unsigned long long ignored = 0;
    unsigned long long caught = 0;
    proc_stat_signal_masks(task, &ignored, &caught);
    int len = sprintf(
        buffer,
        // 1. pid: 进程ID (%d)
        "%d "
        // 2. comm: 可执行文件名 (括号括起，%s)
        "(%s) "
        // 3. state: 进程状态 (%c) [citation:1]
        "%c "
        // 4. ppid: 父进程ID (%d)
        "%d "
        // 5. pgrp: 进程组ID (%d) [原代码此处错误，不应为0]
        "%d "
        // 6. session: 会话ID (%d) [原代码错误使用了task->uid]
        "%d "
        // 7. tty_nr: 控制终端 (%d)
        "%d "
        // 8. tpgid: 前台进程组ID (%d)
        "%d "
        // 9. flags: 内核标志位 (%u) [citation:1]
        "%u "
        // 10. minflt: 缺页次数(轻微) (%lu)
        "%lu "
        // 11. cminflt: 子进程缺页(轻微) (%lu)
        "%lu "
        // 12. majflt: 缺页次数(严重) (%lu)
        "%lu "
        // 13. cmajflt: 子进程缺页(严重) (%lu)
        "%lu "
        // 14. utime: 用户态时间 (%lu) [citation:1]
        "%lu "
        // 15. stime: 内核态时间 (%lu) [citation:1]
        "%lu "
        // 16. cutime: 子进程用户态时间 (%ld) [citation:1]
        "%ld "
        // 17. cstime: 子进程内核态时间 (%ld) [citation:1]
        "%ld "
        // 18. priority: 优先级 (%ld) [citation:1]
        "%ld "
        // 19. nice: nice值 (%ld) [citation:1]
        "%ld "
        // 20. num_threads: 线程数 (%ld) [citation:1]
        "%ld "
        // 21. itrealvalue: 间隔定时器 (%ld) [citation:1]
        "%ld "
        // 22. starttime: 启动时间 (时钟滴答, %llu) [citation:1]
        "%llu "
        // 23. vsize: 虚拟内存大小 (%lu) [citation:1]
        "%lu "
        // 24. rss: 驻留内存页数 (%ld) [citation:1]
        "%ld "
        // 25. rsslim: RSS软限制 (%lu) [citation:1]
        "%lu "
        // 26. startcode: 代码段起始地址 (%lu) [citation:1]
        "%lu "
        // 27. endcode: 代码段结束地址 (%lu) [citation:1]
        "%lu "
        // 28. startstack: 栈起始地址 (%lu) [citation:1]
        "%lu "
        // 29. kstkesp: ESP指针值 (%lu) [citation:1]
        "%lu "
        // 30. kstkeip: EIP指针值 (%lu) [citation:1]
        "%lu "
        // 31. signal: 挂起信号位图 (%lu) [citation:1]
        "%lu "
        // 32. blocked: 阻塞信号位图 (%lu) [citation:1]
        "%lu "
        // 33. sigignore: 忽略信号位图 (%lu) [citation:1]
        "%lu "
        // 34. sigcatch: 捕获信号位图 (%lu) [citation:1]
        "%lu "
        // 35. wchan: 等待通道地址 (%lu) [citation:1]
        "%lu "
        // 36. nswap: 交换页数 (%lu) [citation:1]
        "%lu "
        // 37. cnswap: 子进程交换页数 (%lu) [citation:1]
        "%lu "
        // 38. exit_signal: 退出信号 (%d) [citation:1]
        "%d "
        // 39. processor: 最近执行的CPU (%d) [citation:1]
        "%d "
        // 40. rt_priority: 实时优先级 (%u) [citation:1]
        "%u "
        // 41. policy: 调度策略 (%u) [citation:1]
        "%u "
        // 42. delayacct_blkio_ticks: IO延迟滴答数 (%llu) [citation:1]
        "%llu "
        // 43. guest_time: 客户机时间 (%lu) [citation:1]
        "%lu "
        // 44. cguest_time: 子进程客户机时间 (%ld) [citation:1]
        "%ld "
        // 45. start_data: 数据段起始地址 (%lu) [citation:1]
        "%lu "
        // 46. end_data: 数据段结束地址 (%lu) [citation:1]
        "%lu "
        // 47. start_brk: 堆起始地址 (%lu) [citation:1]
        "%lu "
        // 48. arg_start: 参数列表起始地址 (%lu) [citation:1]
        "%lu "
        // 49. arg_end: 参数列表结束地址 (%lu) [citation:1]
        "%lu "
        // 50. env_start: 环境变量起始地址 (%lu) [citation:1]
        "%lu "
        // 51. env_end: 环境变量结束地址 (%lu) [citation:1]
        "%lu "
        // 52. exit_code: 退出码 (%d)
        "%d\n",

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
        20L,                                                     // 18. priority
        0L,                                                      // 19. nice
        (long)threads,                   // 20. num_threads
        0L,                              // 21. itrealvalue
        0ULL,                            // 22. starttime
        0UL,                             // 23. vsize
        0UL,                             // 24. rss (页数)
        task->rlim[RLIMIT_RSS].rlim_cur, // 25. rsslim
        task->load_start,                // 26. startcode
        task->load_end,                  // 27. endcode
        USER_STACK_START,                // 28. startstack
        0UL,                             // 29. kstkesp
        0UL,                             // 30. kstkeip
        (unsigned long)sigset_kernel_to_user(task->signal->signal),  // 31
        (unsigned long)sigset_kernel_to_user(task->signal->blocked), // 32
        (unsigned long)ignored,       // 33. sigignore
        (unsigned long)caught,        // 34. sigcatch
        0UL,                          // 35. wchan
        0UL,                          // 36. nswap
        0UL,                          // 37. cnswap
        task->is_clone ? 0 : SIGCHLD, // 38. exit_signal
        task->cpu_id,                 // 39. processor
        0U,                           // 40. rt_priority
        0U,                           // 41. policy
        0ULL,                         // 42. delayacct_blkio_ticks
        0UL,                          // 43. guest_time
        0L,                           // 44. cguest_time
        0UL,                          // 45. start_data
        0UL,                          // 46. end_data
        task->mm->brk_start,          // 47. start_brk
        task->arg_start,              // 48. arg_start
        task->arg_end,                // 49. arg_end
        task->env_start,              // 50. env_start
        task->env_end,                // 51. env_end
        task->status                  // 52. exit_code
    );

    *content_len = len;

    return buffer;
}

size_t proc_pstat_stat(proc_handle_t *handle) {
    task_t *task;
    if (handle->task == NULL) {
        task = current_task;
    } else {
        task = handle->task;
    }
    size_t content_len = 0;
    char *content = proc_gen_stat_file(task, &content_len);
    free(content);
    return content_len;
}

size_t proc_pstat_read(proc_handle_t *handle, void *addr, size_t offset,
                       size_t size) {
    task_t *task;
    if (handle->task == NULL) {
        task = current_task;
    } else {
        task = handle->task;
    }
    size_t content_len = 0;
    char *content = proc_gen_stat_file(task, &content_len);
    if (offset >= content_len) {
        free(content);
        return 0;
    }
    content_len = MIN(content_len, offset + size);
    size_t to_copy = MIN(content_len, size);
    memcpy(addr, content + offset, to_copy);
    free(content);
    ((char *)addr)[to_copy] = '\0';
    return to_copy;
}

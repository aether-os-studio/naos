#include <fs/proc/proc.h>
#include <task/task.h>
#include <libs/string_builder.h>

static char task_state_to_proc_state(task_t *task) {
    if (!task) {
        return 'R';
    }

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

static void proc_status_sig_masks(task_t *task, unsigned long long *ignored,
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

char *proc_gen_status_file(task_t *task, size_t *content_len) {
    uint64_t tgid = task_effective_tgid(task);
    size_t threads = task_thread_group_count(tgid);
    unsigned long long ignored = 0;
    unsigned long long caught = 0;
    proc_status_sig_masks(task, &ignored, &caught);
    string_builder_t *builder = create_string_builder(1024);

    string_builder_append(
        builder,
        "Name:\t%s\n"
        "State:\t%c\n"
        "Tgid:\t%llu\n"
        "Pid:\t%llu\n"
        "PPid:\t%llu\n"
        "Threads:\t%llu\n"
        "NStgid:\t%llu\n"
        "NSpid:\t%llu\n"
        "NSpgid:\t%lld\n"
        "NSsid:\t%lld\n"
        "VmPeak:\t0 kB\n"
        "VmSize:\t0 kB\n"
        "VmLck:\t0 kB\n"
        "VmPin:\t0 kB\n"
        "VmHWM:\t0 kB\n"
        "VmRSS:\t0 kB\n"
        "RssAnon:\t0 kB\n"
        "RssFile:\t0 kB\n"
        "RssShmem:\t0 kB\n"
        "VmData:\t0 kB\n"
        "VmStk:\t0 kB\n"
        "VmExe:\t0 kB\n"
        "VmLib:\t0 kB\n"
        "VmPTE:\t0 kB\n"
        "VmSwap:\t0 kB\n"
        "HugetlbPages:\t0 kB\n"
        "SigPnd:\t%016llx\n"
        "ShdPnd:\t%016llx\n"
        "SigBlk:\t%016llx\n"
        "SigIgn:\t%016llx\n"
        "SigCgt:\t%016llx\n"
        "CapInh:\t0000000000000000\n"
        "CapPrm:\t0000000000000000\n"
        "CapEff:\t0000000000000000\n"
        "CapBnd:\t0000000000000000\n"
        "CapAmb:\t0000000000000000\n",
        task ? task->name : "unknown", task_state_to_proc_state(task),
        (unsigned long long)tgid, (unsigned long long)(task ? task->pid : 0),
        (unsigned long long)task_parent_pid(task), (unsigned long long)threads,
        (unsigned long long)tgid, (unsigned long long)(task ? task->pid : 0),
        task ? task->pgid : 0, task ? task->sid : 0,
        (unsigned long long)(task && task->signal
                                 ? sigset_kernel_to_user(task->signal->signal)
                                 : 0),
        0ULL,
        (unsigned long long)(task && task->signal
                                 ? sigset_kernel_to_user(task->signal->blocked)
                                 : 0),
        ignored, caught);

    char *data = builder->data;
    *content_len = builder->size;
    free(builder);
    return data;
}

size_t proc_pstatus_stat(proc_handle_t *handle) {
    task_t *task = procfs_handle_task_or_current(handle);
    size_t content_len = 0;
    char *content = proc_gen_status_file(task, &content_len);
    free(content);
    return content_len;
}

size_t proc_pstatus_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    task_t *task = procfs_handle_task_or_current(handle);
    size_t content_len = 0;
    char *content = proc_gen_status_file(task, &content_len);
    if (offset >= content_len) {
        free(content);
        return 0;
    }

    size_t to_copy = MIN(size, content_len - offset);
    memcpy(addr, content + offset, to_copy);
    free(content);
    return to_copy;
}

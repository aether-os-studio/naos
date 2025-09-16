#include <arch/arch.h>
#include <task/task.h>
#include <drivers/kernel_logger.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/vfs.h>
#include <fs/vfs/proc.h>
#include <arch/arch.h>
#include <mm/mm.h>
#include <fs/fs_syscall.h>
#include <net/socket.h>

const uint64_t bitmap_size = (USER_MMAP_END - USER_MMAP_START) / DEFAULT_PAGE_SIZE / 8;

spinlock_t task_queue_lock = {0};
task_t *tasks[MAX_TASK_NUM];
task_t *idle_tasks[MAX_CPU_NUM];

extern stdio_handle_t *global_stdio_handle;

void send_sigint()
{
    if (global_stdio_handle == NULL)
        return;

    uint64_t continue_ptr_count = 0;
    for (size_t i = 1; i < MAX_TASK_NUM; i++)
    {
        task_t *ptr = tasks[i];
        if (ptr == NULL)
        {
            continue_ptr_count++;
            if (continue_ptr_count >= MAX_CONTINUE_NULL_TASKS)
                break;
            continue;
        }
        continue_ptr_count = 0;

        if (tasks[i]->pgid == global_stdio_handle->at_process_group_id)
        {
            if (tasks[i]->actions[SIGINT].sa_handler == SIG_DFL || tasks[i]->actions[SIGINT].sa_handler == SIG_IGN)
            {
                spin_lock(&tasks[i]->signal_lock);
                tasks[i]->signal |= SIGMASK(SIGKILL);
                spin_unlock(&tasks[i]->signal_lock);
            }
            else if (tasks[i]->state != TASK_READING_STDIO)
            {
                spin_lock(&tasks[i]->signal_lock);
                tasks[i]->signal |= SIGMASK(SIGINT);
                spin_unlock(&tasks[i]->signal_lock);
            }
        }
    }
}

bool task_initialized = false;
bool can_schedule = false;

extern int unix_socket_fsid;
extern int unix_accept_fsid;

task_t *get_free_task()
{
    for (uint64_t i = 0; i < cpu_count; i++)
    {
        if (idle_tasks[i] == NULL)
        {
            idle_tasks[i] = (task_t *)malloc(sizeof(task_t));
            memset(idle_tasks[i], 0, sizeof(task_t));
            idle_tasks[i]->state = TASK_CREATING;
            idle_tasks[i]->pid = 0;
            can_schedule = true;
            return idle_tasks[i];
        }
    }

    spin_lock(&task_queue_lock);

    for (uint64_t i = 1; i < MAX_TASK_NUM; i++)
    {
        if (tasks[i] == NULL)
        {
            tasks[i] = (task_t *)malloc(sizeof(task_t));
            memset(tasks[i], 0, sizeof(task_t));
            tasks[i]->state = TASK_CREATING;
            tasks[i]->pid = i;
            can_schedule = true;
            spin_unlock(&task_queue_lock);
            return tasks[i];
        }
    }

    spin_unlock(&task_queue_lock);

    return NULL;
}

uint32_t cpu_idx = 0;

uint32_t alloc_cpu_id()
{
    uint32_t idx = cpu_idx;
    cpu_idx = (cpu_idx + 1) % cpu_count;
    return idx;
}

task_t *task_create(const char *name, void (*entry)(uint64_t), uint64_t arg, uint64_t priority)
{
    arch_disable_interrupt();

    task_t *task = get_free_task();
    task->call_in_signal = 0;
    memset(&task->signal_saved_regs, 0, sizeof(struct pt_regs));
    task->cpu_id = alloc_cpu_id();
    task->ppid = task->pid;
    task->uid = 0;
    task->gid = 0;
    task->euid = 0;
    task->egid = 0;
    task->ruid = 0;
    task->rgid = 0;
    task->pgid = 0;
    task->sid = 0;
    task->waitpid = 0;
    task->priority = priority;
    task->jiffies = 0;
    task->kernel_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    task->syscall_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    task->signal_syscall_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    task->syscall_stack_user = 0;
    memset((void *)(task->kernel_stack - STACK_SIZE), 0, STACK_SIZE);
    memset((void *)(task->syscall_stack - STACK_SIZE), 0, STACK_SIZE);
    memset((void *)(task->signal_syscall_stack - STACK_SIZE), 0, STACK_SIZE);
    task->arch_context = malloc(sizeof(arch_context_t));
    memset(task->arch_context, 0, sizeof(arch_context_t));
    arch_context_init(task->arch_context, virt_to_phys((uint64_t)get_kernel_page_dir()), (uint64_t)entry, task->kernel_stack, false, arg);
    task->signal = 0;
    task->saved_signal = 0;
    task->status = 0;
    task->cwd = rootdir;
    task->mmap_regions = malloc(sizeof(Bitmap));
    bitmap_init(task->mmap_regions, alloc_frames_bytes(bitmap_size), bitmap_size);
    memset(task->mmap_regions->buffer, 0xff, bitmap_size);
    task->fd_info = malloc(sizeof(fd_info_t));
    memset(task->fd_info, 0, sizeof(task->fd_info));
    memset(task->fd_info->fds, 0, sizeof(task->fd_info->fds));
    task->fd_info->fds[0] = malloc(sizeof(fd_t));
    task->fd_info->fds[0]->node = vfs_open("/dev/stdin");
    task->fd_info->fds[0]->offset = 0;
    task->fd_info->fds[0]->flags = 0;
    task->fd_info->fds[1] = malloc(sizeof(fd_t));
    task->fd_info->fds[1]->node = vfs_open("/dev/stdout");
    task->fd_info->fds[1]->offset = 0;
    task->fd_info->fds[1]->flags = 0;
    task->fd_info->fds[2] = malloc(sizeof(fd_t));
    task->fd_info->fds[2]->node = vfs_open("/dev/stderr");
    task->fd_info->fds[2]->offset = 0;
    task->fd_info->fds[2]->flags = 0;
    task->fd_info->ref_count++;
    strncpy(task->name, name, TASK_NAME_MAX);

    memset(task->actions, 0, sizeof(task->actions));

    memset(&task->term, 0, sizeof(termios));
    task->term.c_iflag = BRKINT | ICRNL | INPCK | ISTRIP | IXON;
    task->term.c_oflag = OPOST;
    task->term.c_cflag = CS8 | CREAD | CLOCAL;
    task->term.c_lflag = ECHO | ICANON | IEXTEN | ISIG;
    task->term.c_line = 0;
    task->term.c_cc[VINTR] = 3;     // Ctrl-C
    task->term.c_cc[VQUIT] = 28;    // Ctrl-task->term.c_cc[VERASE] = 127; // DEL
    task->term.c_cc[VKILL] = 21;    // Ctrl-U
    task->term.c_cc[VEOF] = 4;      // Ctrl-D
    task->term.c_cc[VTIME] = 0;     // No timer
    task->term.c_cc[VMIN] = 1;      // Return each byte
    task->term.c_cc[VSTART] = 17;   // Ctrl-Q
    task->term.c_cc[VSTOP] = 19;    // Ctrl-S
    task->term.c_cc[VSUSP] = 26;    // Ctrl-Z
    task->term.c_cc[VREPRINT] = 18; // Ctrl-R
    task->term.c_cc[VDISCARD] = 15; // Ctrl-O
    task->term.c_cc[VWERASE] = 23;  // Ctrl-W
    task->term.c_cc[VLNEXT] = 22;   // Ctrl-V
    // Initialize other control characters to 0
    for (int i = 16; i < NCCS; i++)
    {
        task->term.c_cc[i] = 0;
    }

    task->tmp_rec_v = 0;
    task->cmdline = NULL;

    memset(task->actions, 0, sizeof(task->actions));

    memset(task->rlim, 0, sizeof(task->rlim));
    task->rlim[RLIMIT_NPROC] = (struct rlimit){0, MAX_TASK_NUM};
    task->rlim[RLIMIT_NOFILE] = (struct rlimit){MAX_FD_NUM, MAX_FD_NUM};
    task->rlim[RLIMIT_CORE] = (struct rlimit){0, 0};

    task->child_vfork_done = false;
    task->is_vfork = false;

    procfs_on_new_task(task);

    task->state = TASK_READY;
    task->current_state = TASK_READY;

    return task;
}

task_t *task_search(task_state_t state, uint32_t cpu_id)
{
    task_t *task = NULL;

    spin_lock(&task_queue_lock);

    uint64_t continue_ptr_count = 0;

    for (size_t i = 1; i < MAX_TASK_NUM; i++)
    {
        task_t *ptr = tasks[i];
        if (ptr == NULL)
        {
            continue_ptr_count++;
            if (continue_ptr_count >= MAX_CONTINUE_NULL_TASKS)
                break;
            continue;
        }
        continue_ptr_count = 0;
        if (ptr->state != state)
            continue;
        if (current_task == ptr)
            continue;
        if (ptr->cpu_id != cpu_id)
            continue;

        if (task == NULL || ptr->jiffies < task->jiffies)
            task = ptr;
    }

    if (task == NULL && state == TASK_READY)
    {
        task = idle_tasks[cpu_id];
    }

    spin_unlock(&task_queue_lock);

    return task;
}

void idle_entry(uint64_t arg)
{
    while (1)
    {
        arch_enable_interrupt();
        arch_pause();
    }
}

extern void init_thread(uint64_t);

extern void futex_init();

void task_init()
{
    memset(tasks, 0, sizeof(tasks));
    memset(idle_tasks, 0, sizeof(idle_tasks));

    for (uint64_t cpu = 0; cpu < cpu_count; cpu++)
    {
        task_t *idle_task = task_create("idle", idle_entry, 0, IDLE_PRIORITY);
        idle_task->cpu_id = cpu;
        idle_task->state = TASK_RUNNING;
    }

    arch_set_current(idle_tasks[0]);
    task_create("init", init_thread, 0, NORMAL_PRIORITY);

    task_initialized = true;

    can_schedule = true;
}

uint64_t push_slice(uint64_t ustack, uint8_t *slice, uint64_t len)
{
    uint64_t tmp_stack = ustack;
    tmp_stack -= len;
    tmp_stack -= (tmp_stack % 0x08);

    memcpy((void *)tmp_stack, slice, len);

    return tmp_stack;
}

uint64_t push_infos(task_t *task, uint64_t current_stack, char *argv[], int argv_count, char *envp[], int envp_count, uint64_t e_entry, uint64_t phdr, uint64_t phnum, uint64_t at_base)
{
    uint64_t env_i = 0;
    uint64_t argv_i = 0;

    uint64_t tmp_stack = current_stack;
    tmp_stack = push_slice(tmp_stack, (uint8_t *)task->name, strlen(task->name) + 1);

    uint64_t execfn_ptr = tmp_stack;

    uint64_t *envps = (uint64_t *)malloc((1 + envp_count) * sizeof(uint64_t));
    memset(envps, 0, (1 + envp_count) * sizeof(uint64_t));
    uint64_t *argvps = (uint64_t *)malloc((1 + argv_count) * sizeof(uint64_t));
    memset(argvps, 0, (1 + argv_count) * sizeof(uint64_t));

    if (envp != NULL)
    {
        // push envs
        for (env_i = 0; envp[env_i] != NULL; env_i++)
        {
            tmp_stack = push_slice(tmp_stack, (uint8_t *)envp[env_i], strlen(envp[env_i]) + 1);
            envps[env_i] = tmp_stack;
        }
    }

    if (argv != NULL)
    {
        // push argvs
        for (argv_i = 0; argv[argv_i] != NULL; argv_i++)
        {
            tmp_stack = push_slice(tmp_stack, (uint8_t *)argv[argv_i], strlen(argv[argv_i]) + 1);
            argvps[argv_i] = tmp_stack;
        }
    }

    uint64_t total_length = 2 * sizeof(uint64_t) + 7 * 2 * sizeof(uint64_t) + (env_i + 0) * sizeof(uint64_t) + sizeof(uint64_t) + (argv_i + 0) * sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t);
    tmp_stack -= (tmp_stack - total_length) % 0x10;

    // push auxv
    uint8_t *tmp = (uint8_t *)malloc(2 * sizeof(uint64_t));
    memset(tmp, 0, 2 * sizeof(uint64_t));
    tmp_stack = push_slice(tmp_stack, tmp, 2 * sizeof(uint64_t));

    ((uint64_t *)tmp)[0] = AT_PHDR;
    ((uint64_t *)tmp)[1] = phdr;
    tmp_stack = push_slice(tmp_stack, tmp, 2 * sizeof(uint64_t));

    ((uint64_t *)tmp)[0] = AT_PHENT;
    ((uint64_t *)tmp)[1] = sizeof(Elf64_Phdr);
    tmp_stack = push_slice(tmp_stack, tmp, 2 * sizeof(uint64_t));

    ((uint64_t *)tmp)[0] = AT_PHNUM;
    ((uint64_t *)tmp)[1] = phnum;
    tmp_stack = push_slice(tmp_stack, tmp, 2 * sizeof(uint64_t));

    ((uint64_t *)tmp)[0] = AT_ENTRY;
    ((uint64_t *)tmp)[1] = e_entry;
    tmp_stack = push_slice(tmp_stack, tmp, 2 * sizeof(uint64_t));

    ((uint64_t *)tmp)[0] = AT_EXECFN;
    ((uint64_t *)tmp)[1] = execfn_ptr;
    tmp_stack = push_slice(tmp_stack, tmp, 2 * sizeof(uint64_t));

    ((uint64_t *)tmp)[0] = AT_BASE;
    ((uint64_t *)tmp)[1] = at_base;
    tmp_stack = push_slice(tmp_stack, tmp, 2 * sizeof(uint64_t));

    ((uint64_t *)tmp)[0] = AT_PAGESZ;
    ((uint64_t *)tmp)[1] = DEFAULT_PAGE_SIZE;
    tmp_stack = push_slice(tmp_stack, tmp, 2 * sizeof(uint64_t));

    memset(tmp, 0, 2 * sizeof(uint64_t));

    // push envp
    tmp_stack = push_slice(tmp_stack, tmp, sizeof(uint64_t));
    tmp_stack = push_slice(tmp_stack, (uint8_t *)envps, env_i * sizeof(uint64_t));

    // push argvp
    tmp_stack = push_slice(tmp_stack, tmp, sizeof(uint64_t));
    tmp_stack = push_slice(tmp_stack, (uint8_t *)argvps, argv_i * sizeof(uint64_t));

    tmp_stack = push_slice(tmp_stack, (uint8_t *)&argv_i, sizeof(uint64_t));

    free(tmp);
    free(envps);
    free(argvps);

    return tmp_stack;
}

uint64_t task_fork(struct pt_regs *regs, bool vfork)
{
    arch_disable_interrupt();

    task_t *child = get_free_task();
    if (child == NULL)
    {
        return (uint64_t)-ENOMEM;
    }

    strncpy(child->name, current_task->name, TASK_NAME_MAX);
    child->call_in_signal = current_task->call_in_signal;

    memset(&child->signal_saved_regs, 0, sizeof(struct pt_regs));

    child->cpu_id = alloc_cpu_id();

    child->kernel_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    child->syscall_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    child->signal_syscall_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    child->syscall_stack_user = 0;
    memset((void *)(child->kernel_stack - STACK_SIZE), 0, STACK_SIZE);
    memset((void *)(child->syscall_stack - STACK_SIZE), 0, STACK_SIZE);
    memset((void *)(child->signal_syscall_stack - STACK_SIZE), 0, STACK_SIZE);

    child->arch_context = malloc(sizeof(arch_context_t));
    memset(child->arch_context, 0, sizeof(arch_context_t));
    current_task->arch_context->ctx = regs;
    arch_context_copy(child->arch_context, current_task->arch_context, child->kernel_stack, vfork ? CLONE_VM : 0);
    child->ppid = current_task->pid;
    child->uid = current_task->uid;
    child->gid = current_task->gid;
    child->euid = current_task->euid;
    child->egid = current_task->egid;
    child->ruid = current_task->ruid;
    child->rgid = current_task->rgid;
    child->pgid = current_task->pgid;
    child->sid = current_task->sid;

    child->priority = NORMAL_PRIORITY;
    child->jiffies = current_task->jiffies;

    child->cwd = current_task->cwd;
    child->cmdline = strdup(current_task->cmdline);

    child->mmap_regions = vfork ? current_task->mmap_regions : malloc(sizeof(Bitmap));
    if (vfork)
    {
        child->mmap_regions->bitmap_refcount++;
    }
    else
    {
        void *data = alloc_frames_bytes(bitmap_size);
        bitmap_init(child->mmap_regions, data, bitmap_size);
        memcpy(data, current_task->mmap_regions->buffer, bitmap_size);
    }

    child->load_start = current_task->load_start;
    child->load_end = current_task->load_end;

    child->fd_info = vfork ? current_task->fd_info : malloc(sizeof(fd_info_t));

    if (!vfork)
    {
        memset(child->fd_info, 0, sizeof(fd_info_t));
        memset(child->fd_info->fds, 0, sizeof(child->fd_info->fds));
        // child->fd_info->fds[0] = malloc(sizeof(fd_t));
        // child->fd_info->fds[0]->node = vfs_open("/dev/stdin");
        // child->fd_info->fds[0]->offset = 0;
        // child->fd_info->fds[0]->flags = 0;
        // child->fd_info->fds[1] = malloc(sizeof(fd_t));
        // child->fd_info->fds[1]->node = vfs_open("/dev/stdout");
        // child->fd_info->fds[1]->offset = 0;
        // child->fd_info->fds[1]->flags = 0;
        // child->fd_info->fds[2] = malloc(sizeof(fd_t));
        // child->fd_info->fds[2]->node = vfs_open("/dev/stderr");
        // child->fd_info->fds[2]->offset = 0;
        // child->fd_info->fds[2]->flags = 0;

        for (uint64_t i = 0; i < MAX_FD_NUM; i++)
        {
            fd_t *fd = current_task->fd_info->fds[i];

            if (fd)
            {
                child->fd_info->fds[i] = malloc(sizeof(fd_t));
                memcpy(child->fd_info->fds[i], fd, sizeof(fd_t));
                fd->node->refcount++;
            }
            else
            {
                child->fd_info->fds[i] = NULL;
            }
        }

        child->fd_info->ref_count++;
    }
    else
    {
        child->fd_info->ref_count++;
    }

    child->saved_signal = 0;
    memcpy(child->actions, current_task->actions, sizeof(child->actions));
    child->signal = 0;
    child->blocked = current_task->blocked;

    memcpy(&child->term, &current_task->term, sizeof(termios));

    child->tmp_rec_v = 0;

    memcpy(child->rlim, current_task->rlim, sizeof(child->rlim));

    child->child_vfork_done = false;

    if (vfork)
    {
        child->is_vfork = true;
    }
    else
    {
        child->is_vfork = false;
    }

    procfs_on_new_task(child);

    child->state = TASK_READY;
    child->current_state = TASK_READY;

    if (vfork)
    {
        current_task->child_vfork_done = false;

        while (!current_task->child_vfork_done)
        {
            arch_yield();
        }

        current_task->child_vfork_done = false;
    }

    return child->pid;
}

char interpreter_name_global[256] = {0};

spinlock_t execve_lock = {0};

uint64_t task_execve(const char *path, const char **argv, const char **envp)
{
    arch_disable_interrupt();

    spin_lock(&execve_lock);

    vfs_node_t node = vfs_open(path);
    if (!node)
    {
        spin_unlock(&execve_lock);
        return (uint64_t)-ENOENT;
    }

    uint64_t buf_len = (node->size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    int argv_count = 0;
    int envp_count = 0;

    if (argv && (translate_address(get_current_page_dir(true), (uint64_t)argv) != 0))
    {
        for (argv_count = 0; argv[argv_count] != NULL && (translate_address(get_current_page_dir(true), (uint64_t)argv[argv_count]) != 0); argv_count++)
        {
        }
    }

    if (envp && (translate_address(get_current_page_dir(true), (uint64_t)envp) != 0))
    {
        for (envp_count = 0; envp[envp_count] != NULL && (translate_address(get_current_page_dir(true), (uint64_t)envp[envp_count]) != 0); envp_count++)
        {
        }
    }

    char **new_argv = (char **)malloc((argv_count + 1) * sizeof(char *));
    memset(new_argv, 0, (argv_count + 1) * sizeof(char *));
    char **new_envp = (char **)malloc((envp_count + 1) * sizeof(char *));
    memset(new_envp, 0, (envp_count + 1) * sizeof(char *));

    argv_count = 0;
    envp_count = 0;

    if (argv && (translate_address(get_current_page_dir(true), (uint64_t)argv) != 0))
    {
        for (argv_count = 0; argv[argv_count] != NULL && (translate_address(get_current_page_dir(true), (uint64_t)argv[argv_count]) != 0); argv_count++)
        {
            new_argv[argv_count] = strdup(argv[argv_count]);
        }
    }
    new_argv[argv_count] = NULL;

    if (envp && (translate_address(get_current_page_dir(true), (uint64_t)envp) != 0))
    {
        for (envp_count = 0; envp[envp_count] != NULL && (translate_address(get_current_page_dir(true), (uint64_t)envp[envp_count]) != 0); envp_count++)
        {
            new_envp[envp_count] = strdup(envp[envp_count]);
        }
    }
    new_envp[envp_count] = NULL;

    uint8_t *buffer = (uint8_t *)alloc_frames_bytes(node->size);

    vfs_read(node, buffer, 0, node->size);

    char *fullpath = vfs_get_fullpath(node);

    if (buffer[0] == '#' && buffer[1] == '!')
    {
        for (int i = 0; i < argv_count; i++)
            if (new_argv[i])
                free(new_argv[i]);
        free(new_argv);
        for (int i = 0; i < envp_count; i++)
            if (new_envp[i])
                free(new_envp[i]);
        free(new_envp);

        spin_unlock(&execve_lock);

        char *p = (char *)buffer + 2;
        const char *interpreter_name = NULL;
        while (*p != '\n')
        {
            if (!interpreter_name && *p != ' ')
            {
                interpreter_name = (const char *)p;
            }
            p++;
        }
        *p = '\0';

        if (!interpreter_name)
            return -EINVAL;

        int argc = 0;
        while (argv[argc++])
            ;
        const char *injected_argv[64];
        memcpy((char *)&injected_argv[1], argv, argc * sizeof(char *));
        injected_argv[1] = path;
        strncpy(interpreter_name_global, interpreter_name, sizeof(interpreter_name_global));
        injected_argv[0] = interpreter_name_global;

        free_frames_bytes(buffer, node->size);
        free(fullpath);

        return task_execve((const char *)injected_argv[0], injected_argv, envp);
    }

    current_task->mmap_regions->bitmap_refcount--;
    if (!current_task->mmap_regions->bitmap_refcount)
    {
        free_frames_bytes(current_task->mmap_regions->buffer, bitmap_size);
        free(current_task->mmap_regions);
    }
    current_task->mmap_regions = malloc(sizeof(Bitmap));
    void *data = alloc_frames_bytes(bitmap_size);
    bitmap_init(current_task->mmap_regions, data, bitmap_size);
    memset(current_task->mmap_regions->buffer, 0xff, bitmap_size);

    if (current_task->is_vfork || current_task->arch_context->mm->page_table_addr == (uint64_t)virt_to_phys(get_kernel_page_dir()))
    {
        current_task->arch_context->mm = clone_page_table(current_task->arch_context->mm, 0);
    }

#if defined(__x86_64__)
    asm volatile("movq %0, %%cr3" ::"r"(current_task->arch_context->mm->page_table_addr));
#endif

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)buffer;

    uint64_t e_entry = ehdr->e_entry;

    uint64_t interpreter_entry = 0;

    if (e_entry == 0)
    {
        free_frames_bytes(buffer, node->size);
        free(fullpath);
        for (int i = 0; i < argv_count; i++)
            if (new_argv[i])
                free(new_argv[i]);
        free(new_argv);
        for (int i = 0; i < envp_count; i++)
            if (new_envp[i])
                free(new_envp[i]);
        free(new_envp);
        free(fullpath);
        spin_unlock(&execve_lock);
        return (uint64_t)-EINVAL;
    }

    if (!arch_check_elf(ehdr))
    {
        free_frames_bytes(buffer, node->size);
        free(fullpath);
        for (int i = 0; i < argv_count; i++)
            if (new_argv[i])
                free(new_argv[i]);
        free(new_argv);
        for (int i = 0; i < envp_count; i++)
            if (new_envp[i])
                free(new_envp[i]);
        free(new_envp);
        free(fullpath);
        spin_unlock(&execve_lock);
        return (uint64_t)-ENOEXEC;
    }

    // 处理程序头
    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)buffer + ehdr->e_phoff);

    uint64_t load_start = UINT64_MAX;
    uint64_t load_end = 0;

    for (int i = 0; i < ehdr->e_phnum; ++i)
    {
        if (phdr[i].p_type == PT_INTERP)
        {
            const char *interpreter_name = ((const char *)ehdr + phdr[i].p_offset);

            vfs_node_t interpreter_node = vfs_open(interpreter_name);
            if (!interpreter_node)
            {
                free_frames_bytes(buffer, node->size);
                free(fullpath);
                for (int i = 0; i < argv_count; i++)
                    if (new_argv[i])
                        free(new_argv[i]);
                free(new_argv);
                for (int i = 0; i < envp_count; i++)
                    if (new_envp[i])
                        free(new_envp[i]);
                free(new_envp);
                free(fullpath);
                spin_unlock(&execve_lock);
                return (uint64_t)-ENOENT;
            }

            uint8_t *interpreter_buffer = (uint8_t *)alloc_frames_bytes(interpreter_node->size);

            vfs_read(interpreter_node, interpreter_buffer, 0, interpreter_node->size);

            Elf64_Ehdr *interpreter_ehdr = (Elf64_Ehdr *)interpreter_buffer;
            Elf64_Phdr *interpreter_phdr = (Elf64_Phdr *)(interpreter_buffer + interpreter_ehdr->e_phoff);

            for (int j = 0; j < interpreter_ehdr->e_phnum; j++)
            {
                if (interpreter_phdr[j].p_type != PT_LOAD)
                    continue;

                uint64_t seg_addr = INTERPRETER_BASE_ADDR + interpreter_phdr[j].p_vaddr;
                uint64_t seg_size = interpreter_phdr[j].p_memsz;
                uint64_t file_size = interpreter_phdr[j].p_filesz;
                uint64_t page_size = DEFAULT_PAGE_SIZE;
                uint64_t page_mask = page_size - 1;

                // 计算对齐后的地址和大小
                uint64_t aligned_addr = seg_addr & ~page_mask;
                uint64_t size_diff = seg_addr - aligned_addr;
                uint64_t alloc_size = (seg_size + size_diff + page_mask) & ~page_mask;

                uint64_t flags = PT_FLAG_R | PT_FLAG_U | PT_FLAG_W | PT_FLAG_X;
                map_page_range(get_current_page_dir(true), aligned_addr, 0, alloc_size, flags);
                memcpy((void *)seg_addr, (void *)((char *)interpreter_buffer + interpreter_phdr[j].p_offset), file_size);

                if (seg_size > file_size)
                {
                    uint64_t bss_start = seg_addr + file_size;
                    uint64_t bss_size = seg_size - file_size;
                    memset((void *)bss_start, 0, bss_size);

                    uint64_t page_remain = (bss_size % DEFAULT_PAGE_SIZE);
                    if (page_remain)
                    {
                        uint64_t align_start = bss_start + bss_size - page_remain;
                        memset((void *)align_start, 0, page_remain);
                    }
                }
            }

            interpreter_entry = INTERPRETER_BASE_ADDR + interpreter_ehdr->e_entry;

            free_frames_bytes(interpreter_buffer, node->size);
        }
        else
        {
            if (phdr[i].p_type != PT_LOAD)
                continue;

            uint64_t seg_addr = phdr[i].p_vaddr;
            uint64_t seg_size = phdr[i].p_memsz;
            uint64_t file_size = phdr[i].p_filesz;
            uint64_t page_size = DEFAULT_PAGE_SIZE;
            uint64_t page_mask = page_size - 1;

            // 计算对齐后的地址和大小
            uint64_t aligned_addr = seg_addr & ~page_mask;
            uint64_t size_diff = seg_addr - aligned_addr;
            uint64_t alloc_size = (seg_size + size_diff + page_mask) & ~page_mask;

            if (aligned_addr < load_start)
                load_start = aligned_addr;
            else if (aligned_addr + alloc_size > load_end)
                load_end = aligned_addr + alloc_size;

            uint64_t flags = PT_FLAG_R | PT_FLAG_U | PT_FLAG_W | PT_FLAG_X;
            map_page_range(get_current_page_dir(true), aligned_addr, 0, alloc_size, flags);
            memcpy((void *)seg_addr, (void *)((char *)buffer + phdr[i].p_offset), file_size);

            if (seg_size > file_size)
            {
                uint64_t bss_start = seg_addr + file_size;
                uint64_t bss_size = seg_size - file_size;
                memset((void *)bss_start, 0, bss_size);

                uint64_t page_remain = (bss_size % DEFAULT_PAGE_SIZE);
                if (page_remain)
                {
                    uint64_t align_start = bss_start + bss_size - page_remain;
                    memset((void *)align_start, 0, page_remain);
                }
            }
        }
    }

    strncpy(current_task->name, fullpath, TASK_NAME_MAX);

    free(fullpath);

    current_task->exec_node = node;

    map_page_range(get_current_page_dir(true), USER_STACK_START, 0, USER_STACK_END - USER_STACK_START, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    memset((void *)USER_STACK_START, 0, USER_STACK_END - USER_STACK_START);
    uint64_t stack = push_infos(current_task, USER_STACK_END, (char **)new_argv, argv_count, (char **)new_envp, envp_count, e_entry, (uint64_t)(load_start + ehdr->e_phoff), ehdr->e_phnum, interpreter_entry ? INTERPRETER_BASE_ADDR : load_start);

    free_frames_bytes(buffer, node->size);

    if (current_task->ppid != current_task->pid && tasks[current_task->ppid] && !tasks[current_task->ppid]->child_vfork_done)
    {
        tasks[current_task->ppid]->child_vfork_done = true;
        current_task->is_vfork = false;
    }

    char cmdline[DEFAULT_PAGE_SIZE * 4];
    memset(cmdline, 0, sizeof(cmdline));
    char *cmdline_ptr = cmdline;
    for (int i = 0; i < argv_count; i++)
    {
        int len = sprintf(cmdline_ptr, "%s ", new_argv[i]);
        cmdline_ptr += len;
    }

    for (int i = 0; i < argv_count; i++)
    {
        if (new_argv[i])
        {
            free(new_argv[i]);
        }
    }
    free(new_argv);
    for (int i = 0; i < envp_count; i++)
    {
        if (new_envp[i])
        {
            free(new_envp[i]);
        }
    }
    free(new_envp);

    if (current_task->ppid != current_task->pid && tasks[current_task->ppid] && (tasks[current_task->ppid]->fd_info == current_task->fd_info))
    {
        current_task->fd_info->ref_count--;
        current_task->fd_info = malloc(sizeof(fd_info_t));

        for (uint64_t i = 0; i < MAX_FD_NUM; i++)
        {
            fd_t *fd = tasks[current_task->ppid]->fd_info->fds[i];

            if (fd)
            {
                current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
                memcpy(current_task->fd_info->fds[i], fd, sizeof(fd_t));
                fd->node->refcount++;
            }
            else
            {
                current_task->fd_info->fds[i] = NULL;
            }
        }

        current_task->fd_info->ref_count++;
    }

    for (uint64_t i = 3; i < MAX_FD_NUM; i++)
    {
        if (!current_task->fd_info->fds[i])
            continue;

        if (current_task->fd_info->fds[i]->flags & O_CLOEXEC)
        {
            vfs_close(current_task->fd_info->fds[i]->node);
            free(current_task->fd_info->fds[i]);
            current_task->fd_info->fds[i] = NULL;
        }
    }

    for (int i = 1; i < MAXSIG; i++)
    {
        if (i != SIGCHLD && current_task->actions[i].sa_handler != SIG_IGN)
        {
            memset(&current_task->actions[i], 0, sizeof(sigaction_t));
        }
    }

    current_task->cmdline = strdup(cmdline);
    current_task->load_start = load_start;
    current_task->load_end = load_end;

    spin_unlock(&execve_lock);

    arch_to_user_mode(current_task->arch_context, interpreter_entry ? interpreter_entry : e_entry, stack);

    return (uint64_t)-EAGAIN;
}

void sys_yield()
{
    arch_yield();
}

int task_block(task_t *task, task_state_t state, int timeout_ms)
{
    uint64_t wakeup_ns = timeout_ms * 1000000;

    task->state = state;
    if (timeout_ms > 0)
        task->force_wakeup_ns = nanoTime() + wakeup_ns;
    else
        task->force_wakeup_ns = UINT64_MAX;

    if (current_task == task && state == TASK_BLOCKING)
    {
        arch_yield();
    }

    return task->status;
}

void task_unblock(task_t *task, int reason)
{
    task->status = reason;
    task->state = TASK_READY;
}

void task_exit_inner(task_t *task, int64_t code)
{
    spin_lock(&task_queue_lock);

    task->current_state = TASK_DIED;
    task->state = TASK_DIED;

    arch_context_free(task->arch_context);

    task->status = (uint64_t)code;

    if (task->fd_info)
    {
        task->fd_info->ref_count--;
        if (task->fd_info->ref_count <= 0)
        {
            for (uint64_t i = 0; i < MAX_FD_NUM; i++)
            {
                if (task->fd_info->fds[i])
                {
                    vfs_close(task->fd_info->fds[i]->node);
                    free(task->fd_info->fds[i]);

                    task->fd_info->fds[i] = NULL;
                }
            }
            free(task->fd_info);
        }
    }

    if (task->cmdline)
        free(task->cmdline);

    task->mmap_regions->bitmap_refcount--;
    if (task->mmap_regions->bitmap_refcount == 0)
    {
        free_frames_bytes(task->mmap_regions->buffer, bitmap_size);
        free(task->mmap_regions);
    }

    if (task->ppid != task->pid && tasks[task->ppid] && !tasks[task->ppid]->child_vfork_done)
    {
        tasks[task->ppid]->child_vfork_done = true;
        task->is_vfork = false;
    }

    if (task->ppid && task->pid != task->ppid && task->ppid < MAX_TASK_NUM && tasks[task->ppid])
    {
        // void *handler = tasks[task->ppid]->actions[SIGCHLD].sa_handler;
        // if (!(handler == SIG_DFL || handler == SIG_IGN))
        // {
        //     tasks[task->ppid]->signal |= SIGMASK(SIGCHLD);
        // }
    }

    if (task->waitpid != 0 && task->waitpid < MAX_TASK_NUM && tasks[task->waitpid] && tasks[task->waitpid]->state == TASK_BLOCKING)
    {
        task_unblock(tasks[task->waitpid], EOK);
    }

    procfs_on_exit_task(task);

    spin_unlock(&task_queue_lock);
}

uint64_t task_exit(int64_t code)
{
    arch_disable_interrupt();

    can_schedule = false;

    // spin_lock(&task_queue_lock);
    // uint64_t continue_ptr_count = 0;
    // for (int i = 0; i < MAX_TASK_NUM; i++)
    // {
    //     if (!tasks[i])
    //     {
    //         continue_ptr_count++;
    //         if (continue_ptr_count >= MAX_CONTINUE_NULL_TASKS)
    //             break;
    //         continue;
    //     }
    //     continue_ptr_count = 0;
    //     if ((tasks[i]->ppid != tasks[i]->pid) && (tasks[i]->ppid == current_task->pid))
    //     {
    //         task_exit_inner(tasks[i], SIGCHLD);

    //         free_page_table(tasks[i]->arch_context->mm);

    //         free(tasks[i]->arch_context);

    //         free_frames_bytes((void *)(tasks[i]->kernel_stack - STACK_SIZE), STACK_SIZE);
    //         free_frames_bytes((void *)(tasks[i]->syscall_stack - STACK_SIZE), STACK_SIZE);
    //         free_frames_bytes((void *)(tasks[i]->signal_syscall_stack - STACK_SIZE), STACK_SIZE);

    //         free(tasks[i]);

    //         tasks[i] = NULL;
    //     }
    // }
    // spin_unlock(&task_queue_lock);

    task_exit_inner(current_task, code);

    can_schedule = true;

    task_t *next = task_search(TASK_READY, current_task->cpu_id);

    if (next)
    {
        arch_set_current(next);
        arch_switch_with_context(NULL, next->arch_context, next->kernel_stack);
    }
    else
    {
        arch_set_current(idle_tasks[current_cpu_id]);
        arch_switch_with_context(NULL, idle_tasks[current_cpu_id]->arch_context, idle_tasks[current_cpu_id]->kernel_stack);
    }

    // never return !!!

    return (uint64_t)-EAGAIN;
}

uint64_t sys_waitpid(uint64_t pid, int *status, uint64_t options)
{
    arch_disable_interrupt();
    task_t *target = NULL;
    uint64_t ret = -ECHILD;

    // First check if we have any children at all
    bool has_children = false;
    for (uint64_t i = 1; i < MAX_TASK_NUM; i++)
    {
        spin_lock(&task_queue_lock);
        task_t *ptr = tasks[i];
        spin_unlock(&task_queue_lock);
        if (ptr && ptr->ppid == current_task->pid)
        {
            has_children = true;
            break;
        }
    }

    if (!has_children)
    {
        return -ECHILD;
    }

    while (1)
    {
        task_t *found_alive = NULL;
        task_t *found_dead = NULL;

        uint64_t continue_ptr_count = 0;
        for (uint64_t i = 1; i < MAX_TASK_NUM; i++)
        {
            spin_lock(&task_queue_lock);
            task_t *ptr = tasks[i];
            spin_unlock(&task_queue_lock);

            if (ptr == NULL)
            {
                continue_ptr_count++;
                if (continue_ptr_count >= MAX_CONTINUE_NULL_TASKS)
                    break;
                continue;
            }
            continue_ptr_count = 0;

            if (ptr->ppid != current_task->pid)
                continue;

            if ((int64_t)pid > 0)
            {
                if (ptr->pid != pid)
                    continue;
            }
            else if (pid == 0)
            {
                if (ptr->pgid != current_task->pgid)
                    continue;
            }
            else if (pid != (uint64_t)-1)
            {
                continue;
            }

            if (ptr->state == TASK_DIED)
            {
                found_dead = ptr;
                break;
            }
            else
            {
                found_alive = ptr;
            }
        }

        if (found_dead)
        {
            target = found_dead;
            break;
        }

        if (found_alive && (options & WNOHANG))
        {
            return 0;
        }

        if (found_alive)
        {
            found_alive->waitpid = current_task->pid;
            task_block(current_task, TASK_BLOCKING, -1);
            continue;
        }

        return -ECHILD;
    }

    if (target)
    {
        if (status)
        {
            if (target->status < 128)
            {
                *status = (target->status & 0xff) << 8;
            }
            else
            {
                int sig = target->status - 128;
                *status = (sig & 0xff);
            }
        }

        ret = target->pid;

        spin_lock(&task_queue_lock);
        tasks[target->pid] = NULL;
        spin_unlock(&task_queue_lock);

        free_page_table(target->arch_context->mm);

        arch_context_free(target->arch_context);

        free(target->arch_context);

        free_frames_bytes((void *)(target->kernel_stack - STACK_SIZE), STACK_SIZE);
        free_frames_bytes((void *)(target->syscall_stack - STACK_SIZE), STACK_SIZE);
        free_frames_bytes((void *)(target->signal_syscall_stack - STACK_SIZE), STACK_SIZE);

        free(target);
    }

    return ret;
}

uint64_t sys_clone(struct pt_regs *regs, uint64_t flags, uint64_t newsp, int *parent_tid, int *child_tid, uint64_t tls)
{
    arch_disable_interrupt();

    task_t *child = get_free_task();
    if (child == NULL)
    {
        return (uint64_t)-ENOMEM;
    }

    strncpy(child->name, current_task->name, TASK_NAME_MAX);
    child->call_in_signal = current_task->call_in_signal;

    memset(&child->signal_saved_regs, 0, sizeof(struct pt_regs));

    child->cpu_id = alloc_cpu_id();

    child->kernel_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    child->syscall_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    child->signal_syscall_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    child->syscall_stack_user = 0;
    memset((void *)(child->kernel_stack - STACK_SIZE), 0, STACK_SIZE);
    memset((void *)(child->syscall_stack - STACK_SIZE), 0, STACK_SIZE);
    memset((void *)(child->signal_syscall_stack - STACK_SIZE), 0, STACK_SIZE);

    child->arch_context = malloc(sizeof(arch_context_t));
    memset(child->arch_context, 0, sizeof(arch_context_t));
    current_task->arch_context->ctx = regs;
    arch_context_copy(child->arch_context, current_task->arch_context, child->kernel_stack, flags);
#if defined(__x86_64__)
    if (newsp)
        child->arch_context->ctx->rsp = newsp;
#endif
    child->ppid = current_task->pid;
    child->uid = current_task->uid;
    child->gid = current_task->gid;
    child->euid = current_task->euid;
    child->egid = current_task->egid;
    child->ruid = current_task->ruid;
    child->rgid = current_task->rgid;
    child->pgid = current_task->pgid;
    child->sid = current_task->sid;

    child->priority = NORMAL_PRIORITY;
    child->jiffies = current_task->jiffies;

    child->cwd = current_task->cwd;
    child->cmdline = strdup(current_task->cmdline);

    child->mmap_regions = (flags & CLONE_VM) ? current_task->mmap_regions : malloc(sizeof(Bitmap));
    if (flags & CLONE_VM)
    {
        child->mmap_regions->bitmap_refcount++;
    }
    else
    {
        void *data = alloc_frames_bytes(bitmap_size);
        bitmap_init(child->mmap_regions, data, bitmap_size);
        memcpy(data, current_task->mmap_regions->buffer, bitmap_size);
    }
    child->load_start = current_task->load_start;
    child->load_end = current_task->load_end;

    child->fd_info = (flags & CLONE_FILES) ? current_task->fd_info : malloc(sizeof(fd_info_t));

    if (!(flags & CLONE_FILES))
    {
        memset(child->fd_info, 0, sizeof(fd_info_t));
        memset(child->fd_info->fds, 0, sizeof(child->fd_info->fds));
        // child->fd_info->fds[0] = malloc(sizeof(fd_t));
        // child->fd_info->fds[0]->node = vfs_open("/dev/stdin");
        // child->fd_info->fds[0]->offset = 0;
        // child->fd_info->fds[0]->flags = 0;
        // child->fd_info->fds[1] = malloc(sizeof(fd_t));
        // child->fd_info->fds[1]->node = vfs_open("/dev/stdout");
        // child->fd_info->fds[1]->offset = 0;
        // child->fd_info->fds[1]->flags = 0;
        // child->fd_info->fds[2] = malloc(sizeof(fd_t));
        // child->fd_info->fds[2]->node = vfs_open("/dev/stderr");
        // child->fd_info->fds[2]->offset = 0;
        // child->fd_info->fds[2]->flags = 0;

        for (uint64_t i = 0; i < MAX_FD_NUM; i++)
        {
            fd_t *fd = current_task->fd_info->fds[i];

            if (fd)
            {
                child->fd_info->fds[i] = malloc(sizeof(fd_t));
                memcpy(child->fd_info->fds[i], fd, sizeof(fd_t));
                fd->node->refcount++;
            }
            else
            {
                child->fd_info->fds[i] = NULL;
            }
        }

        child->fd_info->ref_count++;
    }
    else
    {
        child->fd_info->ref_count++;
    }

    memcpy(&child->term, &current_task->term, sizeof(termios));

    child->saved_signal = 0;
    memcpy(child->actions, current_task->actions, sizeof(child->actions));
    child->signal = 0;
    child->blocked = current_task->blocked;

    if (flags & CLONE_SETTLS)
    {
#if defined(__x86_64__)
        child->arch_context->fsbase = tls;
#endif
    }

    if (parent_tid && (flags & CLONE_PARENT_SETTID))
    {
        *parent_tid = (int)current_task->pid;
    }

    if (child_tid && (flags & CLONE_CHILD_SETTID))
    {
        *child_tid = (int)child->pid;
    }

    child->tmp_rec_v = 0;

    memcpy(child->rlim, current_task->rlim, sizeof(child->rlim));

    child->child_vfork_done = false;

    if ((flags & CLONE_VM))
    {
        child->is_vfork = true;
    }
    else
    {
        child->is_vfork = false;
    }

    procfs_on_new_task(child);

    child->state = TASK_READY;
    child->current_state = TASK_READY;

    if ((flags & CLONE_VFORK))
    {
        current_task->child_vfork_done = false;

        while (!current_task->child_vfork_done)
        {
            arch_yield();
        }

        current_task->child_vfork_done = false;
    }

    return child->pid;
}

uint64_t sys_nanosleep(struct timespec *req, struct timespec *rem)
{
    if (req->tv_sec < 0)
        return (uint64_t)-EINVAL;

    if (req->tv_sec < 0 || req->tv_nsec >= 1000000000L)
    {
        return (uint64_t)-EINVAL;
    }

    uint64_t start = nanoTime();
    uint64_t target = start + (req->tv_sec * 1000000000ULL) + req->tv_nsec;

    do
    {
        if (signals_pending_quick(current_task))
        {
            if (rem)
            {
                uint64_t remaining = target - nanoTime();
                struct timespec remain_ts = {
                    .tv_sec = remaining / 1000000000,
                    .tv_nsec = remaining % 1000000000};
                memcpy(rem, &remain_ts, sizeof(struct timespec));
            }
            return (uint64_t)-EINTR;
        }

        arch_yield();
    } while (target > nanoTime());

    return 0;
}

uint64_t sys_prctl(uint64_t option, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
    switch (option)
    {
    case PR_SET_NAME: // 设置进程名 (PR_SET_NAME=15)
        strncpy(current_task->name, (char *)arg2, TASK_NAME_MAX);
        return 0;

    case PR_GET_NAME: // 获取进程名 (PR_GET_NAME=16)
        strncpy((char *)arg2, current_task->name, TASK_NAME_MAX);
        return 0;

    case PR_SET_SECCOMP: // 启用seccomp过滤
        if (arg2 == SECCOMP_MODE_STRICT)
        {
            // current_task->seccomp_mode = SECCOMP_MODE_STRICT;
            return 0;
        }
        return -EINVAL;

    case PR_GET_SECCOMP: // 查询seccomp状态
        // return current_task->seccomp_mode;
        return 0;

    case PR_SET_TIMERSLACK:
        current_task->timer_slack_ns = arg2;
        return 0;

    default:
        return -ENOSYS; // 未实现的功能返回不支持
    }
}

void ms_to_timeval(uint64_t ms, struct timeval *tv)
{
    tv->tv_sec = ms / 1000;
    tv->tv_usec = (ms % 1000) * 1000; // 转换为微秒保持结构体定义
}

uint64_t timeval_to_ms(struct timeval tv)
{
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000; // 微秒转毫秒
}

void sched_update_itimer()
{
    uint64_t rtAt = current_task->itimer_real.at;
    uint64_t rtReset = current_task->itimer_real.reset;

    tm time_now;
    time_read(&time_now);

    uint64_t now = mktime(&time_now) * 1000;

    if (rtAt && rtAt <= now)
    {
        spin_lock(&current_task->signal_lock);
        current_task->signal |= SIGMASK(SIGALRM);
        spin_unlock(&current_task->signal_lock);

        if (rtReset)
        {
            current_task->itimer_real.at = now + rtReset;
        }
        else
        {
            current_task->itimer_real.at = 0;
        }
    }

    for (int j = 0; j < MAX_TIMERS_NUM; j++)
    {
        if (current_task->timers[j] == NULL)
            break;
        kernel_timer_t *kt = current_task->timers[j];
        if (kt->expires && now >= kt->expires)
        {
            spin_lock(&current_task->signal_lock);
            current_task->signal |= SIGMASK(kt->sigev_signo);
            spin_unlock(&current_task->signal_lock);

            if (kt->interval)
                kt->expires += kt->interval;
            else
                kt->expires = 0;
        }
    }
}

extern int timerfdfs_id;

void sched_update_timerfd()
{
    if (current_task->fd_info)
    {
        uint64_t continue_null_fd_count = 0;

        for (int fd = 3; fd < MAX_FD_NUM; fd++)
        {
            if (current_task->fd_info->fds[fd] == NULL)
            {
                continue_null_fd_count++;
                if (continue_null_fd_count >= 5)
                    break;
                continue;
            }

            continue_null_fd_count = 0;

            if (current_task->fd_info->fds[fd] && current_task->fd_info->fds[fd]->node->fsid == timerfdfs_id)
            {
                timerfd_t *tfd = current_task->fd_info->fds[fd]->node->handle;

                // 根据时钟类型获取当前时间
                uint64_t now;
                if (tfd->timer.clock_type == CLOCK_MONOTONIC)
                {
                    now = nanoTime();
                }
                else // CLOCK_REALTIME
                {
                    tm time;
                    time_read(&time);
                    now = (uint64_t)mktime(&time) * 1000000000ULL + nanoTime() % 1000000000ULL;
                }

                if (tfd->timer.expires && now >= tfd->timer.expires)
                {
                    if (tfd->timer.interval)
                    {
                        uint64_t delta = now - tfd->timer.expires;
                        uint64_t periods = delta / tfd->timer.interval + 1;
                        tfd->count += periods;
                        tfd->timer.expires += periods * tfd->timer.interval;
                    }
                    else
                    {
                        tfd->count++;
                        tfd->timer.expires = 0;
                    }
                }
            }
        }
    }
}

void sched_check_wakeup()
{
    uint64_t continue_ptr_count = 0;
    for (size_t i = 1; i < MAX_TASK_NUM; i++)
    {
        task_t *ptr = tasks[i];
        if (ptr == NULL)
        {
            continue_ptr_count++;
            if (continue_ptr_count >= MAX_CONTINUE_NULL_TASKS)
                break;
            continue;
        }
        continue_ptr_count = 0;

        if (ptr->state == TASK_BLOCKING && nanoTime() > ptr->force_wakeup_ns)
        {
            task_unblock(ptr, ETIMEDOUT);
        }
    }
}

size_t sys_setitimer(int which, struct itimerval *value, struct itimerval *old)
{
    if (which != 0)
        return (size_t)-ENOSYS;

    uint64_t rt_at = current_task->itimer_real.at;
    uint64_t rt_reset = current_task->itimer_real.reset;

    tm time_now;
    time_read(&time_now);
    uint64_t now = mktime(&time_now) * 1000;

    if (old)
    {
        uint64_t remaining = rt_at > now ? rt_at - now : 0;
        ms_to_timeval(remaining, &old->it_value);
        ms_to_timeval(rt_reset, &old->it_interval);
    }

    if (value)
    {
        uint64_t targValue = value->it_value.tv_sec * 1000 + value->it_value.tv_usec / 1000;
        uint64_t targInterval = value->it_interval.tv_sec * 1000 + value->it_interval.tv_usec / 1000;

        current_task->itimer_real.at = targValue ? (now + targValue) : 0ULL;
        current_task->itimer_real.reset = targInterval;
    }

    return 0;
}

int sys_timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid)
{
    kernel_timer_t *kt = NULL;
    uint64_t i;
    for (i = 0; i < MAX_TIMERS_NUM; i++)
    {
        if (current_task->timers[i] == NULL)
        {
            kt = malloc(sizeof(kernel_timer_t));
            current_task->timers[i] = kt;
            break;
        }
    }

    if (!kt)
        return -ENOMEM;

    memset(kt, 0, sizeof(kernel_timer_t));

    kt->clock_type = clockid;
    kt->sigev_notify = SIGEV_SIGNAL;

    if (sevp)
    {
        struct sigevent ksev;
        memcpy(&ksev, sevp, sizeof(struct sigevent));

        kt->sigev_signo = ksev.sigev_signo;
        kt->sigev_value = ksev.sigev_value;
        kt->sigev_notify = ksev.sigev_notify;
    }

    *timerid = (timer_t)i;

    return 0;
}

int sys_timer_settime(timer_t timerid, const struct itimerval *new_value, struct itimerval *old_value)
{
    uint64_t idx = (uint64_t)timerid;
    if (idx >= MAX_TIMERS_NUM)
        return -EINVAL;

    kernel_timer_t *kt = current_task->timers[idx];

    struct itimerval kts;
    memcpy(&kts, new_value, sizeof(*new_value));

    uint64_t interval = new_value->it_interval.tv_sec * 1000 + new_value->it_interval.tv_usec / 1000;
    uint64_t expires = new_value->it_value.tv_sec * 1000 + new_value->it_value.tv_usec / 1000;

    tm time_now;
    time_read(&time_now);

    uint64_t now = mktime(&time_now) * 1000;

    if (old_value)
    {
        struct itimerval old;
        old.it_interval.tv_sec = kt->interval / 1000;
        old.it_interval.tv_usec = (kt->interval % 1000) * 1000000;
        old.it_value.tv_sec = (kt->expires - now) / 1000;
        old.it_value.tv_usec = ((kt->expires - now) % 1000) * 1000000;
        memcpy(old_value, &old, sizeof(old));
    }

    kt->interval = interval;
    kt->expires = now + expires;

    return 0;
}

#define LINUX_REBOOT_MAGIC1 0xfee1dead
#define LINUX_REBOOT_MAGIC2 672274793
#define LINUX_REBOOT_MAGIC2A 85072278
#define LINUX_REBOOT_MAGIC2B 369367448
#define LINUX_REBOOT_MAGIC2C 537993216

#define LINUX_REBOOT_CMD_RESTART 0x01234567
#define LINUX_REBOOT_CMD_HALT 0xCDEF0123
#define LINUX_REBOOT_CMD_CAD_ON 0x89ABCDEF
#define LINUX_REBOOT_CMD_CAD_OFF 0x00000000
#define LINUX_REBOOT_CMD_POWER_OFF 0x4321FEDC
#define LINUX_REBOOT_CMD_RESTART2 0xA1B2C3D4
#define LINUX_REBOOT_CMD_SW_SUSPEND 0xD000FCE2
#define LINUX_REBOOT_CMD_KEXEC 0x45584543

bool cad_enabled = true;

uint64_t sys_reboot(int magic1, int magic2, uint32_t cmd, void *arg)
{
    if (magic1 != LINUX_REBOOT_MAGIC1 || magic2 != LINUX_REBOOT_MAGIC2)
        return (uint64_t)-EINVAL;

    switch (cmd)
    {
    case LINUX_REBOOT_CMD_CAD_OFF:
        cad_enabled = false;
        return 0;
    case LINUX_REBOOT_CMD_CAD_ON:
        cad_enabled = true;
        return 0;
    default:
        return (uint64_t)-EINVAL;
        break;
    }
}

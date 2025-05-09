#include <arch/arch.h>
#include <task/task.h>
#include <drivers/kernel_logger.h>
#include <fs/vfs/vfs.h>
#include <arch/arch.h>
#include <mm/mm.h>
#include <fs/fs_syscall.h>

task_t *tasks[MAX_TASK_NUM];
task_t *idle_tasks[MAX_CPU_NUM];

bool task_initialized = false;
bool can_schedule = false;

task_t *get_free_task()
{
    for (uint64_t i = 0; i < MAX_TASK_NUM; i++)
    {
        if (tasks[i] == NULL)
        {
            tasks[i] = (task_t *)phys_to_virt(alloc_frames(1));
            memset(tasks[i], 0, DEFAULT_PAGE_SIZE);
            tasks[i]->pid = i;
            return tasks[i];
        }
    }

    return NULL;
}

uint32_t cpu_idx = 0;

uint32_t alloc_cpu_id()
{
    uint32_t idx = cpu_idx;
    cpu_idx = (cpu_idx + 1) % cpu_count;
    return idx;
}

task_t *task_create(const char *name, void (*entry)())
{
    can_schedule = false;

    task_t *task = get_free_task();
    task->cpu_id = alloc_cpu_id();
    task->ppid = task->pid;
    task->uid = 0;
    task->gid = 0;
    task->euid = 0;
    task->egid = 0;
    task->pgid = 0;
    task->waitpid = 0;
    task->state = TASK_READY;
    task->jiffies = 0;
    task->kernel_stack = phys_to_virt((uint64_t)alloc_frames(STACK_SIZE / DEFAULT_PAGE_SIZE)) + STACK_SIZE;
    task->syscall_stack = phys_to_virt((uint64_t)alloc_frames(STACK_SIZE / DEFAULT_PAGE_SIZE)) + STACK_SIZE;
    task->arch_context = malloc(sizeof(arch_context_t));
    arch_context_init(task->arch_context, virt_to_phys((uint64_t)get_kernel_page_dir()), (uint64_t)entry, task->kernel_stack, false);
    task->signal = 0;
    task->status = 0;
    task->cwd = rootdir;
    task->mmap_start = USER_MMAP_START;
    task->brk_start = USER_BRK_START;
    task->brk_end = USER_BRK_START;
    memset(task->actions, 0, sizeof(task->actions));
    task->fds[0] = vfs_open("/dev/stdin");
    task->fds[1] = vfs_open("/dev/stdout");
    task->fds[2] = vfs_open("/dev/stderr");
    strncpy(task->name, name, TASK_NAME_MAX);

    can_schedule = true;

    return task;
}

task_t *task_search(task_state_t state, uint32_t cpu_id)
{
    task_t *task = NULL;

    for (size_t i = cpu_count; i < MAX_TASK_NUM; i++)
    {
        task_t *ptr = tasks[i];
        if (ptr == NULL)
            continue;
        if (current_task == ptr)
            continue;
        if (ptr->state != state)
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

    return task;
}

void idle_entry()
{
    while (1)
    {
        arch_pause();
    }
}

#include <drivers/bus/pci.h>
#include <drivers/block/ahci/ahci.h>
#include <drivers/block/nvme/nvme.h>
#include <drivers/usb/xhci.h>
#include <drivers/virtio/virtio.h>
#include <fs/partition.h>
#include <drivers/fb.h>

extern void fatfs_init();
extern void iso9660_init();
extern void epoll_init();
extern void pipefs_init();
extern void socketfs_init();

extern void mount_root();

bool system_initialized = false;

void init_thread()
{
    printk("NAOS init thread is running...\n");

    pci_init();
#if defined(__x86_64__)
    ahci_init();
#endif
    nvme_init();

    xhci_init();

    virtio_init();

    partition_init();
    fbdev_init();

    epoll_init();
    pipefs_init();
    socketfs_init();
    iso9660_init();
    fatfs_init();

    mount_root();

    arch_input_dev_init();

    system_initialized = true;

    task_execve("/bin/bash", NULL, NULL);

    printk("run /bin/bash failed\n");

    while (1)
    {
        arch_pause();
    }
}

void task_init()
{
    memset(tasks, 0, sizeof(tasks));
    memset(idle_tasks, 0, sizeof(idle_tasks));

    for (uint64_t cpu = 0; cpu < cpu_count; cpu++)
    {
        idle_tasks[cpu] = task_create("idle", idle_entry);
        idle_tasks[cpu]->state = TASK_RUNNING;
    }
    arch_set_current(idle_tasks[0]);
    task_create("init", init_thread);

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

uint64_t push_infos(task_t *task, uint64_t current_stack, char *argv[], char *envp[], uint64_t e_entry, uint64_t phdr, uint64_t phnum, uint64_t at_base)
{
    uint64_t env_i = 0;
    uint64_t argv_i = 0;

    uint64_t tmp_stack = current_stack;
    tmp_stack = push_slice(tmp_stack, (uint8_t *)task->name, strlen(task->name) + 1);

    uint64_t execfn_ptr = tmp_stack;

    uint64_t *envps = (uint64_t *)malloc(512);
    memset(envps, 0, 512);
    uint64_t *argvps = (uint64_t *)malloc(512);
    memset(argvps, 0, 512);

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

    uint64_t total_length = 2 * sizeof(uint64_t) + 7 * 2 * sizeof(uint64_t) + env_i * sizeof(uint64_t) + sizeof(uint64_t) + argv_i * sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint64_t);
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

uint64_t task_fork(struct pt_regs *regs)
{
    arch_disable_interrupt();

    can_schedule = false;

    task_t *child = get_free_task();
    if (child == NULL)
    {
        return (uint64_t)-ENOMEM;
    }

    strncpy(child->name, current_task->name, TASK_NAME_MAX);

    child->state = TASK_READY;

    child->cpu_id = alloc_cpu_id();

    child->kernel_stack = phys_to_virt((uint64_t)alloc_frames(STACK_SIZE / DEFAULT_PAGE_SIZE)) + STACK_SIZE;
    child->syscall_stack = phys_to_virt((uint64_t)alloc_frames(STACK_SIZE / DEFAULT_PAGE_SIZE)) + STACK_SIZE;

    child->arch_context = malloc(sizeof(arch_context_t));
    memset(child->arch_context, 0, sizeof(arch_context_t));
    current_task->arch_context->ctx = regs;
    arch_context_copy(child->arch_context, current_task->arch_context, child->kernel_stack);
    child->ppid = current_task->pid;
    child->uid = current_task->uid;
    child->gid = current_task->gid;
    child->euid = current_task->euid;
    child->egid = current_task->egid;
    child->pgid = current_task->pgid;

    child->jiffies = current_task->jiffies;

    child->cwd = current_task->cwd;

    child->mmap_start = USER_MMAP_START;
    child->brk_start = USER_BRK_START;
    child->brk_end = USER_BRK_START;

    memcpy(child->fds, current_task->fds, sizeof(child->fds));
    for (uint64_t i = 3; i < MAX_FD_NUM; i++)
    {
        if (child->fds[i] && child->fds[i]->type == file_pipe && child->fds[i]->handle)
        {
            pipe_t *pipe = child->fds[i]->handle;
            pipe->reference_count++;
        }
    }

    can_schedule = true;

    arch_enable_interrupt();

    return child->pid;
}

uint64_t task_execve(const char *path, const char **argv, const char **envp)
{
    arch_disable_interrupt();

    can_schedule = false;

    vfs_node_t node = vfs_open(path);
    if (!node)
    {
        can_schedule = true;
        return (uint64_t)-ENOENT;
    }

    char buf[32];
    ssize_t max = vfs_read(node, buf, 0, sizeof(buf));

    uint64_t buf_len = (node->size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));

    char **new_argv = (char **)malloc(512);
    char **new_envp = (char **)malloc(512);

    int argv_count = 0;
    int envp_count = 0;

    if (argv)
    {
        for (argv_count = 0; argv[argv_count] != NULL; argv_count++)
        {
            new_argv[argv_count] = strdup(argv[argv_count]);
        }
    }
    new_argv[argv_count] = NULL;

    if (envp)
    {
        for (envp_count = 0; envp[envp_count] != NULL; envp_count++)
        {
            new_envp[envp_count] = strdup(envp[envp_count]);
        }
    }
    new_envp[envp_count] = NULL;

    // if (max > 2 && buf[0] == '#' && buf[1] == '!')
    // {
    //     vfs_close(node);
    //     node = vfs_open("/bin/bash");
    //     buf_len = (node->size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1));
    //     memmove(new_argv + 1, new_argv, argv_count);
    //     new_argv[0] = path;
    // }

#if defined(__x86_64__)
    uint64_t new_page_table = clone_page_table(virt_to_phys((uint64_t)get_kernel_page_dir()), USER_STACK_START, USER_STACK_END);
    __asm__ __volatile__("movq %0, %%cr3" ::"r"(new_page_table));
#endif

    uint8_t *buffer = (uint8_t *)EHDR_START_ADDR;
    map_page_range(get_current_page_dir(true), EHDR_START_ADDR, 0, buf_len, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    vfs_read(node, buffer, 0, node->size);

    memset(buffer + node->size, 0, buf_len - node->size);

    char *fullpath = vfs_get_fullpath(node);

    vfs_close(node);

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)EHDR_START_ADDR;

    uint64_t e_entry = ehdr->e_entry;

    uint64_t interpreter_entry = 0;

    if (e_entry == 0)
    {
        free(fullpath);
#if defined(__x86_64__)
        __asm__ __volatile__("movq %0, %%cr3" ::"r"(current_task->arch_context->cr3));
#endif
        free_page_table(new_page_table);
        for (int i = 0; i < argv_count; i++)
            if (new_argv[i])
                free(new_argv[i]);
        free(new_argv);
        for (int i = 0; i < envp_count; i++)
            if (new_envp[i])
                free(new_envp[i]);
        free(new_envp);
        can_schedule = true;
        return -EINVAL;
    }

    if (!arch_check_elf(ehdr))
    {
        free(fullpath);
#if defined(__x86_64__)
        __asm__ __volatile__("movq %0, %%cr3" ::"r"(current_task->arch_context->cr3));
#endif
        free_page_table(new_page_table);
        for (int i = 0; i < argv_count; i++)
            if (new_argv[i])
                free(new_argv[i]);
        free(new_argv);
        for (int i = 0; i < envp_count; i++)
            if (new_envp[i])
                free(new_envp[i]);
        free(new_envp);
        can_schedule = true;
        return (uint64_t)-EINVAL;
    }

    // 处理程序头
    Elf64_Phdr *phdr = (Elf64_Phdr *)(EHDR_START_ADDR + ehdr->e_phoff);

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
                can_schedule = true;
                return (uint64_t)-ENOENT;
            }

            uint8_t *interpreter_buffer = (uint8_t *)INTERPRETER_EHDR_ADDR;
            map_page_range(get_current_page_dir(true), INTERPRETER_EHDR_ADDR, 0, (interpreter_node->size + DEFAULT_PAGE_SIZE - 1) & (~(DEFAULT_PAGE_SIZE - 1)), PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

            vfs_read(interpreter_node, interpreter_buffer, 0, interpreter_node->size);

            vfs_close(interpreter_node);

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

                memcpy((void *)seg_addr, (void *)(INTERPRETER_EHDR_ADDR + interpreter_phdr[j].p_offset), file_size);

                if (seg_size > file_size)
                {
                    memset((char *)seg_addr + file_size,
                           0, seg_size - file_size);
                }
            }

            interpreter_entry = INTERPRETER_BASE_ADDR + interpreter_ehdr->e_entry;
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

            memcpy((void *)seg_addr, (void *)(EHDR_START_ADDR + phdr[i].p_offset), file_size);

            if (seg_size > file_size)
            {
                memset((char *)seg_addr + file_size,
                       0, seg_size - file_size);
            }
        }
    }

    strncpy(current_task->name, fullpath, TASK_NAME_MAX);
    free(fullpath);

    map_page_range(get_current_page_dir(true), USER_STACK_START, 0, USER_STACK_END - USER_STACK_START, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);
    memset((void *)USER_STACK_START, 0, USER_STACK_END - USER_STACK_START);

#if defined(__x86_64__)
    current_task->arch_context->cr3 = new_page_table;
    __asm__ __volatile__("movq %0, %%cr3" ::"r"(current_task->arch_context->cr3));
#endif

    uint64_t stack = push_infos(current_task, USER_STACK_END, (char **)new_argv, (char **)new_envp, e_entry, (uint64_t)(load_start + ehdr->e_phoff), ehdr->e_phnum, interpreter_entry ? INTERPRETER_BASE_ADDR : load_start);
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
    can_schedule = true;
    arch_to_user_mode(current_task->arch_context, interpreter_entry ? interpreter_entry : e_entry, stack);

    return (uint64_t)-EAGAIN;
}

void sys_yield()
{
    arch_yield();
}

int task_block(task_t *task, task_state_t state, int timeout_ms)
{
    (void)timeout_ms;

    task->state = state;

    if (current_task == task)
    {
        arch_enable_interrupt();

        arch_yield();

        arch_pause();
    }

    return task->status;
}

void task_unblock(task_t *task, int reason)
{
    task->status = reason;
    task->state = TASK_READY;
}

uint64_t task_exit(int64_t code)
{
    arch_disable_interrupt();

    task_t *task = current_task;

    arch_context_free(task->arch_context);

    free(task->arch_context);

    free_frames(task->kernel_stack, STACK_SIZE / DEFAULT_PAGE_SIZE);
    free_frames(task->syscall_stack, STACK_SIZE / DEFAULT_PAGE_SIZE);

    task->status = (uint64_t)code;

    task_t *next = task_search(TASK_READY, task->cpu_id);

    task->state = TASK_DIED;

    task->ppid = 0;

    for (uint64_t i = 0; i < MAX_FD_NUM; i++)
    {
        if (current_task->fds[i])
        {
            vfs_close(current_task->fds[i]);
        }
    }

    if (task->waitpid != 0)
    {
        task_unblock(tasks[task->waitpid], EOK);
    }

    arch_set_current(next);

    arch_switch_with_context(NULL, next->arch_context, next->kernel_stack);

    return (uint64_t)-EAGAIN;
}

uint64_t sys_waitpid(uint64_t pid, int *status)
{
    task_t *child = NULL;

    uint64_t child_pid = 0;

    while (1)
    {
        bool has_child = false;

        if (pid == (uint64_t)-1)
        {
            for (uint64_t i = cpu_count; i < MAX_TASK_NUM; i++)
            {
                task_t *ptr = tasks[i];
                if (ptr && ptr->ppid != ptr->pid && ptr->ppid == current_task->pid)
                {
                    child_pid = ptr->pid;
                    has_child = true;
                    break;
                }
            }

            if (has_child)
            {
                arch_enable_interrupt();

                arch_yield();

                arch_pause();
            }
            else
            {
                *status = 0;
                return child_pid;
            }

            continue;
        }

        for (uint64_t i = cpu_count; i < MAX_TASK_NUM; i++)
        {
            task_t *ptr = tasks[i];
            if (ptr == NULL)
                continue;

            if (ptr->ppid != current_task->pid)
                continue;

            if (pid != ptr->pid && pid != 0)
                continue;

            if (ptr->state == TASK_DIED)
            {
                child = ptr;
                tasks[i] = NULL;
                goto rollback;
            }

            has_child = true;

            break;
        }
        if (has_child)
        {
            current_task->waitpid = pid;
            task_block(current_task, TASK_BLOCKING, 0);

            continue;
        }

        break;
    }

    return -ENOENT;

rollback:
    *status = (int)child->status;
    uint32_t ret = child->pid;

    current_task->waitpid = 0;

    free_frames(virt_to_phys((uint64_t)child), 1);

    return ret;
}

uint64_t sys_clone(struct pt_regs *regs, uint64_t flags, uint64_t newsp, int *parent_tid, int *child_tid, uint64_t tls)
{
    arch_disable_interrupt();

    can_schedule = false;

    task_t *child = get_free_task();
    if (child == NULL)
    {
        return (uint64_t)-ENOMEM;
    }

    strncpy(child->name, current_task->name, TASK_NAME_MAX);

    child->state = TASK_READY;

    child->cpu_id = alloc_cpu_id();

    child->kernel_stack = phys_to_virt((uint64_t)alloc_frames(STACK_SIZE / DEFAULT_PAGE_SIZE)) + STACK_SIZE;
    child->syscall_stack = phys_to_virt((uint64_t)alloc_frames(STACK_SIZE / DEFAULT_PAGE_SIZE)) + STACK_SIZE;

    child->arch_context = malloc(sizeof(arch_context_t));
    memset(child->arch_context, 0, sizeof(arch_context_t));
    current_task->arch_context->ctx = regs;
    arch_context_copy(child->arch_context, current_task->arch_context, child->kernel_stack);
#if defined(__x86_64__)
    if (newsp)
        child->arch_context->ctx->rsp = newsp;
#endif
    child->ppid = current_task->pid;
    child->uid = current_task->uid;
    child->gid = current_task->gid;
    child->euid = current_task->euid;
    child->egid = current_task->egid;
    child->pgid = current_task->pgid;

    child->jiffies = current_task->jiffies;

    child->cwd = current_task->cwd;

    child->mmap_start = USER_MMAP_START;
    child->brk_start = USER_BRK_START;
    child->brk_end = USER_BRK_START;

    memcpy(child->fds, current_task->fds, sizeof(child->fds));
    for (uint64_t i = 3; i < MAX_FD_NUM; i++)
    {
        if (child->fds[i] && child->fds[i]->type == file_pipe && child->fds[i]->handle)
        {
            pipe_t *pipe = child->fds[i]->handle;
            pipe->reference_count++;
        }
    }

    if (flags & CLONE_SIGHAND)
    {
        memcpy(child->actions, current_task->actions, sizeof(child->actions));
        child->signal = current_task->signal;
        child->blocked = current_task->blocked;
    }

    if (flags & CLONE_SETTLS)
#if defined(__x86_64__)
        child->arch_context->fsbase = tls;
#endif

    if (flags & CLONE_PARENT_SETTID)
        *parent_tid = (int)child->pid;

    can_schedule = true;

    arch_enable_interrupt();

    return child->pid;
}

uint64_t sys_nanosleep(struct timespec *req, struct timespec *rem)
{
    if (req->tv_sec < 0)
        return (uint64_t)-EINVAL;

    size_t ms = req->tv_sec * 1000 + req->tv_nsec / 1000000;

    uint64_t target = nanoTime() + ms;

    do
    {
        arch_enable_interrupt();

        arch_yield();

        arch_pause();
    } while (target > nanoTime());

    return 0;
}

#include <task/task.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>
#include <fs/vfs/vfs.h>

task_t *tasks[MAX_TASK_NUM];
task_t *idle_tasks[MAX_CPU_NUM];

bool task_initialized = false;

task_t *get_free_task()
{
    for (uint64_t i = 0; i < MAX_TASK_NUM; i++)
    {
        if (tasks[i] == NULL)
        {
            tasks[i] = (task_t *)malloc(sizeof(task_t));
            memset(tasks[i], 0, sizeof(task_t));
            tasks[i]->pid = i;
            return tasks[i];
        }
    }

    return NULL;
}

uint32_t cpu_idx;

uint32_t alloc_cpu_id()
{
    uint32_t idx = cpu_idx;
    cpu_idx = (cpu_idx + 1) % cpu_count;
    return idx;
}

task_t *task_create(const char *name, void (*entry)())
{
    task_t *task = get_free_task();
    task->cpu_id = alloc_cpu_id();
    task->ppid = task->pid;
    task->waitpid = 0;
    task->state = TASK_READY;
    task->kernel_stack = phys_to_virt((uint64_t)alloc_frames(STACK_SIZE / DEFAULT_PAGE_SIZE));
    task->syscall_stack = phys_to_virt((uint64_t)alloc_frames(STACK_SIZE / DEFAULT_PAGE_SIZE));
    task->arch_context = malloc(sizeof(arch_context_t));
    arch_context_init(task->arch_context, virt_to_phys((uint64_t)get_current_page_dir()), (uint64_t)entry, task->kernel_stack + STACK_SIZE, false);
    task->signal = 0;
    task->status = 0;
    task->cwd = rootdir;
    task->brk_start = USER_BRK_START;
    task->brk_end = USER_BRK_START;
    strncpy(task->name, name, TASK_NAME_MAX);

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
#include <fs/partition.h>
#include <drivers/fb.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/vfs.h>

extern void fatfs_init();

extern void mount_root();

void init_thread()
{
    printk("NAOS init thread is running...\n");

    pci_init();
    ahci_init();
    nvme_init();

    vfs_init();

    fatfs_init();

    dev_init();

    partition_init();

    fbdev_init();

    mount_root();

    task_execve("/usr/bin/init.exec", NULL, NULL);

    while (1)
    {
        arch_pause();
    }
}

void task_init()
{
    memset(tasks, 0, sizeof(tasks));

    for (uint64_t cpu = 0; cpu < cpu_count; cpu++)
    {
        idle_tasks[cpu] = task_create("idle", idle_entry);
    }
    arch_set_current(idle_tasks[0]);
    task_create("init", init_thread);

    task_initialized = true;
}

uint64_t push_slice(uint64_t ustack, uint8_t *slice, uint64_t len)
{
    uint64_t tmp_stack = ustack;
    tmp_stack -= len;
    tmp_stack -= tmp_stack % 8;

    memcpy((void *)tmp_stack, slice, len);

    return tmp_stack;
}

uint64_t push_infos(task_t *task, uint64_t current_stack, char *argv[], char *envp[])
{
    uint64_t env_i = 0;
    uint64_t argv_i = 0;

    uint64_t tmp_stack = current_stack;
    tmp_stack = push_slice(tmp_stack, (uint8_t *)task->name, strlen(task->name) + 1);

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

    // push auxv
    uint8_t *tmp = (uint8_t *)malloc(2);
    memset(tmp, 0, 2);
    tmp_stack = push_slice(tmp_stack, tmp, 2);

    // push envp
    tmp_stack = push_slice(tmp_stack, tmp, 1);
    tmp_stack = push_slice(tmp_stack, (uint8_t *)envps, env_i * sizeof(uint64_t));

    // push argvp
    tmp_stack = push_slice(tmp_stack, tmp, 1);
    tmp_stack = push_slice(tmp_stack, (uint8_t *)argvps, argv_i * sizeof(uint64_t));

    uint64_t *args_len = (uint64_t *)malloc(sizeof(uint64_t));
    args_len[0] = argv_i;

    tmp_stack = push_slice(tmp_stack, (uint8_t *)args_len, sizeof(uint64_t));

    free(envps);
    free(argvps);
    free(args_len);

    return tmp_stack;
}

uint64_t task_fork()
{
    task_t *child = get_free_task();
    if (child == NULL)
    {
        return (uint64_t)-ENOMEM;
    }

    child->arch_context = malloc(sizeof(arch_context_t));
    arch_context_copy(child->arch_context, current_task->arch_context);
    child->ppid = current_task->pid;

    return child->pid;
}

uint64_t task_execve(const char *path, char *const *argv, char *const *envp)
{
    close_interrupt;

    vfs_node_t node = vfs_open(path);
    if (!node)
    {
        return (uint64_t)-ENOENT;
    }

    uint8_t *buffer = (uint8_t *)malloc(sizeof(Elf64_Ehdr));
    if (!buffer)
    {
        vfs_close(node);
        return (uint64_t)-ENOMEM;
    }

    vfs_read(node, buffer, 0, sizeof(Elf64_Ehdr));

    char *fullpath = vfs_get_fullpath(node);

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)buffer;

    uint64_t e_entry = ehdr->e_entry;

    if (e_entry == 0)
    {
        printk("bad e_entry\n");
        free(buffer);
        free(fullpath);
        vfs_close(node);
        return -EINVAL;
    }

    // 验证ELF魔数
    if (memcmp((void *)ehdr->e_ident, "\x7F"
                                      "ELF",
               4) != 0)
    {
        printk("Invalid ELF magic\n");
        free(buffer);
        free(fullpath);
        vfs_close(node);
        return -EINVAL;
    }

    // 检查架构和类型
    if (ehdr->e_ident[4] != 2 || // 64-bit
        ehdr->e_machine != 0x3E  // x86_64
    )
    {
        printk("Unsupported ELF format\n");
        free(buffer);
        free(fullpath);
        vfs_close(node);
        return -EINVAL;
    }

    // 处理程序头
    Elf64_Phdr *phdr = (Elf64_Phdr *)malloc(ehdr->e_phnum * sizeof(Elf64_Phdr));
    if (!phdr)
    {
        free(buffer);
        free(fullpath);
        vfs_close(node);
        return (uint64_t)-ENOMEM;
    }

    current_task->arch_context->cr3 = clone_page_table(virt_to_phys((uint64_t)get_current_page_dir()), USER_STACK_START, USER_STACK_END);

    __asm__ __volatile__("movq %0, %%cr3\n\t" ::"r"(current_task->arch_context->cr3) : "memory");

    uint64_t load_start = UINT64_MAX;
    uint64_t load_end = 0;

    vfs_read(node, phdr, ehdr->e_phoff, ehdr->e_phnum * sizeof(Elf64_Phdr));

    for (int i = 0; i < ehdr->e_phnum; ++i)
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

        map_page_range(get_current_page_dir(), aligned_addr, 0, alloc_size, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U | PT_FLAG_X);

        vfs_read(node, (void *)seg_addr, phdr[i].p_offset, file_size);

        // 清零剩余内存
        if (seg_size > file_size)
        {
            memset((char *)aligned_addr + size_diff + file_size,
                   0, seg_size - file_size);
        }
    }

    free(phdr);
    free(buffer);

    vfs_close(node);

    strncpy(current_task->name, fullpath, TASK_NAME_MAX);

    free(fullpath);

    map_page_range(get_current_page_dir(), USER_STACK_START, 0, USER_STACK_END - USER_STACK_START, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

#if defined(__x86_64__)
    current_task->arch_context->ctx->rsp = push_infos(current_task, USER_STACK_END, (char **)argv, (char **)envp);
#elif defined(__aarch64__)
#elif defined(__riscv)
#elif defined(__loongarch64)
#endif

    arch_to_user_mode(current_task->arch_context, e_entry, current_task->arch_context->ctx->rsp);

    return (uint64_t)-EAGAIN;
}

void sys_yield()
{
    arch_yield();
}

uint64_t task_exit(int64_t code)
{
    task_t *task = current_task;

    arch_context_free(task->arch_context);

    free_frames(task->kernel_stack, STACK_SIZE / DEFAULT_PAGE_SIZE);
    free_frames(task->syscall_stack, STACK_SIZE / DEFAULT_PAGE_SIZE);

    free(task->arch_context);

    tasks[task->pid] = NULL;

    task->state = TASK_DIED;

    task->status = (uint64_t)code;

    sys_yield();

    return (uint64_t)-EAGAIN;
}

#include <task/task.h>
#include <arch/arch.h>
#include <drivers/kernel_logger.h>

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
    task->cwd = rootdir;
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

    mount_root();

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

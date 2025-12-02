#include <arch/arch.h>
#include <task/task.h>
#include <task/futex.h>
#include <task/sched.h>
#include <drivers/kernel_logger.h>
#include <fs/vfs/dev.h>
#include <fs/vfs/vfs.h>
#include <fs/vfs/proc.h>
#include <arch/arch.h>
#include <mm/mm.h>
#include <fs/fs_syscall.h>
#include <net/socket.h>
#include <uacpi/sleep.h>

rrs_t *schedulers[MAX_CPU_NUM];

const uint64_t bitmap_size =
    (USER_MMAP_END - USER_MMAP_START) / DEFAULT_PAGE_SIZE / 8;

spinlock_t task_queue_lock = SPIN_INIT;
task_t *tasks[MAX_TASK_NUM];
task_t *idle_tasks[MAX_CPU_NUM];

void send_process_group_signal(int pgid, int signal) {
    uint64_t continue_ptr_count = 0;
    for (size_t i = 1; i < MAX_TASK_NUM; i++) {
        task_t *ptr = tasks[i];
        if (ptr == NULL) {
            continue_ptr_count++;
            if (continue_ptr_count >= MAX_CONTINUE_NULL_TASKS)
                break;
            continue;
        }
        continue_ptr_count = 0;

        if (tasks[i]->pgid == pgid) {
            sys_kill(tasks[i]->pid, signal);
        }
    }
}

void free_task(task_t *ptr) {
    spin_lock(&task_queue_lock);
    tasks[ptr->pid] = NULL;
    spin_unlock(&task_queue_lock);

    vma_manager_exit_cleanup(&ptr->arch_context->mm->task_vma_mgr);

    if (!ptr->is_kernel)
        free_page_table(ptr->arch_context->mm);

    if (ptr->cmdline)
        free(ptr->cmdline);

    arch_context_free(ptr->arch_context);
    free(ptr->arch_context);

    free(ptr->sched_info);
    ptr->sched_info = NULL;

    if (ptr->fd_info) {
        if (ptr->fd_info->ref_count <= 0) {
            for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
                if (ptr->fd_info->fds[i]) {
                    vfs_close(ptr->fd_info->fds[i]->node);
                    free(ptr->fd_info->fds[i]);

                    ptr->fd_info->fds[i] = NULL;
                }
            }
            free(ptr->fd_info);
        }
    }

    free_frames_bytes((void *)(ptr->kernel_stack - STACK_SIZE), STACK_SIZE);
    free_frames_bytes((void *)(ptr->syscall_stack - STACK_SIZE), STACK_SIZE);

    free(ptr);
}

bool task_initialized = false;
bool can_schedule = false;

extern int unix_socket_fsid;
extern int unix_accept_fsid;

uint32_t cpu_idx = 0;

uint32_t alloc_cpu_id() {
    uint32_t idx = cpu_idx;
    cpu_idx = (cpu_idx + 1) % cpu_count;
    return idx;
}

task_t *get_free_task() {
    for (uint64_t i = 0; i < cpu_count; i++) {
        if (idle_tasks[i] == NULL) {
            task_t *task = (task_t *)malloc(sizeof(task_t));
            memset(task, 0, sizeof(task_t));
            task->state = TASK_CREATING;
            task->pid = 0;
            task->cpu_id = i;
            idle_tasks[i] = task;
            can_schedule = true;
            spin_unlock(&task_queue_lock);
            return task;
        }
    }

    spin_lock(&task_queue_lock);

    for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
        if (tasks[i] == NULL) {
            task_t *task = (task_t *)malloc(sizeof(task_t));
            memset(task, 0, sizeof(task_t));
            task->state = TASK_CREATING;
            task->pid = i;
            task->cpu_id = alloc_cpu_id();
            tasks[i] = task;
            can_schedule = true;
            spin_unlock(&task_queue_lock);
            return task;
        }
    }

    spin_unlock(&task_queue_lock);

    return NULL;
}

task_t *task_create(const char *name, void (*entry)(uint64_t), uint64_t arg,
                    int priority) {
    arch_disable_interrupt();

    can_schedule = false;

    task_t *task = get_free_task();
    task->signal = malloc(sizeof(task_signal_info_t));
    memset(task->signal, 0, sizeof(task_signal_info_t));
    task->signal->signal_lock = SPIN_INIT;
    memset(&task->signal->signal_saved_regs, 0, sizeof(struct pt_regs));
    task->is_kernel = true;
    task->ppid = task->pid;
    task->uid = 0;
    task->gid = 0;
    task->euid = 0;
    task->egid = 0;
    task->ruid = 0;
    task->rgid = 0;
    task->pgid = 0;
    task->tgid = 0;
    task->sid = 0;
    task->waitpid = 0;
    task->priority = priority;
    task->kernel_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    task->syscall_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    memset((void *)(task->kernel_stack - STACK_SIZE), 0, STACK_SIZE);
    memset((void *)(task->syscall_stack - STACK_SIZE), 0, STACK_SIZE);
    task->arch_context = malloc(sizeof(arch_context_t));
    memset(task->arch_context, 0, sizeof(arch_context_t));
    arch_context_init(task->arch_context,
                      virt_to_phys((uint64_t)get_kernel_page_dir()),
                      (uint64_t)entry, task->kernel_stack, false, arg);
#if defined(__riscv__)
    task->arch_context->ctx->ktp = (uint64_t)task;
    task->arch_context->ctx->tp = (uint64_t)task;
    task->arch_context->ctx->gp = cpuid_to_hartid[task->cpu_id];
#endif
    task->signal->signal = 0;
    task->status = 0;
    task->cwd = rootdir;
    task->fd_info = malloc(sizeof(fd_info_t));
    memset(task->fd_info, 0, sizeof(fd_info_t));
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

    memset(task->signal->actions, 0, sizeof(task->signal->actions));

    task->cmdline = NULL;

    memset(task->rlim, 0, sizeof(task->rlim));
    task->rlim[RLIMIT_STACK] = (struct rlimit){
        USER_STACK_END - USER_STACK_START, USER_STACK_END - USER_STACK_START};
    task->rlim[RLIMIT_NPROC] = (struct rlimit){MAX_TASK_NUM, MAX_TASK_NUM};
    task->rlim[RLIMIT_NOFILE] = (struct rlimit){MAX_FD_NUM, MAX_FD_NUM};
    task->rlim[RLIMIT_CORE] = (struct rlimit){0, 0};

    task->child_vfork_done = false;
    task->is_vfork = false;
    task->is_clone = false;
    task->should_free = false;

    procfs_on_new_task(task);

    task->state = TASK_READY;
    task->current_state = TASK_READY;

    task->sched_info = calloc(1, sizeof(struct sched_entity));
    add_rrs_entity(task, schedulers[task->cpu_id]);

    can_schedule = true;

    return task;
}

void idle_entry(uint64_t arg) {
    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}

extern void init_thread(uint64_t arg);

void task_init() {
    memset(tasks, 0, sizeof(tasks));
    memset(idle_tasks, 0, sizeof(idle_tasks));

    for (uint64_t cpu = 0; cpu < cpu_count; cpu++) {
        schedulers[cpu] = malloc(sizeof(rrs_t));
        memset(schedulers[cpu], 0, sizeof(rrs_t));
        schedulers[cpu]->sched_queue = create_llist_queue();
    }

    for (uint64_t cpu = 0; cpu < cpu_count; cpu++) {
        task_t *idle_task = task_create("idle", idle_entry, 0, IDLE_PRIORITY);
        idle_task->cpu_id = cpu;
        idle_task->state = TASK_READY;
        idle_task->current_state = TASK_RUNNING;
        schedulers[cpu]->idle = idle_task->sched_info;
        remove_rrs_entity(idle_task, schedulers[cpu]);
        schedulers[cpu]->curr = idle_task->sched_info;
    }

    task_create("init", init_thread, 0, NORMAL_PRIORITY);

    arch_set_current(idle_tasks[current_cpu_id]);

    task_initialized = true;

    can_schedule = true;
}

static uint64_t simple_rand() {
    tm time;
    time_read(&time);
    uint32_t seed = mktime(&time);
    seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return ((uint64_t)seed << 32) | seed;
}

#define PUSH_TO_STACK(a, b, c)                                                 \
    a -= sizeof(b);                                                            \
    *((b *)(a)) = c

#define PUSH_BYTES_TO_STACK(stack_ptr, data, len)                              \
    do {                                                                       \
        stack_ptr -= (len);                                                    \
        memcpy((void *)(stack_ptr), (data), (len));                            \
    } while (0)

#define ALIGN_STACK_DOWN(stack_ptr, alignment)                                 \
    stack_ptr = (stack_ptr) & ~((alignment) - 1)

uint64_t push_infos(task_t *task, uint64_t current_stack, char *argv[],
                    int argv_count, char *envp[], int envp_count,
                    uint64_t e_entry, uint64_t phdr, uint64_t phnum,
                    uint64_t at_base) {
    uint64_t tmp_stack = current_stack;

    size_t name_len = strlen(task->name) + 1;
    PUSH_BYTES_TO_STACK(tmp_stack, task->name, name_len);
    uint64_t execfn_ptr = tmp_stack;

    uint64_t random_values[2];
    random_values[0] = simple_rand();
    random_values[1] = simple_rand();
    PUSH_BYTES_TO_STACK(tmp_stack, random_values, 16);
    uint64_t random_ptr = tmp_stack;

    uint64_t *envp_addrs = NULL;
    if (envp_count > 0 && envp != NULL) {
        envp_addrs = (uint64_t *)malloc(envp_count * sizeof(uint64_t));

        for (int i = envp_count - 1; i >= 0; i--) {
            size_t len = strlen(envp[i]) + 1;
            PUSH_BYTES_TO_STACK(tmp_stack, envp[i], len);
            envp_addrs[i] = tmp_stack;
        }
    }

    uint64_t *argv_addrs = NULL;
    if (argv_count > 0 && argv != NULL) {
        argv_addrs = (uint64_t *)malloc(argv_count * sizeof(uint64_t));

        // 从后向前推送
        for (int i = argv_count - 1; i >= 0; i--) {
            size_t len = strlen(argv[i]) + 1;
            PUSH_BYTES_TO_STACK(tmp_stack, argv[i], len);
            argv_addrs[i] = tmp_stack;
        }
    }

    uint64_t total_len = sizeof(uint64_t) +
                         (argv_count + 1) * sizeof(uint64_t) +
                         (envp_count + 1) * sizeof(uint64_t);
    tmp_stack -= (tmp_stack - total_len) % 0x10;

    PUSH_TO_STACK(tmp_stack, uint64_t, 0);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_NULL);

    PUSH_TO_STACK(tmp_stack, uint64_t, DEFAULT_PAGE_SIZE);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_PAGESZ);

    PUSH_TO_STACK(tmp_stack, uint64_t, random_ptr);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_RANDOM);

    PUSH_TO_STACK(tmp_stack, uint64_t, at_base);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_BASE);

    PUSH_TO_STACK(tmp_stack, uint64_t, execfn_ptr);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_EXECFN);

    PUSH_TO_STACK(tmp_stack, uint64_t, e_entry);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_ENTRY);

    PUSH_TO_STACK(tmp_stack, uint64_t, phnum);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_PHNUM);

    PUSH_TO_STACK(tmp_stack, uint64_t, sizeof(Elf64_Phdr));
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_PHENT);

    PUSH_TO_STACK(tmp_stack, uint64_t, phdr);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_PHDR);

    // NULL 结束标记
    PUSH_TO_STACK(tmp_stack, uint64_t, 0);

    if (envp_count > 0 && envp_addrs != NULL) {
        for (int i = envp_count - 1; i >= 0; i--) {
            PUSH_TO_STACK(tmp_stack, uint64_t, envp_addrs[i]);
        }
    }

    // NULL 结束标记
    PUSH_TO_STACK(tmp_stack, uint64_t, 0);

    if (argv_count > 0 && argv_addrs != NULL) {
        for (int i = argv_count - 1; i >= 0; i--) {
            PUSH_TO_STACK(tmp_stack, uint64_t, argv_addrs[i]);
        }
    }

    PUSH_TO_STACK(tmp_stack, uint64_t, argv_count);

    if (argv_addrs)
        free(argv_addrs);
    if (envp_addrs)
        free(envp_addrs);

    return tmp_stack;
}

uint64_t task_fork(struct pt_regs *regs, bool vfork) {
    return sys_clone(regs, vfork ? CLONE_VFORK : 0, 0, NULL, NULL, 0);
}

uint64_t get_node_size(vfs_node_t node) {
    if (node->type & file_symlink) {
        char linkpath[128];
        memset(linkpath, 0, sizeof(linkpath));
        int ret = vfs_readlink(node, linkpath, sizeof(linkpath));
        if (ret < 0) {
            return (uint64_t)-ENOENT;
        }

        vfs_node_t linknode = vfs_open_at(node->parent, linkpath);
        if (!linknode) {
            return (uint64_t)-ENOENT;
        }

        return get_node_size(linknode);
    } else {
        return node->size;
    }
}

uint64_t task_execve(const char *path_user, const char **argv,
                     const char **envp) {
    can_schedule = false;

    char path[128];
    strncpy(path, path_user, sizeof(path));

    vfs_node_t node = vfs_open(path);
    if (!node) {
        can_schedule = true;
        return (uint64_t)-ENOENT;
    }

    uint64_t size = get_node_size(node);
    if ((int64_t)size < 0)
        return size;

    // argv/envp 处理代码保持不变
    int argv_count = 0;
    int envp_count = 0;

    if (argv &&
        (translate_address(get_current_page_dir(true), (uint64_t)argv) != 0)) {
        for (argv_count = 0;
             argv[argv_count] != NULL &&
             (translate_address(get_current_page_dir(true),
                                (uint64_t)argv[argv_count]) != 0);
             argv_count++) {
        }
    }

    if (envp &&
        (translate_address(get_current_page_dir(true), (uint64_t)envp) != 0)) {
        for (envp_count = 0;
             envp[envp_count] != NULL &&
             (translate_address(get_current_page_dir(true),
                                (uint64_t)envp[envp_count]) != 0);
             envp_count++) {
        }
    }

    char **new_argv = (char **)malloc((argv_count + 1) * sizeof(char *));
    memset(new_argv, 0, (argv_count + 1) * sizeof(char *));
    char **new_envp = (char **)malloc((envp_count + 1) * sizeof(char *));
    memset(new_envp, 0, (envp_count + 1) * sizeof(char *));

    argv_count = 0;
    envp_count = 0;

    if (argv &&
        (translate_address(get_current_page_dir(true), (uint64_t)argv) != 0)) {
        for (argv_count = 0;
             argv[argv_count] != NULL &&
             (translate_address(get_current_page_dir(true),
                                (uint64_t)argv[argv_count]) != 0);
             argv_count++) {
            new_argv[argv_count] = strdup(argv[argv_count]);
        }
    }
    new_argv[argv_count] = NULL;

    if (envp &&
        (translate_address(get_current_page_dir(true), (uint64_t)envp) != 0)) {
        for (envp_count = 0;
             envp[envp_count] != NULL &&
             (translate_address(get_current_page_dir(true),
                                (uint64_t)envp[envp_count]) != 0);
             envp_count++) {
            new_envp[envp_count] = strdup(envp[envp_count]);
        }
    }
    new_envp[envp_count] = NULL;

    uint8_t header_buf[256];
    ssize_t header_read = vfs_read(node, header_buf, 0, sizeof(header_buf));
    if (header_read < sizeof(Elf64_Ehdr)) {
        for (int i = 0; i < argv_count; i++)
            if (new_argv[i])
                free(new_argv[i]);
        free(new_argv);
        for (int i = 0; i < envp_count; i++)
            if (new_envp[i])
                free(new_envp[i]);
        free(new_envp);
        can_schedule = true;
        return (uint64_t)-ENOEXEC;
    }

    // 检查 shebang
    if (header_buf[0] == '#' && header_buf[1] == '!') {
        for (int i = 0; i < argv_count; i++)
            if (new_argv[i])
                free(new_argv[i]);
        free(new_argv);
        for (int i = 0; i < envp_count; i++)
            if (new_envp[i])
                free(new_envp[i]);
        free(new_envp);

        char *p = (char *)header_buf + 2;
        const char *interpreter_name = NULL;
        while (*p != '\n' && p < (char *)header_buf + header_read) {
            if (!interpreter_name && *p != ' ') {
                interpreter_name = (const char *)p;
            }
            p++;
        }
        *p = '\0';

        if (!interpreter_name)
            return -EINVAL;

        char interpreter_name_buf[128];
        strncpy(interpreter_name_buf, interpreter_name,
                sizeof(interpreter_name_buf));

        int argc = 0;
        while (argv[argc++])
            ;
        const char *injected_argv[128];
        memcpy((char *)&injected_argv[1], argv, argc * sizeof(char *));
        injected_argv[0] = interpreter_name_buf;
        injected_argv[1] = path;

        return task_execve((const char *)injected_argv[0], injected_argv, envp);
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)header_buf;

    uint64_t e_entry = ehdr->e_entry;
    if (e_entry == 0) {
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

    if (!arch_check_elf(ehdr)) {
        for (int i = 0; i < argv_count; i++)
            if (new_argv[i])
                free(new_argv[i]);
        free(new_argv);
        for (int i = 0; i < envp_count; i++)
            if (new_envp[i])
                free(new_envp[i]);
        free(new_envp);
        can_schedule = true;
        return (uint64_t)-ENOEXEC;
    }

    Elf64_Phdr *phdr;
    size_t phdr_size = ehdr->e_phnum * sizeof(Elf64_Phdr);
    bool phdr_allocated = false;

    if (ehdr->e_phoff + phdr_size <= sizeof(header_buf)) {
        phdr = (Elf64_Phdr *)(header_buf + ehdr->e_phoff);
    } else {
        phdr = (Elf64_Phdr *)malloc(phdr_size);
        phdr_allocated = true;
        vfs_read(node, phdr, ehdr->e_phoff, phdr_size);
    }

    if (!current_task->is_vfork) {
        if (current_task->arch_context->mm->ref_count <= 1)
            vma_manager_exit_cleanup(
                &current_task->arch_context->mm->task_vma_mgr);
    }

    task_mm_info_t *old_mm = current_task->arch_context->mm;
    task_mm_info_t *new_mm = (task_mm_info_t *)malloc(sizeof(task_mm_info_t));
    memset(new_mm, 0, sizeof(task_mm_info_t));
    new_mm->page_table_addr = alloc_frames(1);
    memset((void *)phys_to_virt(new_mm->page_table_addr), 0, DEFAULT_PAGE_SIZE);
#if defined(__x86_64__) || defined(__riscv__)
    memcpy((uint64_t *)phys_to_virt(new_mm->page_table_addr) + 256,
           get_kernel_page_dir() + 256, DEFAULT_PAGE_SIZE / 2);
#endif
    new_mm->ref_count = 1;
    memset(&new_mm->task_vma_mgr, 0, sizeof(vma_manager_t));
    new_mm->task_vma_mgr.initialized = true;

    new_mm->task_vma_mgr.last_alloc_addr = USER_MMAP_START;
    new_mm->brk_start = USER_BRK_START;
    new_mm->brk_current = new_mm->brk_start;
    new_mm->brk_end = USER_BRK_END;

#if defined(__x86_64__)
    asm volatile("movq %0, %%cr3" ::"r"(new_mm->page_table_addr));
#elif defined(__aarch64__)
    asm volatile("msr TTBR0_EL1, %0" : : "r"(new_mm->page_table_addr));
    asm volatile("dsb ishst\n\t"
                 "tlbi vmalle1is\n\t"
                 "dsb ish\n\t"
                 "isb\n\t");
#elif defined(__riscv__)
    uint64_t satp = MAKE_SATP_PADDR(SATP_MODE_SV48, 0, new_mm->page_table_addr);
    asm volatile("csrw satp, %0" : : "r"(satp) : "memory");
    asm volatile("sfence.vma");
    csr_set(sstatus, (1UL << 18));
#endif

    current_task->arch_context->mm = new_mm;

    if (!current_task->is_kernel) {
        free_page_table(old_mm);
    }

    uint64_t load_start = UINT64_MAX;
    uint64_t load_end = 0;
    uint64_t interpreter_entry = 0;
    uint64_t interpreter_load_start = UINT64_MAX;
    uint64_t interpreter_load_end = 0;
    char *interpreter_path = NULL;

    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_INTERP) {
            char interp_name[256];
            vfs_read(node, interp_name, phdr[i].p_offset,
                     phdr[i].p_filesz < 256 ? phdr[i].p_filesz : 255);
            interp_name[phdr[i].p_filesz < 256 ? phdr[i].p_filesz : 255] = '\0';

            interpreter_path = strdup(interp_name);

            vfs_node_t interpreter_node = vfs_open(interp_name);
            if (!interpreter_node) {
                if (phdr_allocated)
                    free(phdr);
                for (int i = 0; i < argv_count; i++)
                    if (new_argv[i])
                        free(new_argv[i]);
                free(new_argv);
                for (int i = 0; i < envp_count; i++)
                    if (new_envp[i])
                        free(new_envp[i]);
                free(new_envp);
                can_schedule = true;
                return (uint64_t)-ENOENT;
            }

            Elf64_Ehdr interp_ehdr;
            vfs_read(interpreter_node, &interp_ehdr, 0, sizeof(Elf64_Ehdr));

            size_t interp_phdr_size = interp_ehdr.e_phnum * sizeof(Elf64_Phdr);
            Elf64_Phdr *interp_phdr = (Elf64_Phdr *)malloc(interp_phdr_size);
            vfs_read(interpreter_node, interp_phdr, interp_ehdr.e_phoff,
                     interp_phdr_size);

            for (int j = 0; j < interp_ehdr.e_phnum; j++) {
                if (interp_phdr[j].p_type != PT_LOAD)
                    continue;

                uint64_t seg_addr =
                    INTERPRETER_BASE_ADDR + interp_phdr[j].p_vaddr;
                uint64_t seg_size = interp_phdr[j].p_memsz;
                uint64_t file_size = interp_phdr[j].p_filesz;
                uint64_t page_size = DEFAULT_PAGE_SIZE;
                uint64_t page_mask = page_size - 1;

                uint64_t aligned_addr = seg_addr & ~page_mask;
                uint64_t size_diff = seg_addr - aligned_addr;
                uint64_t alloc_size =
                    (seg_size + size_diff + page_mask) & ~page_mask;

                if (aligned_addr < interpreter_load_start)
                    interpreter_load_start = aligned_addr;
                if (aligned_addr + alloc_size > interpreter_load_end)
                    interpreter_load_end = aligned_addr + alloc_size;

                uint64_t flags = PT_FLAG_U | PT_FLAG_R | PT_FLAG_W | PT_FLAG_X;
                map_page_range(get_current_page_dir(true), aligned_addr, 0,
                               alloc_size, flags);

                vfs_read(interpreter_node, (void *)seg_addr,
                         interp_phdr[j].p_offset, file_size);

                if (seg_size > file_size) {
                    memset((void *)(seg_addr + file_size), 0,
                           seg_size - file_size);
                }
            }

            interpreter_entry = INTERPRETER_BASE_ADDR + interp_ehdr.e_entry;
            free(interp_phdr);

        } else if (phdr[i].p_type == PT_LOAD) {
            uint64_t seg_addr = phdr[i].p_vaddr;
            uint64_t seg_size = phdr[i].p_memsz;
            uint64_t file_size = phdr[i].p_filesz;
            uint64_t page_size = DEFAULT_PAGE_SIZE;
            uint64_t page_mask = page_size - 1;

            uint64_t aligned_addr = seg_addr & ~page_mask;
            uint64_t size_diff = seg_addr - aligned_addr;
            uint64_t alloc_size =
                (seg_size + size_diff + page_mask) & ~page_mask;

            if (aligned_addr < load_start)
                load_start = aligned_addr;
            if (aligned_addr + alloc_size > load_end)
                load_end = aligned_addr + alloc_size;

            uint64_t flags = PT_FLAG_U | PT_FLAG_R | PT_FLAG_W | PT_FLAG_X;
            map_page_range(get_current_page_dir(true), aligned_addr, 0,
                           alloc_size, flags);

            vfs_read(node, (void *)seg_addr, phdr[i].p_offset, file_size);

            if (seg_size > file_size) {
                memset((void *)(seg_addr + file_size), 0, seg_size - file_size);
            }
        }
    }

    if (phdr_allocated) {
        free(phdr);
    }

    char *fullpath = vfs_get_fullpath(node);

    strncpy(current_task->name, fullpath, TASK_NAME_MAX);

    free(fullpath);

    node->refcount++;
    current_task->exec_node = node;

    map_page_range(get_current_page_dir(true), USER_STACK_START, 0,
                   USER_STACK_END - USER_STACK_START,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    memset((void *)USER_STACK_START, 0, USER_STACK_END - USER_STACK_START);
    uint64_t stack =
        push_infos(current_task, USER_STACK_END, (char **)new_argv, argv_count,
                   (char **)new_envp, envp_count, e_entry,
                   (uint64_t)(load_start + ehdr->e_phoff), ehdr->e_phnum,
                   interpreter_entry ? INTERPRETER_BASE_ADDR : load_start);

    if (current_task->ppid != current_task->pid && tasks[current_task->ppid] &&
        !tasks[current_task->ppid]->child_vfork_done) {
        tasks[current_task->ppid]->child_vfork_done = true;
        current_task->is_vfork = false;
    }

    char cmdline[DEFAULT_PAGE_SIZE * 4];
    memset(cmdline, 0, sizeof(cmdline));
    char *cmdline_ptr = cmdline;
    int cmdline_len = 0;
    for (int i = 0; i < argv_count; i++) {
        int len = sprintf(cmdline_ptr, "%s ", new_argv[i]);
        cmdline_ptr += len;
        cmdline_len += len;
    }
    if (cmdline_len > 1) {
        cmdline[cmdline_len - 1] = '\0';
    }

    for (int i = 0; i < argv_count; i++) {
        if (new_argv[i]) {
            free(new_argv[i]);
        }
    }
    free(new_argv);
    for (int i = 0; i < envp_count; i++) {
        if (new_envp[i]) {
            free(new_envp[i]);
        }
    }
    free(new_envp);

    if (current_task->ppid != current_task->pid && tasks[current_task->ppid] &&
        (tasks[current_task->ppid]->fd_info == current_task->fd_info)) {
        current_task->fd_info->ref_count--;
        current_task->fd_info = malloc(sizeof(fd_info_t));

        for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
            fd_t *fd = tasks[current_task->ppid]->fd_info->fds[i];

            if (fd) {
                current_task->fd_info->fds[i] = malloc(sizeof(fd_t));
                memcpy(current_task->fd_info->fds[i], fd, sizeof(fd_t));
                fd->node->refcount++;
            } else {
                current_task->fd_info->fds[i] = NULL;
            }
        }

        current_task->fd_info->ref_count++;
    }

    for (uint64_t i = 3; i < MAX_FD_NUM; i++) {
        if (!current_task->fd_info->fds[i])
            continue;

        if (current_task->fd_info->fds[i]->flags & O_CLOEXEC) {
            vfs_close(current_task->fd_info->fds[i]->node);
            free(current_task->fd_info->fds[i]);
            current_task->fd_info->fds[i] = NULL;
        }
    }

    sigaction_t old_sigchld_handler;
    memcpy(&old_sigchld_handler, &current_task->signal->actions[SIGCHLD],
           sizeof(sigaction_t));
    if (current_task->signal)
        free(current_task->signal);
    current_task->signal = malloc(sizeof(task_signal_info_t));
    memset(current_task->signal, 0, sizeof(task_signal_info_t));
    current_task->signal->signal_lock = SPIN_INIT;
    memcpy(&current_task->signal->actions[SIGCHLD], &old_sigchld_handler,
           sizeof(sigaction_t));

    current_task->cmdline = strdup(cmdline);
    current_task->load_start = load_start;
    current_task->load_end = load_end;

    if (interpreter_path) {
        vma_t *ld_so_vma = vma_alloc();

        ld_so_vma->vm_start = interpreter_load_start;
        ld_so_vma->vm_end = interpreter_load_end;
        ld_so_vma->vm_flags |= VMA_READ | VMA_WRITE | VMA_EXEC;

        ld_so_vma->vm_type = VMA_TYPE_ANON;
        ld_so_vma->vm_name = interpreter_path;

        vma_t *region =
            vma_find_intersection(&current_task->arch_context->mm->task_vma_mgr,
                                  interpreter_load_start, interpreter_load_end);
        if (!region) {
            vma_insert(&current_task->arch_context->mm->task_vma_mgr,
                       ld_so_vma);
        }
    } else {
        free(interpreter_path);
    }

    vma_t *exec_vma = vma_alloc();

    exec_vma->vm_start = load_start;
    exec_vma->vm_end = load_end;
    exec_vma->vm_flags |= VMA_READ | VMA_WRITE | VMA_EXEC;

    exec_vma->vm_type = VMA_TYPE_ANON;
    exec_vma->vm_name = strdup(path);

    vma_t *region = vma_find_intersection(
        &current_task->arch_context->mm->task_vma_mgr, load_start, load_end);
    if (!region) {
        vma_insert(&current_task->arch_context->mm->task_vma_mgr, exec_vma);
    }

    vma_t *stack_vma = vma_alloc();

    stack_vma->vm_start = USER_STACK_START;
    stack_vma->vm_end = USER_STACK_END;
    stack_vma->vm_flags |= VMA_READ | VMA_WRITE;

    stack_vma->vm_type = VMA_TYPE_ANON;
    stack_vma->vm_name = strdup("[stack]");

    region =
        vma_find_intersection(&current_task->arch_context->mm->task_vma_mgr,
                              USER_STACK_START, USER_STACK_END);
    if (!region) {
        vma_insert(&current_task->arch_context->mm->task_vma_mgr, stack_vma);
    }

    current_task->is_clone = false;
    current_task->is_kernel = false;
    can_schedule = true;

    arch_to_user_mode(current_task->arch_context,
                      interpreter_entry ? interpreter_entry : e_entry, stack);

    return (uint64_t)-EAGAIN;
}

void sys_yield() { arch_yield(); }

int task_block(task_t *task, task_state_t state, int64_t timeout_ns) {
    task->state = state;
    if (timeout_ns > 0)
        task->force_wakeup_ns = nano_time() + timeout_ns;
    else
        task->force_wakeup_ns = UINT64_MAX;

    remove_rrs_entity(task, schedulers[task->cpu_id]);

    schedule(SCHED_FLAG_YIELD);

    return task->status;
}

void task_unblock(task_t *task, int reason) {
    task->status = reason;
    task->state = TASK_READY;

    add_rrs_entity(task, schedulers[task->cpu_id]);
}

extern spinlock_t futex_lock;
extern struct futex_wait futex_wait_list;

extern uint64_t sys_futex_wake(uint64_t addr, int val, uint32_t bitset);

void task_exit_inner(task_t *task, int64_t code) {
    struct sched_entity *entity = (struct sched_entity *)task->sched_info;
    remove_rrs_entity(task, schedulers[task->cpu_id]);

    task->current_state = TASK_DIED;
    task->state = TASK_DIED;

    vfs_close(task->exec_node);

    spin_lock(&futex_lock);

    struct futex_wait *curr = &futex_wait_list;
    struct futex_wait *prev = NULL;
    int count = 0;
    while (curr) {
        bool found = false;

        if (curr->task == task) {
            if (prev) {
                prev->next = curr->next;
            }
            free(curr);
            found = true;
        }
        if (found) {
            curr = prev->next;
        } else {
            prev = curr;
            curr = curr->next;
        }
    }

    spin_unlock(&futex_lock);

    if (task->tidptr) {
        *task->tidptr = 0;
        sys_futex_wake((uint64_t)task->tidptr, INT32_MAX, 0xFFFFFFFF);
    }

    task->status = (uint64_t)code;

    if (task->fd_info)
        task->fd_info->ref_count--;

    if (task->ppid != task->pid && tasks[task->ppid] &&
        !tasks[task->ppid]->child_vfork_done) {
        tasks[task->ppid]->child_vfork_done = true;
        task->is_vfork = false;
    }

    procfs_on_exit_task(task);

    if (task->waitpid != 0 && task->waitpid < MAX_TASK_NUM &&
        tasks[task->waitpid] &&
        (tasks[task->waitpid]->state == TASK_BLOCKING ||
         tasks[task->waitpid]->state == TASK_READING_STDIO)) {
        task_unblock(tasks[task->waitpid], EOK);
    }

    if (!task->is_clone && task->ppid && task->pid != task->ppid &&
        task->ppid < MAX_TASK_NUM && tasks[task->ppid]) {
        task_t *parent = tasks[task->ppid];
        // sigaction_t *sa = &parent->signal->actions[SIGCHLD];

        // if (code > 128) {
        //     return;
        // }

        // if (sa->sa_handler != SIG_IGN || (sa->sa_flags & SA_NOCLDWAIT)) {
        //     if (sa->sa_handler != SIG_IGN && sa->sa_handler != SIG_DFL) {
        //         siginfo_t sigchld_info;
        //         sigchld_info.si_signo = SIGCHLD;
        //         sigchld_info.__si_fields.__si_common.__first.__piduid.si_pid
        //         =
        //             task->pid;
        //         sigchld_info.__si_fields.__si_common.__first.__piduid.si_uid
        //         =
        //             task->uid;
        //         sigchld_info.si_code = code;
        //         sigchld_info.__si_fields.__si_common.__second.__sigchld
        //             .si_status = CLD_EXITED;
        //         sigchld_info.__si_fields.__si_common.__second.__sigchld
        //             .si_utime = nano_time();
        //         sigchld_info.__si_fields.__si_common.__second.__sigchld
        //             .si_stime = nano_time();
        //         task_commit_signal(parent, SIGCHLD, &sigchld_info);
        //     }

        //     if (sa->sa_flags & SA_NOCLDWAIT) {
        //         task->should_free = true;
        //     } else if (sa->sa_handler == SIG_IGN) {
        //         // 只是忽略信号，不立即释放
        //     }
        // }

        task_unblock(parent, 128 + SIGCHLD);
    } else if (task->pid == task->ppid) {
        task->should_free = true;
    }
}

uint64_t task_exit(int64_t code) {
    arch_disable_interrupt();

    can_schedule = false;

    spin_lock(&task_queue_lock);
    uint64_t continue_ptr_count = 0;
    for (int i = 0; i < MAX_TASK_NUM; i++) {
        if (!tasks[i]) {
            continue_ptr_count++;
            if (continue_ptr_count >= MAX_CONTINUE_NULL_TASKS)
                break;
            continue;
        }
        continue_ptr_count = 0;
        if (tasks[i] != current_task && (tasks[i]->ppid != tasks[i]->pid) &&
            (tasks[i]->ppid == current_task->pid)) {
            task_commit_signal(tasks[i], SIGKILL, NULL);
            if (tasks[i]->state == TASK_BLOCKING ||
                tasks[i]->state == TASK_READING_STDIO)
                task_unblock(tasks[i], EOK);
        }
    }
    spin_unlock(&task_queue_lock);

    task_exit_inner(current_task, code);

    can_schedule = true;

    while (1) {
        schedule(SCHED_FLAG_YIELD);
    }

    // never return !!!

    return (uint64_t)-EAGAIN;
}

uint64_t sys_waitpid(uint64_t pid, int *status, uint64_t options) {
    arch_disable_interrupt();
    task_t *target = NULL;
    uint64_t ret = -ECHILD;

    // First check if we have any children at all
    bool has_children = false;
    for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
        spin_lock(&task_queue_lock);
        task_t *ptr = tasks[i];
        spin_unlock(&task_queue_lock);
        if (ptr && ptr->ppid != ptr->pid && ptr->ppid == current_task->pid) {
            has_children = true;
            break;
        }
    }

    if (!has_children) {
        return -ECHILD;
    }

    while (1) {
        task_t *found_alive = NULL;
        task_t *found_dead = NULL;

        uint64_t continue_ptr_count = 0;
        for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
            spin_lock(&task_queue_lock);
            task_t *ptr = tasks[i];
            spin_unlock(&task_queue_lock);

            if (ptr == NULL) {
                continue_ptr_count++;
                if (continue_ptr_count >= MAX_CONTINUE_NULL_TASKS)
                    break;
                continue;
            }
            continue_ptr_count = 0;

            if (ptr->ppid == ptr->pid)
                continue;
            if (ptr->ppid != current_task->pid)
                continue;

            if ((int64_t)pid > 0) {
                if (ptr->pid != pid)
                    continue;
            } else if (pid == 0) {
                if (ptr->pgid != current_task->pgid)
                    continue;
            } else if (pid != (uint64_t)-1) {
                continue;
            }

            if (ptr->state == TASK_DIED) {
                found_dead = ptr;
                break;
            } else {
                found_alive = ptr;
                break;
            }
        }

        if (found_dead) {
            target = found_dead;
            break;
        }

        if (found_alive && (options & WNOHANG)) {
            return 0;
        }

        if (found_alive) {
            found_alive->waitpid = current_task->pid;
            if (found_alive->state != TASK_DIED)
                task_block(current_task, TASK_BLOCKING, -1);
            continue;
        }

        return -ECHILD;
    }

    if (target) {
        if (status) {
            if (target->status < 128) {
                *status = ((target->status & 0xff) << 8);
            } else {
                int sig = target->status - 128;
                *status = (sig & 0xff);
            }
        }

        ret = target->pid;

        target->should_free = true;
    }

    uint64_t continue_ptr_count = 0;
    for (uint64_t i = 1; i < MAX_TASK_NUM; i++) {
        spin_lock(&task_queue_lock);
        task_t *ptr = tasks[i];
        spin_unlock(&task_queue_lock);

        if (ptr == NULL) {
            continue_ptr_count++;
            if (continue_ptr_count >= MAX_CONTINUE_NULL_TASKS)
                break;
            continue;
        }
        continue_ptr_count = 0;

        if (ptr->should_free) {
            free_task(ptr);
        }
    }

    return ret;
}

uint64_t sys_clone(struct pt_regs *regs, uint64_t flags, uint64_t newsp,
                   int *parent_tid, int *child_tid, uint64_t tls) {
    arch_disable_interrupt();

    if (flags & CLONE_VFORK) {
        flags |= CLONE_VM;
        flags |= CLONE_FILES;
        flags |= CLONE_SIGHAND;
        flags |= CLONE_THREAD;
    }

    task_t *child = get_free_task();
    if (child == NULL) {
        return (uint64_t)-ENOMEM;
    }

    can_schedule = false;

    strncpy(child->name, current_task->name, TASK_NAME_MAX);

    child->signal = malloc(sizeof(task_signal_info_t));
    memset(child->signal, 0, sizeof(task_signal_info_t));
    child->signal->signal_lock = SPIN_INIT;

    memset(&child->signal->signal_saved_regs, 0, sizeof(struct pt_regs));

    child->cpu_id = alloc_cpu_id();

    child->kernel_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    child->syscall_stack =
        (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    memset((void *)(child->kernel_stack - STACK_SIZE), 0, STACK_SIZE);
    memset((void *)(child->syscall_stack - STACK_SIZE), 0, STACK_SIZE);

    child->arch_context = malloc(sizeof(arch_context_t));
    memset(child->arch_context, 0, sizeof(arch_context_t));
    arch_context_t orig_context;
    memcpy(&orig_context, current_task->arch_context, sizeof(arch_context_t));
    orig_context.ctx = regs;
    arch_context_copy(child->arch_context, &orig_context, child->kernel_stack,
                      flags);

#if defined(__x86_64__)
    uint64_t tmp;
    asm volatile("movq %%cr3, %0\n\tmovq %0, %%cr3" : "=r"(tmp)::"memory");
#elif defined(__aarch64__)
    asm volatile("dsb ishst\n\t"
                 "tlbi vmalle1is\n\t"
                 "dsb ish\n\t"
                 "isb\n\t");
#elif defined(__riscv__)
    asm volatile("sfence.vma");
#endif

#if defined(__x86_64__)
    uint64_t user_sp = regs->rsp;
#elif defined(__aarch64__)
    uint64_t user_sp = regs->sp_el0;
#elif defined(__riscv__)
    child->arch_context->ctx->ktp = (uint64_t)child;
    uint64_t user_sp = regs->sp;
#elif defined(__loongarch64__)
    uint64_t user_sp = regs->usp;
#endif

    if (newsp) {
        user_sp = newsp;
    }

#if defined(__x86_64__)
    child->arch_context->ctx->rsp = user_sp;
#elif defined(__aarch64__)
    child->arch_context->ctx->sp_el0 = user_sp;
#elif defined(__riscv__)
    child->arch_context->ctx->sp = user_sp;
#elif defined(__loongarch64__)
    regs->usp = user_sp;
#endif

    child->is_kernel = false;
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

    child->cwd = current_task->cwd;
    child->cmdline = strdup(current_task->cmdline);

    child->exec_node = current_task->exec_node;
    if (child->exec_node)
        child->exec_node->refcount++;

    child->load_start = current_task->load_start;
    child->load_end = current_task->load_end;

    child->fd_info = (flags & CLONE_FILES) ? current_task->fd_info
                                           : malloc(sizeof(fd_info_t));

    if (!(flags & CLONE_FILES)) {
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

        for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
            fd_t *fd = current_task->fd_info->fds[i];

            if (fd) {
                child->fd_info->fds[i] = malloc(sizeof(fd_t));
                memcpy(child->fd_info->fds[i], fd, sizeof(fd_t));
                fd->node->refcount++;
            } else {
                child->fd_info->fds[i] = NULL;
            }
        }
    } else {
        for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
            fd_t *fd = child->fd_info->fds[i];

            if (fd) {
                child->fd_info->fds[i]->node->refcount++;
            } else {
                child->fd_info->fds[i] = NULL;
            }
        }
    }

    child->fd_info->ref_count++;

    child->signal->signal = 0;
    if (flags & CLONE_SIGHAND) {
        memcpy(child->signal->actions, current_task->signal->actions,
               sizeof(child->signal->actions));
        spin_lock(&current_task->signal->signal_lock);
        child->signal->blocked = current_task->signal->blocked;
        spin_unlock(&current_task->signal->signal_lock);
    } else {
        memset(child->signal->actions, 0, sizeof(child->signal->actions));
        child->signal->blocked = 0;
    }

    if (flags & CLONE_SETTLS) {
#if defined(__x86_64__)
        child->arch_context->fsbase = tls;
#elif defined(__riscv__)
        child->arch_context->ctx->tp = tls;
#endif
    }

    if (flags & CLONE_THREAD) {
        child->tgid = current_task->tgid;
    } else {
        child->tgid = 0;
    }

    if (parent_tid && (flags & CLONE_PARENT_SETTID)) {
        *parent_tid = (int)child->pid;
    }

    if (child_tid && (flags & CLONE_CHILD_SETTID)) {
        *child_tid = (int)child->pid;
    }

    if (child_tid && (flags & CLONE_CHILD_CLEARTID)) {
        child->tidptr = child_tid;
    }

    memset(child->rlim, 0, sizeof(child->rlim));
    child->rlim[RLIMIT_STACK] = (struct rlimit){
        USER_STACK_END - USER_STACK_START, USER_STACK_END - USER_STACK_START};
    child->rlim[RLIMIT_NPROC] = (struct rlimit){MAX_TASK_NUM, MAX_TASK_NUM};
    child->rlim[RLIMIT_NOFILE] = (struct rlimit){MAX_FD_NUM, MAX_FD_NUM};
    child->rlim[RLIMIT_CORE] = (struct rlimit){0, 0};

    child->child_vfork_done = false;

    if ((flags & CLONE_VM)) {
        child->is_vfork = true;
    } else {
        child->is_vfork = false;
    }
    child->is_clone = true;
    child->should_free = false;

    procfs_on_new_task(child);

    child->state = TASK_READY;
    child->current_state = TASK_READY;

    current_task->child_vfork_done = false;

    child->sched_info = calloc(1, sizeof(struct sched_entity));
    add_rrs_entity(child, schedulers[child->cpu_id]);

    can_schedule = true;

    if ((flags & CLONE_VFORK)) {
        while (!current_task->child_vfork_done) {
            arch_yield();
        }

        current_task->child_vfork_done = false;
    }

    return child->pid;
}

uint64_t sys_nanosleep(struct timespec *req, struct timespec *rem) {
    if (req->tv_sec < 0)
        return (uint64_t)-EINVAL;

    if (req->tv_sec < 0 || req->tv_nsec >= 1000000000L) {
        return (uint64_t)-EINVAL;
    }

    uint64_t start = nano_time();
    uint64_t target = start + (req->tv_sec * 1000000000ULL) + req->tv_nsec;

    do {
        if (signals_pending_quick(current_task)) {
            if (rem) {
                uint64_t remaining = target - nano_time();
                struct timespec remain_ts = {.tv_sec = remaining / 1000000000,
                                             .tv_nsec = remaining % 1000000000};
                memcpy(rem, &remain_ts, sizeof(struct timespec));
            }
            return (uint64_t)-EINTR;
        }

        arch_enable_interrupt();
        arch_pause();
    } while (target > nano_time());
    arch_disable_interrupt();

    return 0;
}

uint64_t sys_prctl(uint64_t option, uint64_t arg2, uint64_t arg3, uint64_t arg4,
                   uint64_t arg5) {
    switch (option) {
    case PR_SET_NAME: // 设置进程名 (PR_SET_NAME=15)
        strncpy(current_task->name, (char *)arg2, TASK_NAME_MAX);
        return 0;

    case PR_GET_NAME: // 获取进程名 (PR_GET_NAME=16)
        strncpy((char *)arg2, current_task->name, TASK_NAME_MAX);
        return 0;

    case PR_SET_SECCOMP: // 启用seccomp过滤
        if (arg2 == SECCOMP_MODE_STRICT) {
            // current_task->seccomp_mode = SECCOMP_MODE_STRICT;
            return 0;
        }
        return -EINVAL;

    case PR_GET_SECCOMP: // 查询seccomp状态
        // return current_task->seccomp_mode;
        return 0;

    case PR_SET_TIMERSLACK:
        return 0;

    default:
        return -EINVAL; // 未实现的功能返回不支持
    }
}

void ms_to_timeval(uint64_t ms, struct timeval *tv) {
    tv->tv_sec = ms / 1000;
    tv->tv_usec = (ms % 1000) * 1000; // 转换为微秒保持结构体定义
}

uint64_t timeval_to_ms(struct timeval tv) {
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000; // 微秒转毫秒
}

void sched_update_itimer() {
    uint64_t rtAt = current_task->itimer_real.at;
    uint64_t rtReset = current_task->itimer_real.reset;

    uint64_t now = nano_time() / 1000000;

    if (rtAt && rtAt <= now) {
        task_commit_signal(current_task, SIGALRM, NULL);

        if (rtReset) {
            current_task->itimer_real.at = now + rtReset;
        } else {
            current_task->itimer_real.at = 0;
        }
    }

    for (int j = 0; j < MAX_TIMERS_NUM; j++) {
        if (current_task->timers[j] == NULL)
            break;
        kernel_timer_t *kt = current_task->timers[j];
        if (kt->expires && now >= kt->expires) {
            task_commit_signal(current_task, kt->sigev_signo, NULL);

            if (kt->interval)
                kt->expires += kt->interval;
            else
                kt->expires = 0;
        }
    }
}

extern int timerfdfs_id;

void sched_update_timerfd() {
    if (current_task->fd_info && current_task->fd_info->ref_count) {
        uint64_t continue_null_fd_count = 0;
        for (int fd = 3; fd < MAX_FD_NUM; fd++) {
            fd_t *file = current_task->fd_info->fds[fd];
            if (file == NULL) {
                continue_null_fd_count++;
                if (continue_null_fd_count >= 20)
                    break;
                continue;
            }

            continue_null_fd_count = 0;

            if (file && file->node->fsid == timerfdfs_id) {
                timerfd_t *tfd = file->node->handle;

                // 根据时钟类型获取当前时间
                uint64_t now;
                if (tfd->timer.clock_type == CLOCK_MONOTONIC) {
                    now = nano_time();
                } else {
                    // CLOCK_REALTIME
                    tm time;
                    time_read(&time);
                    now = (uint64_t)mktime(&time) * 1000000000ULL;
                }

                if (tfd->timer.expires && now >= tfd->timer.expires) {
                    if (tfd->timer.interval) {
                        uint64_t delta = now - tfd->timer.expires;
                        uint64_t periods = delta / tfd->timer.interval + 1;
                        tfd->count += periods;
                        tfd->timer.expires += periods * tfd->timer.interval;
                    } else {
                        tfd->count++;
                        tfd->timer.expires = 0;
                    }
                }
            }
        }
    }
}

void sched_check_wakeup() {
    uint64_t continue_ptr_count = 0;
    for (size_t i = 1; i < MAX_TASK_NUM; i++) {
        spin_lock(&task_queue_lock);
        task_t *ptr = tasks[i];
        spin_unlock(&task_queue_lock);
        if (ptr == NULL) {
            continue_ptr_count++;
            if (continue_ptr_count >= MAX_CONTINUE_NULL_TASKS)
                break;
            continue;
        }
        continue_ptr_count = 0;

        if (ptr->state == TASK_BLOCKING && nano_time() > ptr->force_wakeup_ns) {
            task_unblock(ptr, ETIMEDOUT);
            ptr->force_wakeup_ns = UINT64_MAX;
        }
    }
}

size_t sys_setitimer(int which, struct itimerval *value,
                     struct itimerval *old) {
    if (which != 0)
        return (size_t)-ENOSYS;

    uint64_t rt_at = current_task->itimer_real.at;
    uint64_t rt_reset = current_task->itimer_real.reset;

    tm time_now;
    time_read(&time_now);
    uint64_t now = nano_time() / 1000000;

    if (old) {
        uint64_t remaining = rt_at > now ? rt_at - now : 0;
        ms_to_timeval(remaining, &old->it_value);
        ms_to_timeval(rt_reset, &old->it_interval);
    }

    if (value) {
        uint64_t targValue =
            value->it_value.tv_sec * 1000 + value->it_value.tv_usec / 1000;
        uint64_t targInterval = value->it_interval.tv_sec * 1000 +
                                value->it_interval.tv_usec / 1000;

        current_task->itimer_real.at = targValue ? (now + targValue) : 0ULL;
        current_task->itimer_real.reset = targInterval;
    }

    return 0;
}

uint64_t sys_timer_create(clockid_t clockid, struct sigevent *sevp,
                          timer_t *timerid) {
    kernel_timer_t *kt = NULL;
    uint64_t i;
    for (i = 0; i < MAX_TIMERS_NUM; i++) {
        if (current_task->timers[i] == NULL) {
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

    if (sevp) {
        struct sigevent ksev;
        memcpy(&ksev, sevp, sizeof(struct sigevent));

        kt->sigev_signo = ksev.sigev_signo;
        kt->sigev_value = ksev.sigev_value;
        kt->sigev_notify = ksev.sigev_notify;
    }

    *timerid = (timer_t)i;

    return 0;
}

uint64_t sys_timer_settime(timer_t timerid, const struct itimerval *new_value,
                           struct itimerval *old_value) {
    uint64_t idx = (uint64_t)timerid;
    if (idx >= MAX_TIMERS_NUM)
        return -EINVAL;

    kernel_timer_t *kt = current_task->timers[idx];

    struct itimerval kts;
    memcpy(&kts, new_value, sizeof(*new_value));

    uint64_t interval = new_value->it_interval.tv_sec * 1000 +
                        new_value->it_interval.tv_usec / 1000;
    uint64_t expires =
        new_value->it_value.tv_sec * 1000 + new_value->it_value.tv_usec / 1000;

    uint64_t now = nano_time() / 1000000;

    if (old_value) {
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

uint64_t sys_reboot(int magic1, int magic2, uint32_t cmd, void *arg) {
    if (magic1 != LINUX_REBOOT_MAGIC1 || magic2 != LINUX_REBOOT_MAGIC2)
        return (uint64_t)-EINVAL;

    uacpi_status ret;

    switch (cmd) {
    case LINUX_REBOOT_CMD_CAD_OFF:
        cad_enabled = false;
        return 0;
    case LINUX_REBOOT_CMD_CAD_ON:
        cad_enabled = true;
        return 0;
    case LINUX_REBOOT_CMD_RESTART:
    case LINUX_REBOOT_CMD_RESTART2:
        uacpi_prepare_for_sleep_state(UACPI_SLEEP_STATE_S5);

        ret = uacpi_reboot();
        if (uacpi_unlikely_error(ret)) {
            return (uint64_t)-EIO;
        }

        return 0;
    case LINUX_REBOOT_CMD_POWER_OFF:
        ret = uacpi_prepare_for_sleep_state(UACPI_SLEEP_STATE_S5);
        if (uacpi_unlikely_error(ret)) {
            return (uint64_t)-EIO;
        }

        arch_disable_interrupt();
        ret = uacpi_enter_sleep_state(UACPI_SLEEP_STATE_S5);
        if (uacpi_unlikely_error(ret)) {
            arch_enable_interrupt();
            return (uint64_t)-EIO;
        }

        return 0;
    default:
        return (uint64_t)-EINVAL;
        break;
    }
}

uint64_t sys_getpgid(uint64_t pid) {
    if (pid) {
        return tasks[pid] ? tasks[pid]->pgid : -ESRCH;
    } else
        return current_task->pgid;
}

uint64_t sys_setpgid(uint64_t pid, uint64_t pgid) {
    if (pid) {
        if (!tasks[pid])
            return -ESRCH;
        tasks[pid]->pgid = pgid ? pgid : tasks[pid]->pgid;
    } else {
        current_task->pgid = pgid ? pgid : current_task->pgid;
    }
    return 0;
}

uint64_t sys_setpriority(int which, int who, int niceval) {
    task_t *task = NULL;
    switch (which) {
    case PRIO_PROCESS:
        task = tasks[who];
        if (!task)
            return -ESRCH;

        return 0;

    default:
        printk("sys_setpriority: Unsupported which: %d\n", which);
        return (uint64_t)-EINVAL;
    }
}

extern void task_signal();

void schedule(uint64_t sched_flags) {
    arch_disable_interrupt();

    sched_update_itimer();
    sched_update_timerfd();

    task_t *prev = current_task;
    task_t *next = rrs_pick_next_task(schedulers[current_cpu_id]);

    if (next->state == TASK_DIED || next->arch_context->dead) {
        next = idle_tasks[current_cpu_id];
    }

    if (prev == next) {
        goto ret;
    }

    prev->current_state = prev->state;
    next->current_state = TASK_RUNNING;

    arch_set_current(next);

    switch_to(prev, next);

ret:
    if (!(sched_flags & SCHED_FLAG_YIELD))
        task_signal();

    arch_enable_interrupt();
}

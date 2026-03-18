#include <boot/boot.h>
#include <init/abis.h>
#include <libs/string_builder.h>
#include <task/task_syscall.h>

extern hashmap_t task_parent_map;
extern hashmap_t task_pgid_map;
extern spinlock_t should_free_lock;

#define LINUX_USER_HZ 100

static int read_task_file_into_user_memory(task_t *task, vfs_node_t *node,
                                           uint64_t uaddr, size_t offset,
                                           size_t size) {
    if (!task || !task->arch_context || !task->mm || !node)
        return -EFAULT;
    if (size == 0)
        return 0;
    if (check_user_overflow(uaddr, size))
        return -EFAULT;

    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    uint64_t va = uaddr;
    size_t remain = size;
    size_t file_off = offset;

    while (remain > 0) {
        uint64_t page_va = PADDING_DOWN(va, DEFAULT_PAGE_SIZE);
        uint64_t pa = translate_address(pgdir, page_va);
        if (!pa)
            return -EFAULT;

        size_t in_page = va - page_va;
        size_t chunk = MIN(remain, DEFAULT_PAGE_SIZE - in_page);
        size_t loaded = 0;
        while (loaded < chunk) {
            ssize_t ret =
                vfs_read(node, (void *)(phys_to_virt(pa) + in_page + loaded),
                         file_off + loaded, chunk - loaded);
            if (ret < 0)
                return ret;
            if (ret == 0)
                break;
            loaded += (size_t)ret;
        }

        va += chunk;
        file_off += chunk;
        remain -= chunk;

        if (loaded < chunk)
            break;
    }

    return 0;
}

static int zero_task_user_memory(task_t *task, uint64_t uaddr, size_t size) {
    if (!task || !task->arch_context || !task->mm)
        return -EFAULT;
    if (size == 0)
        return 0;
    if (check_user_overflow(uaddr, size))
        return -EFAULT;

    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    uint64_t va = uaddr;
    size_t remain = size;

    while (remain > 0) {
        uint64_t page_va = PADDING_DOWN(va, DEFAULT_PAGE_SIZE);
        uint64_t pa = translate_address(pgdir, page_va);
        if (!pa)
            return -EFAULT;

        size_t in_page = va - page_va;
        size_t chunk = MIN(remain, DEFAULT_PAGE_SIZE - in_page);
        memset((void *)(phys_to_virt(pa) + in_page), 0, chunk);

        va += chunk;
        remain -= chunk;
    }

    return 0;
}

int write_task_user_memory(task_t *task, uint64_t uaddr, const void *src,
                           size_t size) {
    if (!task || !task->arch_context || !task->mm)
        return -EFAULT;
    if (!src || size == 0)
        return 0;
    if (check_user_overflow(uaddr, size))
        return -EFAULT;

    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    const uint8_t *in = (const uint8_t *)src;
    uint64_t va = uaddr;
    size_t remain = size;

    while (remain > 0) {
        uint64_t pa = translate_address(pgdir, va);
        if (!pa)
            return -EFAULT;

        size_t page_left = DEFAULT_PAGE_SIZE - (va & (DEFAULT_PAGE_SIZE - 1));
        size_t chunk = MIN(remain, page_left);
        memcpy((void *)phys_to_virt(pa), in, chunk);

        va += chunk;
        in += chunk;
        remain -= chunk;
    }

    return 0;
}

int read_task_user_memory(task_t *task, uint64_t uaddr, void *dst,
                          size_t size) {
    if (!task || !task->arch_context || !task->mm)
        return -EFAULT;
    if (!dst || size == 0)
        return 0;
    if (check_user_overflow(uaddr, size))
        return -EFAULT;

    uint64_t *pgdir = (uint64_t *)phys_to_virt(task->mm->page_table_addr);
    uint8_t *out = (uint8_t *)dst;
    uint64_t va = uaddr;
    size_t remain = size;

    while (remain > 0) {
        uint64_t pa = translate_address(pgdir, va);
        if (!pa)
            return -EFAULT;

        size_t page_left = DEFAULT_PAGE_SIZE - (va & (DEFAULT_PAGE_SIZE - 1));
        size_t chunk = MIN(remain, page_left);
        memcpy(out, (const void *)phys_to_virt(pa), chunk);

        va += chunk;
        out += chunk;
        remain -= chunk;
    }

    return 0;
}

static uint64_t elf_segment_vma_flags(uint32_t p_flags) {
    uint64_t vm_flags = 0;

    if (p_flags & PF_R)
        vm_flags |= VMA_READ;
    if (p_flags & PF_W)
        vm_flags |= VMA_WRITE;
    if (p_flags & PF_X)
        vm_flags |= VMA_EXEC;

    return vm_flags;
}

static uint64_t elf_segment_pt_flags(uint32_t p_flags) {
    uint64_t pt_flags = PT_FLAG_U;

    if (p_flags & PF_R)
        pt_flags |= PT_FLAG_R;
    if (p_flags & PF_W)
        pt_flags |= PT_FLAG_W;
    if (p_flags & PF_X)
        pt_flags |= PT_FLAG_X;

    return pt_flags;
}

static int map_task_elf_segment(task_t *task, vfs_node_t *node,
                                uint64_t load_base, const Elf64_Phdr *phdr) {
    if (!task || !task->mm || !node || !phdr || phdr->p_type != PT_LOAD)
        return -EINVAL;

    uint64_t seg_addr = load_base + phdr->p_vaddr;
    uint64_t aligned_addr = PADDING_DOWN(seg_addr, DEFAULT_PAGE_SIZE);
    uint64_t aligned_offset = PADDING_DOWN(phdr->p_offset, DEFAULT_PAGE_SIZE);
    uint64_t page_prefix = seg_addr - aligned_addr;
    uint64_t file_map_size = phdr->p_filesz + page_prefix;
    uint64_t mem_map_size = phdr->p_memsz + page_prefix;
    uint64_t alloc_size = PADDING_UP(mem_map_size, DEFAULT_PAGE_SIZE);
    uint64_t final_flags = elf_segment_pt_flags(phdr->p_flags);
    uint64_t load_flags = final_flags | PT_FLAG_W;

    if (file_map_size < phdr->p_filesz || mem_map_size < phdr->p_memsz ||
        alloc_size < mem_map_size || phdr->p_filesz > phdr->p_memsz) {
        return -EINVAL;
    }

    map_page_range(get_current_page_dir(true), aligned_addr, (uint64_t)-1,
                   alloc_size, load_flags);

    int ret = read_task_file_into_user_memory(task, node, aligned_addr,
                                              aligned_offset, file_map_size);
    if (ret != 0)
        return ret;

    if (mem_map_size > file_map_size) {
        ret = zero_task_user_memory(task, aligned_addr + file_map_size,
                                    mem_map_size - file_map_size);
        if (ret != 0)
            return ret;
    }

    if (load_flags != final_flags) {
        map_change_attribute_range(get_current_page_dir(true), aligned_addr,
                                   alloc_size, final_flags);
    }

    return 0;
}

uint64_t timeval_to_ms(struct timeval tv) {
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000; // 微秒转毫秒
}

void ms_to_timeval(uint64_t ms, struct timeval *tv) {
    tv->tv_sec = ms / 1000;
    tv->tv_usec = (ms % 1000) * 1000; // 转换为微秒保持结构体定义
}

extern task_index_bucket_t *task_index_bucket_get_or_create(hashmap_t *map,
                                                            uint64_t key);

extern void task_index_bucket_destroy_if_empty(hashmap_t *map, uint64_t key);

extern void task_parent_index_attach_locked(task_t *task);

extern void task_parent_index_detach_locked(task_t *task, bool prune_bucket);

static void task_pgid_index_attach_locked(task_t *task) {
    if (!task_should_index_pgid(task, task->pgid) ||
        !llist_empty(&task->pgid_node)) {
        return;
    }

    task_index_bucket_t *bucket =
        task_index_bucket_get_or_create(&task_pgid_map, (uint64_t)task->pgid);
    if (!bucket) {
        return;
    }

    llist_append(&bucket->tasks, &task->pgid_node);
    bucket->count++;
}

static void task_pgid_index_detach_locked(task_t *task) {
    if (!task_should_index_pgid(task, task->pgid) ||
        llist_empty(&task->pgid_node)) {
        return;
    }

    uint64_t pgid = (uint64_t)task->pgid;
    task_index_bucket_t *bucket =
        task_index_bucket_lookup(&task_pgid_map, pgid);
    llist_delete(&task->pgid_node);

    if (bucket && bucket->count) {
        bucket->count--;
    }

    task_index_bucket_destroy_if_empty(&task_pgid_map, pgid);
}

static void task_pid_index_remove_locked(task_t *task) {
    if (!task || !task->pid) {
        return;
    }

    hashmap_remove(&task_pid_map, task->pid);
}

static void task_set_pgid_locked(task_t *task, int64_t pgid) {
    if (!task || task->pgid == pgid) {
        return;
    }

    task_pgid_index_detach_locked(task);
    task->pgid = pgid;
    task_pgid_index_attach_locked(task);
}

static void task_set_thread_group_pgid_locked(task_t *task, int64_t pgid) {
    if (!task)
        return;

    uint64_t tgid = task_effective_tgid(task);
    if (!task_pid_map.buckets)
        return;

    for (size_t i = 0; i < task_pid_map.bucket_count; i++) {
        hashmap_entry_t *entry = &task_pid_map.buckets[i];
        if (!hashmap_entry_is_occupied(entry))
            continue;

        task_t *peer = (task_t *)entry->value;
        if (!peer || task_effective_tgid(peer) != tgid)
            continue;

        task_set_pgid_locked(peer, pgid);
    }
}

static void task_set_thread_group_sid_locked(task_t *task, int64_t sid) {
    if (!task)
        return;

    uint64_t tgid = task_effective_tgid(task);
    if (!task_pid_map.buckets)
        return;

    for (size_t i = 0; i < task_pid_map.bucket_count; i++) {
        hashmap_entry_t *entry = &task_pid_map.buckets[i];
        if (!hashmap_entry_is_occupied(entry))
            continue;

        task_t *peer = (task_t *)entry->value;
        if (!peer || task_effective_tgid(peer) != tgid)
            continue;

        peer->sid = sid;
    }
}

extern void task_enqueue_should_free(task_t *task);
extern task_t *task_dequeue_should_free(void);

static inline struct timeval task_ns_to_timeval(uint64_t ns) {
    struct timeval tv;
    tv.tv_sec = (long)(ns / 1000000000ULL);
    tv.tv_usec = (long)((ns % 1000000000ULL) / 1000ULL);
    return tv;
}

static inline void task_fill_rusage(task_t *task, bool include_children,
                                    struct rusage *rusage) {
    if (!rusage)
        return;

    memset(rusage, 0, sizeof(*rusage));
    if (!task)
        return;

    uint64_t utime_ns =
        include_children ? task_total_user_ns(task) : task_self_user_ns(task);
    uint64_t stime_ns =
        include_children ? task_total_system_ns(task) : task->system_time_ns;

    rusage->ru_utime = task_ns_to_timeval(utime_ns);
    rusage->ru_stime = task_ns_to_timeval(stime_ns);
}

extern void task_timeout_cancel(task_t *task);

void free_task(task_t *ptr) {
    task_timeout_cancel(ptr);

    spin_lock(&should_free_lock);
    if (!llist_empty(&ptr->free_node))
        llist_delete(&ptr->free_node);
    spin_unlock(&should_free_lock);

    spin_lock(&task_queue_lock);
    task_pid_index_remove_locked(ptr);
    task_parent_index_detach_locked(ptr, true);
    task_pgid_index_detach_locked(ptr);
    spin_unlock(&task_queue_lock);

    if (!ptr->is_kernel)
        free_page_table(ptr->mm);

    if (ptr->cmdline)
        free(ptr->cmdline);

    ptr->arg_start = 0;
    ptr->arg_end = 0;
    ptr->env_start = 0;
    ptr->env_end = 0;

    shm_exit(ptr);
    task_signal_free(ptr->signal);
    ptr->signal = NULL;
    arch_context_free(ptr->arch_context);
    free(ptr->arch_context);

    free(ptr->sched_info);
    ptr->sched_info = NULL;

    free_frames_bytes((void *)(ptr->kernel_stack - STACK_SIZE), STACK_SIZE);
    free_frames_bytes((void *)(ptr->syscall_stack - STACK_SIZE), STACK_SIZE);

    free(ptr);
}

static void task_execve_free_string_array(char **strings, int count) {
    if (!strings) {
        return;
    }

    for (int i = 0; i < count; i++) {
        if (strings[i]) {
            free(strings[i]);
        }
    }

    free(strings);
}

static uint64_t simple_rand() {
    uint32_t seed = boot_get_boottime() * 100 + nano_time() / 10;
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
                    uint64_t at_base, const char *execfn) {
    uint64_t tmp_stack = current_stack;
    uint64_t arg_low = UINT64_MAX;
    uint64_t arg_high = 0;
    uint64_t env_low = UINT64_MAX;
    uint64_t env_high = 0;

    const char *execfn_name = execfn ? execfn : task->name;
    size_t name_len = strlen(execfn_name) + 1;
    PUSH_BYTES_TO_STACK(tmp_stack, execfn_name, name_len);
    uint64_t execfn_ptr = tmp_stack;

    uint64_t random_values[2] = {simple_rand(), simple_rand()};
    PUSH_BYTES_TO_STACK(tmp_stack, random_values, 16);
    uint64_t random_ptr = tmp_stack;

    uint64_t *envp_addrs = NULL;
    if (envp_count > 0 && envp != NULL) {
        envp_addrs = (uint64_t *)malloc(envp_count * sizeof(uint64_t));

        for (int i = envp_count - 1; i >= 0; i--) {
            size_t len = strlen(envp[i]) + 1;
            PUSH_BYTES_TO_STACK(tmp_stack, envp[i], len);
            envp_addrs[i] = tmp_stack;
            if (tmp_stack < env_low)
                env_low = tmp_stack;
            if (tmp_stack + len > env_high)
                env_high = tmp_stack + len;
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
            if (tmp_stack < arg_low)
                arg_low = tmp_stack;
            if (tmp_stack + len > arg_high)
                arg_high = tmp_stack + len;
        }
    }

    task->arg_start = 0;
    task->arg_end = 0;
    task->env_start = 0;
    task->env_end = 0;

    if (argv_count > 0 && argv_addrs != NULL && arg_low < arg_high) {
        task->arg_start = arg_low;
        task->arg_end = arg_high;
    }

    if (envp_count > 0 && envp_addrs != NULL && env_low < env_high) {
        task->env_start = env_low;
        task->env_end = env_high;
    }

    const size_t auxv_pairs = 16;
    size_t qwords_to_push =
        auxv_pairs * 2 + (size_t)argv_count + (size_t)envp_count + 3;

    tmp_stack &= ~0xFULL;
    if (qwords_to_push & 1)
        tmp_stack -= sizeof(uint64_t);

    PUSH_TO_STACK(tmp_stack, uint64_t, 0);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_NULL);

    PUSH_TO_STACK(tmp_stack, uint64_t, execfn_ptr);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_EXECFN);

    PUSH_TO_STACK(tmp_stack, uint64_t, random_ptr);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_RANDOM);

    PUSH_TO_STACK(tmp_stack, uint64_t, task->egid);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_EGID);

    PUSH_TO_STACK(tmp_stack, uint64_t, task->gid);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_GID);

    PUSH_TO_STACK(tmp_stack, uint64_t, task->euid);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_EUID);

    PUSH_TO_STACK(tmp_stack, uint64_t, task->uid);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_UID);

    PUSH_TO_STACK(tmp_stack, uint64_t, e_entry);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_ENTRY);

    PUSH_TO_STACK(tmp_stack, uint64_t, 0);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_FLAGS);

    PUSH_TO_STACK(tmp_stack, uint64_t, 0);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_SECURE);

    PUSH_TO_STACK(tmp_stack, uint64_t, phnum);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_PHNUM);

    PUSH_TO_STACK(tmp_stack, uint64_t, sizeof(Elf64_Phdr));
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_PHENT);

    PUSH_TO_STACK(tmp_stack, uint64_t, phdr);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_PHDR);

    PUSH_TO_STACK(tmp_stack, uint64_t, DEFAULT_PAGE_SIZE);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_PAGESZ);

    PUSH_TO_STACK(tmp_stack, uint64_t, LINUX_USER_HZ);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_CLKTCK);

    PUSH_TO_STACK(tmp_stack, uint64_t, at_base);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_BASE);

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

    return tmp_stack;
}

static int register_elf_load_vma(task_t *task, vfs_node_t *node,
                                 const char *name, uint64_t load_base,
                                 const Elf64_Phdr *phdr) {
    if (!task || !task->mm || !phdr || phdr->p_type != PT_LOAD ||
        phdr->p_memsz == 0) {
        return 0;
    }

    uint64_t seg_addr = load_base + phdr->p_vaddr;
    uint64_t aligned_addr = PADDING_DOWN(seg_addr, DEFAULT_PAGE_SIZE);
    uint64_t aligned_offset = PADDING_DOWN(phdr->p_offset, DEFAULT_PAGE_SIZE);
    uint64_t size_diff = seg_addr - aligned_addr;
    uint64_t map_size =
        PADDING_UP(phdr->p_memsz + size_diff, DEFAULT_PAGE_SIZE);

    vma_t *vma = vma_alloc();
    if (!vma)
        return -ENOMEM;

    vma->vm_start = aligned_addr;
    vma->vm_end = aligned_addr + map_size;
    vma->vm_flags = elf_segment_vma_flags(phdr->p_flags);
    vma->vm_type = VMA_TYPE_FILE;
    vma->vm_offset = aligned_offset;
    vma->vm_file_flags = 0;
    vma->node = node;
    if (node)
        vfs_node_ref_get(node);
    if (name)
        vma->vm_name = strdup(name);

    if (vma_insert(&task->mm->task_vma_mgr, vma) != 0) {
        vma_free(vma);
        return -ENOMEM;
    }

    return 0;
}

static int task_execve_dethread(task_t *self) {
    if (!self)
        return -EINVAL;

    uint64_t tgid = task_effective_tgid(self);
    if (task_thread_group_count(tgid) <= 1)
        return 0;

    if (self->pid != tgid)
        return -ENOSYS;

    while (true) {
        bool others_alive = false;

        spin_lock(&task_queue_lock);
        if (task_pid_map.buckets) {
            for (size_t i = 0; i < task_pid_map.bucket_count; i++) {
                hashmap_entry_t *entry = &task_pid_map.buckets[i];
                if (!hashmap_entry_is_occupied(entry))
                    continue;

                task_t *task = (task_t *)entry->value;
                if (!task || task == self || task->state == TASK_DIED ||
                    !task->arch_context || task->arch_context->dead) {
                    continue;
                }
                if (task_effective_tgid(task) != tgid)
                    continue;

                others_alive = true;
                task_send_signal(task, SIGKILL, SI_DETHREAD);
                if (task->state == TASK_BLOCKING ||
                    task->state == TASK_READING_STDIO ||
                    task->state == TASK_UNINTERRUPTABLE) {
                    task_unblock(task, EOK);
                }
            }
        }
        spin_unlock(&task_queue_lock);

        if (!others_alive)
            return 0;

        arch_enable_interrupt();
        schedule(SCHED_FLAG_YIELD);
        arch_disable_interrupt();
    }
}

uint64_t task_execve(const char *path_user, const char **argv,
                     const char **envp) {
    task_t *self = current_task;

    char path[512];
    strncpy(path, path_user, sizeof(path));

    vfs_node_t *node = vfs_open(path, 0);
    if (!node) {
        return (uint64_t)-ENOENT;
    }

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

    uint8_t header_buf[1024];
    ssize_t header_read;
    int shebang_depth = 0;

    while (true) {
        header_read = vfs_read(node, header_buf, 0, sizeof(header_buf));

        if (header_read < 2 || header_buf[0] != '#' || header_buf[1] != '!') {
            break;
        }

        if (++shebang_depth > 4) {
            task_execve_free_string_array(new_argv, argv_count);
            task_execve_free_string_array(new_envp, envp_count);
            return (uint64_t)-ELOOP;
        }

        size_t shebang_len = (header_read < (ssize_t)sizeof(header_buf))
                                 ? (size_t)header_read
                                 : sizeof(header_buf) - 1;
        char *line_start = (char *)header_buf + 2;
        char *line_limit = (char *)header_buf + shebang_len;
        char *line_end = line_start;
        char *interpreter_name;
        char *interpreter_end;
        char *optional_arg = NULL;
        char script_path[sizeof(path)];
        char **replaced_argv = NULL;
        int replaced_argc = 2;
        int replaced_index = 0;
        bool found_newline = false;

        header_buf[shebang_len] = '\0';

        while (line_end < line_limit && *line_end != '\n' &&
               *line_end != '\0') {
            line_end++;
        }
        if (line_end < line_limit && *line_end == '\n') {
            found_newline = true;
        }

        while (line_start < line_end &&
               (*line_start == ' ' || *line_start == '\t')) {
            line_start++;
        }
        while (line_end > line_start &&
               (line_end[-1] == ' ' || line_end[-1] == '\t' ||
                line_end[-1] == '\r')) {
            line_end--;
        }
        *line_end = '\0';

        if (line_start == line_end) {
            task_execve_free_string_array(new_argv, argv_count);
            task_execve_free_string_array(new_envp, envp_count);
            return (uint64_t)-ENOEXEC;
        }

        interpreter_name = line_start;
        interpreter_end = interpreter_name;
        while (interpreter_end < line_end && *interpreter_end != ' ' &&
               *interpreter_end != '\t') {
            interpreter_end++;
        }

        if (!found_newline && header_read >= (ssize_t)sizeof(header_buf) &&
            interpreter_end == line_end) {
            task_execve_free_string_array(new_argv, argv_count);
            task_execve_free_string_array(new_envp, envp_count);
            return (uint64_t)-ENOEXEC;
        }

        if (interpreter_end == interpreter_name) {
            task_execve_free_string_array(new_argv, argv_count);
            task_execve_free_string_array(new_envp, envp_count);
            return (uint64_t)-ENOEXEC;
        }

        if (interpreter_end < line_end) {
            *interpreter_end++ = '\0';
            while (interpreter_end < line_end &&
                   (*interpreter_end == ' ' || *interpreter_end == '\t')) {
                interpreter_end++;
            }
            if (interpreter_end < line_end) {
                optional_arg = interpreter_end;
                replaced_argc++;
            }
        }

        if (argv_count > 1) {
            replaced_argc += argv_count - 1;
        }

        replaced_argv = (char **)calloc(replaced_argc + 1, sizeof(char *));
        if (!replaced_argv) {
            task_execve_free_string_array(new_argv, argv_count);
            task_execve_free_string_array(new_envp, envp_count);
            return (uint64_t)-ENOMEM;
        }

        strncpy(script_path, path, sizeof(script_path));
        script_path[sizeof(script_path) - 1] = '\0';

        replaced_argv[replaced_index++] = strdup(interpreter_name);
        if (!replaced_argv[0]) {
            task_execve_free_string_array(replaced_argv, replaced_index);
            task_execve_free_string_array(new_argv, argv_count);
            task_execve_free_string_array(new_envp, envp_count);
            return (uint64_t)-ENOMEM;
        }

        if (optional_arg) {
            replaced_argv[replaced_index++] = strdup(optional_arg);
            if (!replaced_argv[replaced_index - 1]) {
                task_execve_free_string_array(replaced_argv, replaced_index);
                task_execve_free_string_array(new_argv, argv_count);
                task_execve_free_string_array(new_envp, envp_count);
                return (uint64_t)-ENOMEM;
            }
        }

        replaced_argv[replaced_index++] = strdup(script_path);
        if (!replaced_argv[replaced_index - 1]) {
            task_execve_free_string_array(replaced_argv, replaced_index);
            task_execve_free_string_array(new_argv, argv_count);
            task_execve_free_string_array(new_envp, envp_count);
            return (uint64_t)-ENOMEM;
        }

        for (int i = 1; i < argv_count; i++) {
            replaced_argv[replaced_index++] = strdup(new_argv[i]);
            if (!replaced_argv[replaced_index - 1]) {
                task_execve_free_string_array(replaced_argv, replaced_index);
                task_execve_free_string_array(new_argv, argv_count);
                task_execve_free_string_array(new_envp, envp_count);
                return (uint64_t)-ENOMEM;
            }
        }

        vfs_node_t *interpreter_node = vfs_open(interpreter_name, 0);
        if (!interpreter_node) {
            task_execve_free_string_array(replaced_argv, replaced_index);
            task_execve_free_string_array(new_argv, argv_count);
            task_execve_free_string_array(new_envp, envp_count);
            return (uint64_t)-ENOENT;
        }

        task_execve_free_string_array(new_argv, argv_count);
        new_argv = replaced_argv;
        argv_count = replaced_argc;

        strncpy(path, interpreter_name, sizeof(path));
        path[sizeof(path) - 1] = '\0';
        node = interpreter_node;
    }

    if (header_read < sizeof(Elf64_Ehdr)) {
        for (int i = 0; i < argv_count; i++)
            if (new_argv[i])
                free(new_argv[i]);
        free(new_argv);
        for (int i = 0; i < envp_count; i++)
            if (new_envp[i])
                free(new_envp[i]);
        free(new_envp);
        return (uint64_t)-ENOEXEC;
    }

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)header_buf;

    int dethread_ret = task_execve_dethread(self);
    if (dethread_ret < 0) {
        task_execve_free_string_array(new_argv, argv_count);
        task_execve_free_string_array(new_envp, envp_count);
        return (uint64_t)dethread_ret;
    }

    uint64_t real_load_start = 0;
    if (ehdr->e_type == ET_DYN) {
        real_load_start = PIE_BASE_ADDR;
    }

    uint64_t e_entry = real_load_start + ehdr->e_entry;
    if (e_entry == 0) {
        for (int i = 0; i < argv_count; i++)
            if (new_argv[i])
                free(new_argv[i]);
        free(new_argv);
        for (int i = 0; i < envp_count; i++)
            if (new_envp[i])
                free(new_envp[i]);
        free(new_envp);
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

    shm_exec(self);

    task_mm_info_t *old_mm = self->mm;
    task_mm_info_t *new_mm = (task_mm_info_t *)malloc(sizeof(task_mm_info_t));
    memset(new_mm, 0, sizeof(task_mm_info_t));
    spin_init(&new_mm->lock);
    new_mm->page_table_addr = alloc_frames(1);
    memset((void *)phys_to_virt(new_mm->page_table_addr), 0, DEFAULT_PAGE_SIZE);
#if defined(__x86_64__) || defined(__riscv__)
    memcpy((uint64_t *)phys_to_virt(new_mm->page_table_addr) + 256,
           get_kernel_page_dir() + 256, DEFAULT_PAGE_SIZE / 2);
#endif
    new_mm->ref_count = 1;
    vma_manager_init(&new_mm->task_vma_mgr, true);

    new_mm->brk_start = USER_BRK_START;
    new_mm->brk_current = new_mm->brk_start;
    new_mm->brk_end = USER_BRK_END;

    arch_disable_interrupt();

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

    self->mm = new_mm;

    arch_enable_interrupt();

    if (!self->is_kernel) {
        free_page_table(old_mm);
    }

    uint64_t load_start = UINT64_MAX;
    uint64_t load_end = 0;
    uint64_t interpreter_entry = 0;
    char *interpreter_path = NULL;

    uint64_t phdr_vaddr = 0;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_INTERP) {
            char interp_name[256];
            vfs_read(node, interp_name, phdr[i].p_offset,
                     phdr[i].p_filesz < 256 ? phdr[i].p_filesz : 255);
            interp_name[phdr[i].p_filesz < 256 ? phdr[i].p_filesz : 255] = '\0';

            interpreter_path = strdup(interp_name);

            vfs_node_t *interpreter_node = vfs_open(interp_name, 0);
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

                if (map_task_elf_segment(self, interpreter_node,
                                         INTERPRETER_BASE_ADDR,
                                         &interp_phdr[j]) != 0) {
                    printk("Failed to map interpreter PT_LOAD segment\n");
                }

                if (register_elf_load_vma(
                        self, interpreter_node, interpreter_path,
                        INTERPRETER_BASE_ADDR, &interp_phdr[j]) != 0) {
                    printk("Failed to register interpreter PT_LOAD VMA\n");
                }
            }

            interpreter_entry = INTERPRETER_BASE_ADDR + interp_ehdr.e_entry;
            free(interp_phdr);

        } else if (phdr[i].p_type == PT_LOAD) {
            uint64_t seg_addr = real_load_start + phdr[i].p_vaddr;
            uint64_t aligned_addr = PADDING_DOWN(seg_addr, DEFAULT_PAGE_SIZE);
            uint64_t alloc_size = PADDING_UP(
                phdr[i].p_memsz + (seg_addr - aligned_addr), DEFAULT_PAGE_SIZE);

            if (aligned_addr < load_start)
                load_start = aligned_addr;
            if (aligned_addr + alloc_size > load_end)
                load_end = aligned_addr + alloc_size;

            if (map_task_elf_segment(self, node, real_load_start, &phdr[i]) !=
                0) {
                printk("Failed to map executable PT_LOAD segment\n");
            }

            if (register_elf_load_vma(self, node, path, real_load_start,
                                      &phdr[i]) != 0) {
                printk("Failed to register executable PT_LOAD VMA\n");
            }
        } else if (phdr[i].p_type == PT_PHDR) {
            phdr_vaddr = real_load_start + phdr[i].p_vaddr;
        }
    }

    if (!phdr_vaddr) {
        phdr_vaddr = (uint64_t)(load_start + ehdr->e_phoff);
    }

    if (phdr_allocated) {
        free(phdr);
    }

    vfs_node_ref_get(node);
    self->exec_node = node;

    map_page_range(get_current_page_dir(true),
                   USER_STACK_END - DEFAULT_PAGE_SIZE * 8, (uint64_t)-1,
                   DEFAULT_PAGE_SIZE * 8, PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    uint64_t stack = push_infos(
        self, USER_STACK_END, (char **)new_argv, argv_count, (char **)new_envp,
        envp_count, e_entry, phdr_vaddr, ehdr->e_phnum,
        interpreter_entry ? INTERPRETER_BASE_ADDR : 0, path);

    if (self->clone_flags & CLONE_FILES) {
        fd_info_t *old = self->fd_info;
        fd_info_t *new = calloc(1, sizeof(fd_info_t));
        new->ref_count++;

        mutex_init(&new->fdt_lock);
        with_fd_info_lock(old, {
            for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
                fd_t *fd = old->fds[i];

                if (fd) {
                    new->fds[i] = vfs_dup(fd);
                } else {
                    new->fds[i] = NULL;
                }
            }
        });

        old->ref_count--;

        self->fd_info = new;
    }

    string_builder_t *builder = create_string_builder(DEFAULT_PAGE_SIZE * 4);
    for (int i = 0; i < argv_count; i++) {
        string_builder_append(builder, new_argv[i]);
        if (i != argv_count - 1)
            string_builder_append(builder, " ");
    }
    char *cmdline = builder->data;
    free(builder);

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

    with_fd_info_lock(self->fd_info, {
        for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
            if (!self->fd_info->fds[i])
                continue;

            if (self->fd_info->fds[i]->close_on_exec) {
                fd_t *entry = self->fd_info->fds[i];
                self->fd_info->fds[i] = NULL;
                system_abi->on_close_file(self, i, entry);
                fd_release(entry);
            }
        }
    });

    task_signal_info_t *new_signal = task_signal_reset_after_exec(self);
    if (!new_signal)
        return (uint64_t)-ENOMEM;
    task_signal_free(self->signal);
    self->signal = new_signal;

    self->cmdline = strdup(cmdline);
    free(cmdline);
    self->load_start = load_start;
    self->load_end = load_end;

    if (interpreter_path)
        free(interpreter_path);

    strncpy(self->name, path, TASK_NAME_MAX);
    self->name[TASK_NAME_MAX - 1] = '\0';

    vma_t *stack_vma = vma_alloc();

    stack_vma->vm_start = USER_STACK_START;
    stack_vma->vm_end = USER_STACK_END;
    stack_vma->vm_flags |= VMA_ANON | VMA_READ | VMA_WRITE | VMA_STACK;

    stack_vma->vm_type = VMA_TYPE_ANON;
    stack_vma->vm_name = strdup("[stack]");

    vma_t *region = vma_find_intersection(&self->mm->task_vma_mgr,
                                          USER_STACK_START, USER_STACK_END);
    if (!region) {
        vma_insert(&self->mm->task_vma_mgr, stack_vma);
    }

    task_complete_vfork(self);
    self->clone_flags = 0;
    self->is_clone = false;
    self->is_kernel = false;

    arch_to_user_mode(self->arch_context,
                      interpreter_entry ? interpreter_entry : e_entry, stack);

    return (uint64_t)-EAGAIN;
}

uint64_t sys_waitpid(uint64_t pid, int *status, uint64_t options,
                     struct rusage *rusage) {
    task_t *target = NULL;
    uint64_t ret = -ECHILD;
    int64_t wait_pid = (int64_t)pid;
    uint64_t wait_parent_pid = task_effective_wait_parent_pid(current_task);

    if (status && check_user_overflow((uint64_t)status, sizeof(int))) {
        return -EFAULT;
    }
    if (rusage &&
        check_user_overflow((uint64_t)rusage, sizeof(struct rusage))) {
        return -EFAULT;
    }

    bool has_children = false;
    spin_lock(&task_queue_lock);
    task_index_bucket_t *children =
        task_index_bucket_lookup(&task_parent_map, wait_parent_pid);
    has_children = children && children->count > 0;
    spin_unlock(&task_queue_lock);

    if (!has_children) {
        return -ECHILD;
    }

    while (1) {
        task_t *found_alive = NULL;
        task_t *found_dead = NULL;

        arch_disable_interrupt();

        spin_lock(&task_queue_lock);
        task_index_bucket_t *children =
            task_index_bucket_lookup(&task_parent_map, wait_parent_pid);
        struct llist_header *node = children ? children->tasks.next : NULL;
        while (children && node != &children->tasks) {
            task_t *ptr = list_entry(node, task_t, parent_node);
            node = node->next;
            if (!ptr)
                continue;

            if (!task_has_parent(ptr))
                continue;
            if (task_parent_wait_key(ptr) != wait_parent_pid)
                continue;

            if (wait_pid > 0) {
                if (ptr->pid != (uint64_t)wait_pid)
                    continue;
            } else if (wait_pid == 0) {
                if (ptr->pgid != current_task->pgid)
                    continue;
            } else if (wait_pid < -1) {
                if (ptr->pgid != -wait_pid)
                    continue;
            } else if (wait_pid != -1) {
                continue;
            }

            if (ptr->state == TASK_DIED) {
                found_dead = ptr;
                break;
            } else {
                found_alive = ptr;
            }
        }
        spin_unlock(&task_queue_lock);

        arch_enable_interrupt();

        if (found_dead) {
            target = found_dead;
            arch_disable_interrupt();
            break;
        }

        if (found_alive && (options & WNOHANG)) {
            arch_disable_interrupt();
            return 0;
        }

        if (found_alive) {
            found_alive->waitpid = current_task->pid;
            if (found_alive->state != TASK_DIED)
                task_block(current_task, TASK_BLOCKING, -1, "waitpid");
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
        if (rusage) {
            task_fill_rusage(target, true, rusage);
        }

        ret = target->pid;
        task_aggregate_child_usage(current_task, target);

        task_enqueue_should_free(target);
    }

    while (true) {
        task_t *to_free = task_dequeue_should_free();
        if (!to_free)
            break;
        free_task(to_free);
    }

    return ret;
}

uint64_t sys_waitid(int idtype, uint64_t id, siginfo_t *infop, int options,
                    struct rusage *rusage) {
    task_t *target = NULL;
    uint64_t ret = 0;
    int match_idtype = idtype;
    uint64_t match_id = id;
    uint64_t wait_parent_pid = task_effective_wait_parent_pid(current_task);

    if (idtype < P_ALL || idtype > P_PIDFD)
        return -EINVAL;

    if (!(options & (WEXITED | WSTOPPED | WCONTINUED)))
        return -EINVAL;
    if (infop && check_user_overflow((uint64_t)infop, sizeof(siginfo_t))) {
        return -EFAULT;
    }
    if (rusage &&
        check_user_overflow((uint64_t)rusage, sizeof(struct rusage))) {
        return -EFAULT;
    }
    if (idtype == P_PIDFD) {
        int pidfd_ret = pidfd_get_pid_from_fd(id, &match_id);
        if (pidfd_ret < 0) {
            return (uint64_t)pidfd_ret;
        }
        match_idtype = P_PID;
    }

    bool has_children = false;
    spin_lock(&task_queue_lock);
    task_index_bucket_t *children =
        task_index_bucket_lookup(&task_parent_map, wait_parent_pid);
    has_children = children && children->count > 0;
    spin_unlock(&task_queue_lock);

    if (!has_children)
        return -ECHILD;

    while (1) {
        task_t *found_alive = NULL;
        task_t *found_dead = NULL;

        arch_disable_interrupt();

        spin_lock(&task_queue_lock);
        task_index_bucket_t *children =
            task_index_bucket_lookup(&task_parent_map, wait_parent_pid);
        struct llist_header *node = children ? children->tasks.next : NULL;
        while (children && node != &children->tasks) {
            task_t *ptr = list_entry(node, task_t, parent_node);
            node = node->next;
            if (!ptr)
                continue;

            if (!task_has_parent(ptr))
                continue;
            if (task_parent_wait_key(ptr) != wait_parent_pid)
                continue;

            switch (match_idtype) {
            case P_PID:
                if (ptr->pid != match_id)
                    continue;
                break;
            case P_PGID:
                if (ptr->pgid != match_id)
                    continue;
                break;
            case P_ALL:
                break;
            default:
                continue;
            }

            if (ptr->state == TASK_DIED && (options & WEXITED)) {
                found_dead = ptr;
                break;
            } else {
                found_alive = ptr;
            }
        }
        spin_unlock(&task_queue_lock);

        arch_enable_interrupt();

        if (found_dead) {
            target = found_dead;
            break;
        }

        if (found_alive && (options & WNOHANG)) {
            if (infop) {
                siginfo_t empty_info;
                memset(&empty_info, 0, sizeof(empty_info));
                if (copy_to_user(infop, &empty_info, sizeof(empty_info))) {
                    return (uint64_t)-EFAULT;
                }
            }
            return 0;
        }

        if (found_alive) {
            found_alive->waitpid = current_task->pid;
            if (found_alive->state != TASK_DIED)
                task_block(current_task, TASK_BLOCKING, -1, "waitid");
            continue;
        }

        return -ECHILD;
    }

    if (target) {
        if (infop) {
            siginfo_t info;
            memset(&info, 0, sizeof(info));
            info.si_signo = SIGCHLD;
            info.si_errno = 0;
            info._sifields._sigchld._pid = target->pid;
            info._sifields._sigchld._uid = target->uid;

            if (target->state == TASK_DIED) {
                if (target->status >= 128) {
                    info.si_code = CLD_KILLED;
                    info._sifields._sigchld._status = target->status - 128;
                } else {
                    info.si_code = CLD_EXITED;
                    info._sifields._sigchld._status = target->status;
                }
            }
            if (copy_to_user(infop, &info, sizeof(info))) {
                return (uint64_t)-EFAULT;
            }
        }
        if (rusage) {
            task_fill_rusage(target, true, rusage);
        }

        ret = 0;

        if (!(options & WNOWAIT) && target->state == TASK_DIED) {
            task_aggregate_child_usage(current_task, target);
            task_enqueue_should_free(target);
        }
    }

    if (!(options & WNOWAIT)) {
        while (true) {
            task_t *to_free = task_dequeue_should_free();
            if (!to_free)
                break;
            free_task(to_free);
        }
    }

    return ret;
}

uint64_t sys_getrusage(int who, struct rusage *ru) {
    if (!ru || check_user_overflow((uint64_t)ru, sizeof(struct rusage)))
        return (uint64_t)-EFAULT;

    uint64_t now_ns = nano_time();
    task_account_runtime_ns(current_task, now_ns);

    struct rusage result;

    switch (who) {
    case RUSAGE_SELF:
    case RUSAGE_THREAD:
        memset(&result, 0, sizeof(result));
        task_fill_rusage(current_task, false, &result);
        break;
    case RUSAGE_CHILDREN:
        memset(&result, 0, sizeof(result));
        result.ru_utime = task_ns_to_timeval(current_task->child_user_time_ns);
        result.ru_stime =
            task_ns_to_timeval(current_task->child_system_time_ns);
        break;
    default:
        return (uint64_t)-EINVAL;
    }

    if (copy_to_user(ru, &result, sizeof(result)))
        return (uint64_t)-EFAULT;

    return 0;
}

uint64_t sys_clone3(struct pt_regs *regs, clone_args_t *args_user,
                    uint64_t args_size) {
    if (args_size < 64)
        return (uint64_t)-EINVAL;
    clone_args_t args = {0};
    size_t copy_size = MIN((size_t)args_size, sizeof(args));
    if (copy_from_user(&args, args_user, copy_size))
        return (uint64_t)-EFAULT;

    if (args.flags & 0xFF)
        return (uint64_t)-EINVAL;
    if (args.exit_signal & ~0xFFULL)
        return (uint64_t)-EINVAL;

    if ((args.flags & CLONE_PIDFD) &&
        (!args.pidfd || check_user_overflow(args.pidfd, sizeof(int)) ||
         check_unmapped(args.pidfd, sizeof(int)))) {
        return (uint64_t)-EFAULT;
    }

    uint64_t clone_flags =
        (args.flags & ~((uint64_t)CLONE_PIDFD)) | (args.exit_signal & 0xFFULL);
    uint64_t ret =
        sys_clone(regs, clone_flags, args.stack + args.stack_size,
                  (int *)args.parent_tid, (int *)args.child_tid, args.tls);
    if ((int64_t)ret < 0) {
        return ret;
    }

    if (args.flags & CLONE_PIDFD) {
        uint64_t pidfd = pidfd_create_for_pid(ret, 0, true);
        if ((int64_t)pidfd < 0) {
            return pidfd;
        }

        int pidfd_value = (int)pidfd;
        if (copy_to_user((void *)args.pidfd, &pidfd_value,
                         sizeof(pidfd_value))) {
            sys_close(pidfd);
            return (uint64_t)-EFAULT;
        }
    }

    return ret;
}

void before_ret_from_fork() {
    task_t *self = current_task;
    if ((self->clone_flags & CLONE_CHILD_SETTID) && self->set_tidptr) {
        int value = self->pid;
        if (write_task_user_memory(self, (uint64_t)self->set_tidptr, &value,
                                   sizeof(value)) < 0) {
            task_exit(128 + SIGSEGV);
        }
    }
}

uint64_t sys_clone(struct pt_regs *regs, uint64_t flags, uint64_t newsp,
                   int *parent_tid, int *child_tid, uint64_t tls) {
    arch_disable_interrupt();

    if (flags & CLONE_VFORK) {
        flags |= CLONE_VM;
    }

    if ((flags & CLONE_THREAD) &&
        (!(flags & CLONE_SIGHAND) || !(flags & CLONE_VM))) {
        return (uint64_t)-EINVAL;
    }

    if ((flags & CLONE_SIGHAND) && !(flags & CLONE_VM)) {
        return (uint64_t)-EINVAL;
    }

    if ((flags & CLONE_CLEAR_SIGHAND) && (flags & CLONE_SIGHAND)) {
        return (uint64_t)-EINVAL;
    }

    if ((flags & CLONE_PIDFD) && (flags & CLONE_PARENT_SETTID)) {
        return (uint64_t)-EINVAL;
    }

    if ((flags & CLONE_PARENT_SETTID) &&
        (!parent_tid ||
         check_user_overflow((uint64_t)parent_tid, sizeof(int)) ||
         check_unmapped((uint64_t)parent_tid, sizeof(int)))) {
        return (uint64_t)-EFAULT;
    }
    if ((flags & CLONE_PIDFD) &&
        (!parent_tid ||
         check_user_overflow((uint64_t)parent_tid, sizeof(int)) ||
         check_unmapped((uint64_t)parent_tid, sizeof(int)))) {
        return (uint64_t)-EFAULT;
    }

    if ((flags & CLONE_CHILD_SETTID) &&
        (!child_tid || check_user_overflow((uint64_t)child_tid, sizeof(int)) ||
         check_unmapped((uint64_t)child_tid, sizeof(int)))) {
        return (uint64_t)-EFAULT;
    }

    task_t *child = get_free_task();
    if (child == NULL) {
        return (uint64_t)-ENOMEM;
    }

    task_t *self = current_task;

    strncpy(child->name, self->name, TASK_NAME_MAX);

    child->signal = task_signal_clone(self, flags);
    if (!child->signal) {
        return (uint64_t)-ENOMEM;
    }

    child->cpu_id = alloc_cpu_id();

    child->kernel_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    child->syscall_stack =
        (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    memset((void *)(child->kernel_stack - STACK_SIZE), 0, STACK_SIZE);
    memset((void *)(child->syscall_stack - STACK_SIZE), 0, STACK_SIZE);

    if (!self->mm) {
        printk("src->mm == NULL!!! src = %#018lx\n", self);
    }
    child->mm = clone_page_table(self->mm, flags);
    if (!child->mm) {
        printk("dst->mm == NULL!!! dst = %#018lx\n", child);
    }
    child->arch_context = malloc(sizeof(arch_context_t));
    memset(child->arch_context, 0, sizeof(arch_context_t));
    arch_context_t orig_context;
    memcpy(&orig_context, self->arch_context, sizeof(arch_context_t));
    orig_context.ctx = regs;
    arch_context_copy(child->arch_context, &orig_context, child->kernel_stack,
                      flags);
    shm_fork(self, child);

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
    child->parent =
        (flags & (CLONE_THREAD | CLONE_PARENT)) ? self->parent : self;
    child->uid = self->uid;
    child->gid = self->gid;
    child->euid = self->euid;
    child->egid = self->egid;
    child->suid = self->suid;
    child->sgid = self->sgid;
    child->pgid = self->pgid;
    child->sid = self->sid;

    child->priority = NORMAL_PRIORITY;

    child->cwd = self->cwd;
    child->cmdline = self->cmdline ? strdup(self->cmdline) : NULL;
    child->arg_start = self->arg_start;
    child->arg_end = self->arg_end;
    child->env_start = self->env_start;
    child->env_end = self->env_end;

    child->exec_node = self->exec_node;
    if (child->exec_node)
        vfs_node_ref_get(child->exec_node);

    child->load_start = self->load_start;
    child->load_end = self->load_end;

    child->fd_info =
        (flags & CLONE_FILES) ? self->fd_info : calloc(1, sizeof(fd_info_t));
    if (!(flags & CLONE_FILES)) {
        mutex_init(&child->fd_info->fdt_lock);
        for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
            fd_t *fd = self->fd_info->fds[i];

            if (fd) {
                child->fd_info->fds[i] = vfs_dup(fd);
            } else {
                child->fd_info->fds[i] = NULL;
            }
        }
    }

    child->fd_info->ref_count++;

    spin_lock(&task_queue_lock);
    task_parent_index_attach_locked(child);
    task_pgid_index_attach_locked(child);
    spin_unlock(&task_queue_lock);

    child->shm_ids = NULL;

    child->signal->signal = 0;

    if (flags & CLONE_SETTLS) {
#if defined(__x86_64__)
        child->arch_context->fsbase = tls;
#elif defined(__riscv__)
        child->arch_context->ctx->tp = tls;
#endif
    }

    child->parent_death_sig = (uint64_t)-1;

    if (flags & CLONE_THREAD) {
        child->tgid = task_effective_tgid(self);
    } else {
        child->tgid = child->pid;
    }

    system_abi->on_new_task(child);
    for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
        if (child->fd_info->fds[i]) {
            system_abi->on_open_file(child, i);
        }
    }

    int child_tid_value = (int)child->pid;

    if (flags & CLONE_PARENT_SETTID) {
        copy_to_user(parent_tid, &child_tid_value, sizeof(child_tid_value));
    }
    if (flags & CLONE_PIDFD) {
        uint64_t pidfd = pidfd_create_for_pid(child->pid, 0, true);
        if ((int64_t)pidfd < 0) {
            return pidfd;
        }

        int pidfd_value = (int)pidfd;
        if (copy_to_user(parent_tid, &pidfd_value, sizeof(pidfd_value))) {
            sys_close(pidfd);
            return (uint64_t)-EFAULT;
        }
    }

    if (child_tid && (flags & CLONE_CHILD_SETTID)) {
        child->set_tidptr = child_tid;
    }

    if (child_tid && (flags & CLONE_CHILD_CLEARTID)) {
        child->tidptr = child_tid;
    }

    memcpy(child->rlim, self->rlim, sizeof(child->rlim));

    child->child_vfork_done = false;

    child->clone_flags = flags;
    child->is_clone = !!(flags & CLONE_THREAD);

    child->state = TASK_READY;
    child->current_state = TASK_READY;

    self->child_vfork_done = false;

    child->sched_info = calloc(1, sizeof(struct sched_entity));
    add_sched_entity(child, schedulers[child->cpu_id]);

    if ((flags & CLONE_VFORK)) {
        while (!self->child_vfork_done) {
            arch_enable_interrupt();
            schedule(SCHED_FLAG_YIELD);
        }

        arch_disable_interrupt();

        self->child_vfork_done = false;
    }

    return child->pid;
}

uint64_t task_fork(struct pt_regs *regs, bool vfork) {
    uint64_t flags = vfork ? (CLONE_VFORK | CLONE_VM) : 0;
    return sys_clone(regs, flags, 0, NULL, NULL, 0);
}

uint64_t sys_nanosleep(struct timespec *req, struct timespec *rem) {
    if (req->tv_sec < 0)
        return (uint64_t)-EINVAL;

    if (req->tv_sec < 0 || req->tv_nsec >= 1000000000L) {
        return (uint64_t)-EINVAL;
    }

    uint64_t start = nano_time();
    uint64_t target = start + (req->tv_sec * 1000000000ULL) + req->tv_nsec;
    current_task->force_wakeup_ns = target;

    do {
        arch_enable_interrupt();

        schedule(SCHED_FLAG_YIELD);
    } while (target > nano_time());

    arch_disable_interrupt();

    return 0;
}

uint64_t get_nanotime_by_clockid(int clock_id) {
    if (clock_id == CLOCK_REALTIME) {
        return boot_get_boottime() * 1000000000 + nano_time();
    } else if (clock_id == CLOCK_MONOTONIC) {
        return nano_time();
    } else {
        return (uint64_t)-EINVAL;
    }
}

uint64_t sys_clock_nanosleep(int clock_id, int flags,
                             const struct timespec *request,
                             struct timespec *remain) {
    if (clock_id != CLOCK_REALTIME && clock_id != CLOCK_MONOTONIC) {
        return (uint64_t)-EINVAL;
    }

    if (request->tv_sec < 0 || request->tv_nsec >= 1000000000L) {
        return (uint64_t)-EINVAL;
    }

    uint64_t start = get_nanotime_by_clockid(clock_id);
    uint64_t target =
        start + (request->tv_sec * 1000000000ULL) + request->tv_nsec;
    current_task->force_wakeup_ns = target;

    do {
        arch_enable_interrupt();

        schedule(SCHED_FLAG_YIELD);
    } while (target > get_nanotime_by_clockid(clock_id));

    arch_disable_interrupt();

    return 0;
}

uint64_t sys_prctl(uint64_t option, uint64_t arg2, uint64_t arg3, uint64_t arg4,
                   uint64_t arg5) {
    switch (option) {
    case PR_SET_NAME: // 设置进程名 (PR_SET_NAME=15)
    {
        char pr_name[16] = {0};
        if (!arg2 ||
            copy_from_user_str(pr_name, (const char *)arg2, sizeof(pr_name))) {
            return (uint64_t)-EFAULT;
        }
        memset(current_task->name, 0, sizeof(current_task->name));
        strncpy(current_task->name, pr_name, sizeof(pr_name) - 1);
        return 0;
    }

    case PR_GET_NAME: // 获取进程名 (PR_GET_NAME=16)
    {
        char pr_name[16] = {0};
        strncpy(pr_name, current_task->name, sizeof(pr_name) - 1);
        if (!arg2 || copy_to_user((void *)arg2, pr_name, sizeof(pr_name))) {
            return (uint64_t)-EFAULT;
        }
        return 0;
    }

    case PR_SET_SECCOMP: // 启用seccomp过滤
        return 0;

    case PR_GET_SECCOMP: // 查询seccomp状态
        return current_task->seccomp_mode;

    case PR_SET_TIMERSLACK:
        return 0;

    case PR_SET_PDEATHSIG:
        current_task->parent_death_sig = arg2;
        return 0;

    case PR_SET_SECUREBITS:
        return 0;

    case PR_SET_NO_NEW_PRIVS:
        if (arg2 != 1 || arg3 != 0 || arg4 != 0 || arg5 != 0)
            return (uint64_t)-EINVAL;
        current_task->no_new_privs = true;
        return 0;

    case PR_GET_NO_NEW_PRIVS:
        if (arg2 != 0 || arg3 != 0 || arg4 != 0 || arg5 != 0)
            return (uint64_t)-EINVAL;
        return current_task->no_new_privs ? 1 : 0;

    case PR_GET_TIMERSLACK:
        return 0;

    default:
        return -EINVAL; // 未实现的功能返回不支持
    }
}

uint64_t sys_set_robust_list(void *head, size_t len) {
    struct robust_list_head_abi {
        void *list_next;
        long futex_offset;
        void *list_op_pending;
    };

    if (!current_task)
        return (uint64_t)-EINVAL;
    if (len != sizeof(struct robust_list_head_abi))
        return (uint64_t)-EINVAL;

    if ((uint64_t)head != 0 &&
        (check_user_overflow((uint64_t)head, len ? len : 1) ||
         check_unmapped((uint64_t)head, len ? len : 1))) {
        return (uint64_t)-EFAULT;
    }

    current_task->robust_list_head = head;
    current_task->robust_list_len = len;
    return 0;
}

uint64_t sys_get_robust_list(int pid, void **head_ptr, size_t *len_ptr) {
    task_t *target = NULL;

    if (!head_ptr || !len_ptr)
        return (uint64_t)-EFAULT;

    if (pid == 0) {
        target = current_task;
    } else {
        target = task_find_by_pid((uint64_t)pid);
        if (!target)
            return (uint64_t)-ESRCH;
    }

    if (copy_to_user(head_ptr, &target->robust_list_head,
                     sizeof(target->robust_list_head)) ||
        copy_to_user(len_ptr, &target->robust_list_len,
                     sizeof(target->robust_list_len))) {
        return (uint64_t)-EFAULT;
    }

    return 0;
}

uint64_t sys_rseq(void *rseq, uint32_t rseq_len, int flags, uint32_t sig) {
    (void)rseq;
    (void)rseq_len;
    (void)flags;
    (void)sig;
    return (uint64_t)-ENOSYS;
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

uint64_t sys_alarm(uint64_t seconds) {
    struct itimerval old, new;
    new.it_value.tv_sec = seconds;
    new.it_value.tv_usec = 0;
    new.it_interval.tv_sec = 0;
    new.it_interval.tv_usec = 0;
    size_t ret = sys_setitimer(0, &new, &old);
    if ((int64_t)ret < 0)
        return ret;
    return old.it_value.tv_sec + !!old.it_value.tv_usec;
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

    switch (cmd) {
    case LINUX_REBOOT_CMD_CAD_OFF:
        cad_enabled = false;
        return 0;
    case LINUX_REBOOT_CMD_CAD_ON:
        cad_enabled = true;
        return 0;
    case LINUX_REBOOT_CMD_RESTART:
    case LINUX_REBOOT_CMD_RESTART2:
        return 0;
    case LINUX_REBOOT_CMD_POWER_OFF:
        return 0;
    default:
        return (uint64_t)-EINVAL;
        break;
    }
}

uint64_t sys_getpgid(uint64_t pid) {
    if (pid) {
        task_t *task = task_find_by_pid(pid);
        return task ? task->pgid : -ESRCH;
    } else
        return current_task->pgid;
}

uint64_t sys_getsid(uint64_t pid) {
    if (pid == 0)
        return current_task->sid;

    task_t *task = task_find_by_pid(pid);
    return task ? task->sid : (uint64_t)-ESRCH;
}

uint64_t sys_setpgid(uint64_t pid, uint64_t pgid) {
    spin_lock(&task_queue_lock);
    task_t *task = pid ? task_lookup_by_pid_nolock(pid) : current_task;
    if (!task) {
        spin_unlock(&task_queue_lock);
        return -ESRCH;
    }

    int64_t new_pgid =
        pgid ? (int64_t)pgid : (int64_t)task_effective_tgid(task);
    task_set_thread_group_pgid_locked(task, new_pgid);
    spin_unlock(&task_queue_lock);
    return 0;
}

uint64_t sys_setsid() {
    task_t *self = current_task;
    if (!self)
        return (uint64_t)-EINVAL;
    if (self->pid != task_effective_tgid(self))
        return (uint64_t)-EPERM;
    if (self->pgid == (int64_t)task_effective_tgid(self))
        return (uint64_t)-EPERM;

    spin_lock(&task_queue_lock);
    task_set_thread_group_sid_locked(self, (int64_t)task_effective_tgid(self));
    task_set_thread_group_pgid_locked(self, (int64_t)task_effective_tgid(self));
    spin_unlock(&task_queue_lock);
    return task_effective_tgid(self);
}

static int task_sched_normalize_policy(int policy, int *base_policy) {
    const int allowed_mask = SCHED_RESET_ON_FORK;
    if (policy & ~((int)allowed_mask | 0x7)) {
        return -EINVAL;
    }

    int normalized = policy & ~SCHED_RESET_ON_FORK;

    switch (normalized) {
    case SCHED_OTHER:
    case SCHED_FIFO:
    case SCHED_RR:
    case SCHED_BATCH:
    case SCHED_IDLE:
    case SCHED_DEADLINE:
        if (base_policy) {
            *base_policy = normalized;
        }
        return 0;
    default:
        return -EINVAL;
    }
}

static int task_sched_priority_bounds(int policy, int *min_priority,
                                      int *max_priority) {
    int base_policy = 0;
    int ret = task_sched_normalize_policy(policy, &base_policy);
    if (ret < 0) {
        return ret;
    }

    switch (base_policy) {
    case SCHED_FIFO:
    case SCHED_RR:
        if (min_priority) {
            *min_priority = 1;
        }
        if (max_priority) {
            *max_priority = 99;
        }
        return 0;
    case SCHED_OTHER:
    case SCHED_BATCH:
    case SCHED_IDLE:
    case SCHED_DEADLINE:
        if (min_priority) {
            *min_priority = 0;
        }
        if (max_priority) {
            *max_priority = 0;
        }
        return 0;
    default:
        return -EINVAL;
    }
}

static task_t *task_sched_lookup_target(int pid) {
    if (pid < 0) {
        return NULL;
    }

    if (pid == 0) {
        return current_task;
    }

    return task_find_by_pid((uint64_t)pid);
}

uint64_t sys_sched_setparam(int pid, const struct sched_param *param) {
    if (pid < 0) {
        return (uint64_t)-EINVAL;
    }

    struct sched_param kparam = {0};
    if (!param || copy_from_user(&kparam, param, sizeof(kparam))) {
        return (uint64_t)-EFAULT;
    }

    if (!task_sched_lookup_target(pid)) {
        return (uint64_t)-ESRCH;
    }

    if (kparam.sched_priority < 0 || kparam.sched_priority > 99) {
        return (uint64_t)-EINVAL;
    }

    return 0;
}

uint64_t sys_sched_getparam(int pid, struct sched_param *param) {
    if (pid < 0) {
        return (uint64_t)-EINVAL;
    }

    if (!param) {
        return (uint64_t)-EFAULT;
    }

    if (!task_sched_lookup_target(pid)) {
        return (uint64_t)-ESRCH;
    }

    struct sched_param kparam = {
        .sched_priority = 0,
    };

    if (copy_to_user(param, &kparam, sizeof(kparam))) {
        return (uint64_t)-EFAULT;
    }

    return 0;
}

uint64_t sys_sched_setscheduler(int pid, int policy,
                                const struct sched_param *param) {
    if (pid < 0) {
        return (uint64_t)-EINVAL;
    }

    struct sched_param kparam = {0};
    if (!param || copy_from_user(&kparam, param, sizeof(kparam))) {
        return (uint64_t)-EFAULT;
    }

    if (!task_sched_lookup_target(pid)) {
        return (uint64_t)-ESRCH;
    }

    int min_priority = 0;
    int max_priority = 0;
    int ret = task_sched_priority_bounds(policy, &min_priority, &max_priority);
    if (ret < 0) {
        return (uint64_t)ret;
    }

    if (kparam.sched_priority < min_priority ||
        kparam.sched_priority > max_priority) {
        return (uint64_t)-EINVAL;
    }

    return 0;
}

uint64_t sys_sched_getscheduler(int pid) {
    if (pid < 0) {
        return (uint64_t)-EINVAL;
    }

    if (!task_sched_lookup_target(pid)) {
        return (uint64_t)-ESRCH;
    }

    return SCHED_OTHER;
}

uint64_t sys_sched_get_priority_max(int policy) {
    int max_priority = 0;
    int ret = task_sched_priority_bounds(policy, NULL, &max_priority);
    if (ret < 0) {
        return (uint64_t)ret;
    }

    return (uint64_t)max_priority;
}

uint64_t sys_sched_get_priority_min(int policy) {
    int min_priority = 0;
    int ret = task_sched_priority_bounds(policy, &min_priority, NULL);
    if (ret < 0) {
        return (uint64_t)ret;
    }

    return (uint64_t)min_priority;
}

uint64_t sys_sched_rr_get_interval(int pid, struct timespec *interval) {
    if (pid < 0) {
        return (uint64_t)-EINVAL;
    }

    if (!interval) {
        return (uint64_t)-EFAULT;
    }

    if (!task_sched_lookup_target(pid)) {
        return (uint64_t)-ESRCH;
    }

    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 100000000,
    };

    if (copy_to_user(interval, &ts, sizeof(ts))) {
        return (uint64_t)-EFAULT;
    }

    return 0;
}

static size_t task_sched_affinity_bytes(void) {
    size_t bits_per_word = sizeof(unsigned long) * 8;
    size_t words = (cpu_count + bits_per_word - 1) / bits_per_word;
    if (words == 0)
        words = 1;
    return words * sizeof(unsigned long);
}

uint64_t sys_sched_setaffinity(int pid, size_t len,
                               const unsigned long *user_mask_ptr) {
    if (pid < 0)
        return (uint64_t)-EINVAL;
    if (!user_mask_ptr)
        return (uint64_t)-EFAULT;
    if (len < task_sched_affinity_bytes())
        return (uint64_t)-EINVAL;
    if (!task_sched_lookup_target(pid))
        return (uint64_t)-ESRCH;

    unsigned long mask[(MAX_CPU_NUM + sizeof(unsigned long) * 8 - 1) /
                       (sizeof(unsigned long) * 8)];
    memset(mask, 0, sizeof(mask));

    if (copy_from_user(mask, user_mask_ptr, task_sched_affinity_bytes()))
        return (uint64_t)-EFAULT;

    bool any_cpu = false;
    for (uint64_t cpu = 0; cpu < cpu_count; cpu++) {
        size_t word = cpu / (sizeof(unsigned long) * 8);
        size_t bit = cpu % (sizeof(unsigned long) * 8);
        if (mask[word] & (1UL << bit)) {
            any_cpu = true;
            break;
        }
    }

    return any_cpu ? 0 : (uint64_t)-EINVAL;
}

uint64_t sys_sched_getaffinity(int pid, size_t len,
                               unsigned long *user_mask_ptr) {
    if (pid < 0)
        return (uint64_t)-EINVAL;
    if (!user_mask_ptr)
        return (uint64_t)-EFAULT;
    if (len < task_sched_affinity_bytes())
        return (uint64_t)-EINVAL;
    if (!task_sched_lookup_target(pid))
        return (uint64_t)-ESRCH;

    unsigned long mask[(MAX_CPU_NUM + sizeof(unsigned long) * 8 - 1) /
                       (sizeof(unsigned long) * 8)];
    memset(mask, 0, sizeof(mask));

    // for (uint64_t cpu = 0; cpu < cpu_count; cpu++) {
    for (uint64_t cpu = 0; cpu < 1; cpu++) {
        size_t word = cpu / (sizeof(unsigned long) * 8);
        size_t bit = cpu % (sizeof(unsigned long) * 8);
        mask[word] |= (1UL << bit);
    }

    if (copy_to_user(user_mask_ptr, mask, task_sched_affinity_bytes()))
        return (uint64_t)-EFAULT;

    return task_sched_affinity_bytes();
}

uint64_t sys_setpriority(int which, int who, int niceval) {
    task_t *task = NULL;
    switch (which) {
    case PRIO_PROCESS:
        task = task_find_by_pid(who);
        if (!task)
            return -ESRCH;

        return 0;

    default:
        printk("sys_setpriority: Unsupported which: %d\n", which);
        return (uint64_t)-EINVAL;
    }
}

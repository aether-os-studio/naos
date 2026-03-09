#include <libs/string_builder.h>
#include <libs/hashmap.h>
#include <libs/rbtree.h>
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
#include <mm/shm.h>
#include <fs/fs_syscall.h>
#include <net/socket.h>
#include <uacpi/sleep.h>
#include <irq/irq_manager.h>
#include <irq/softirq.h>

sched_rq_t *schedulers[MAX_CPU_NUM];

spinlock_t task_queue_lock = SPIN_INIT;
task_t *idle_tasks[MAX_CPU_NUM];
static uint64_t next_task_pid = 1;
static hashmap_t task_pid_map = HASHMAP_INIT;
static hashmap_t task_parent_map = HASHMAP_INIT;
static hashmap_t task_pgid_map = HASHMAP_INIT;
static rb_root_t task_timeout_root = RB_ROOT_INIT;
static spinlock_t task_timeout_lock = SPIN_INIT;
static spinlock_t should_free_lock = SPIN_INIT;
DEFINE_LLIST(should_free_tasks);

static void task_init_default_rlimits(task_t *task) {
    size_t infinity = (size_t)-1;

    for (size_t index = 0; index < sizeof(task->rlim) / sizeof(task->rlim[0]);
         index++) {
        task->rlim[index] = (struct rlimit){infinity, infinity};
    }

    task->rlim[RLIMIT_STACK] = (struct rlimit){
        USER_STACK_END - USER_STACK_START, USER_STACK_END - USER_STACK_START};
    task->rlim[RLIMIT_NPROC] = (struct rlimit){MAX_TASK_NUM, MAX_TASK_NUM};
    task->rlim[RLIMIT_NOFILE] = (struct rlimit){MAX_FD_NUM, MAX_FD_NUM};
    task->rlim[RLIMIT_CORE] = (struct rlimit){0, 0};
}

typedef struct task_index_bucket {
    uint64_t key;
    size_t count;
    struct llist_header tasks;
} task_index_bucket_t;

extern int timerfdfs_id;

static inline task_index_bucket_t *task_index_bucket_lookup(hashmap_t *map,
                                                            uint64_t key) {
    return (task_index_bucket_t *)hashmap_get(map, key);
}

static task_index_bucket_t *task_index_bucket_get_or_create(hashmap_t *map,
                                                            uint64_t key) {
    task_index_bucket_t *bucket = task_index_bucket_lookup(map, key);
    if (bucket) {
        return bucket;
    }

    bucket = calloc(1, sizeof(task_index_bucket_t));
    ASSERT(bucket != NULL);

    bucket->key = key;
    llist_init_head(&bucket->tasks);
    ASSERT(hashmap_put(map, key, bucket) == 0);

    return bucket;
}

static void task_index_bucket_destroy_if_empty(hashmap_t *map, uint64_t key) {
    task_index_bucket_t *bucket = task_index_bucket_lookup(map, key);
    if (!bucket || bucket->count || !llist_empty(&bucket->tasks)) {
        return;
    }

    hashmap_remove(map, key);
    free(bucket);
}

static inline bool task_should_index_parent(task_t *task, uint64_t ppid) {
    return task && task->pid && ppid && task->pid != ppid;
}

static inline bool task_should_index_pgid(task_t *task, int64_t pgid) {
    return task && task->pid && pgid != 0;
}

static void task_pid_index_add_locked(task_t *task) {
    if (!task || !task->pid) {
        return;
    }

    ASSERT(hashmap_put(&task_pid_map, task->pid, task) == 0);
}

static void task_pid_index_remove_locked(task_t *task) {
    if (!task || !task->pid) {
        return;
    }

    hashmap_remove(&task_pid_map, task->pid);
}

static void task_parent_index_attach_locked(task_t *task) {
    if (!task_should_index_parent(task, task->ppid) ||
        !llist_empty(&task->parent_node)) {
        return;
    }

    task_index_bucket_t *bucket =
        task_index_bucket_get_or_create(&task_parent_map, task->ppid);
    if (!bucket) {
        return;
    }

    llist_append(&bucket->tasks, &task->parent_node);
    bucket->count++;
}

static void task_parent_index_detach_locked(task_t *task, bool prune_bucket) {
    if (!task_should_index_parent(task, task->ppid) ||
        llist_empty(&task->parent_node)) {
        return;
    }

    uint64_t parent_pid = task->ppid;
    task_index_bucket_t *bucket =
        task_index_bucket_lookup(&task_parent_map, parent_pid);
    llist_delete(&task->parent_node);

    if (bucket && bucket->count) {
        bucket->count--;
    }

    if (prune_bucket) {
        task_index_bucket_destroy_if_empty(&task_parent_map, parent_pid);
    }
}

static void task_set_ppid_locked(task_t *task, uint64_t ppid,
                                 bool prune_old_bucket) {
    if (!task || task->ppid == ppid) {
        return;
    }

    task_parent_index_detach_locked(task, prune_old_bucket);
    task->ppid = ppid;
    task_parent_index_attach_locked(task);
}

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

static void task_set_pgid_locked(task_t *task, int64_t pgid) {
    if (!task || task->pgid == pgid) {
        return;
    }

    task_pgid_index_detach_locked(task);
    task->pgid = pgid;
    task_pgid_index_attach_locked(task);
}

static inline int task_timeout_cmp_values(uint64_t left_deadline,
                                          uint64_t left_pid,
                                          uint64_t right_deadline,
                                          uint64_t right_pid) {
    if (left_deadline < right_deadline) {
        return -1;
    }
    if (left_deadline > right_deadline) {
        return 1;
    }
    if (left_pid < right_pid) {
        return -1;
    }
    if (left_pid > right_pid) {
        return 1;
    }
    return 0;
}

static inline task_t *task_timeout_first_locked(void) {
    rb_node_t *first = rb_first(&task_timeout_root);
    return first ? rb_entry(first, task_t, timeout_node) : NULL;
}

static void task_timeout_remove_locked(task_t *task) {
    if (!task || !task->timeout_queued) {
        return;
    }

    rb_erase(&task->timeout_node, &task_timeout_root);
    memset(&task->timeout_node, 0, sizeof(task->timeout_node));
    task->timeout_queued = false;
}

static void task_timeout_add_locked(task_t *task) {
    if (!task || task->force_wakeup_ns == UINT64_MAX || task->timeout_queued) {
        return;
    }

    rb_node_t **slot = &task_timeout_root.rb_node;
    rb_node_t *parent = NULL;

    while (*slot) {
        task_t *curr = rb_entry(*slot, task_t, timeout_node);
        int cmp = task_timeout_cmp_values(task->force_wakeup_ns, task->pid,
                                          curr->force_wakeup_ns, curr->pid);
        parent = *slot;
        if (cmp < 0) {
            slot = &(*slot)->rb_left;
        } else {
            slot = &(*slot)->rb_right;
        }
    }

    task->timeout_node.rb_left = NULL;
    task->timeout_node.rb_right = NULL;
    rb_set_parent(&task->timeout_node, parent);
    rb_set_color(&task->timeout_node, KRB_RED);
    *slot = &task->timeout_node;
    rb_insert_color(&task->timeout_node, &task_timeout_root);
    task->timeout_queued = true;
}

static void task_timeout_cancel(task_t *task) {
    spin_lock(&task_timeout_lock);
    task_timeout_remove_locked(task);
    spin_unlock(&task_timeout_lock);
}

static void task_timeout_arm(task_t *task) {
    spin_lock(&task_timeout_lock);
    task_timeout_remove_locked(task);
    task_timeout_add_locked(task);
    spin_unlock(&task_timeout_lock);
}

static void task_timeout_softirq(void) {
    task_t *expired[32];

    while (true) {
        size_t expired_count = 0;
        uint64_t now = nano_time();

        spin_lock(&task_timeout_lock);
        while (expired_count < (sizeof(expired) / sizeof(expired[0]))) {
            task_t *task = task_timeout_first_locked();
            if (!task || task->force_wakeup_ns > now) {
                break;
            }

            task_timeout_remove_locked(task);
            expired[expired_count++] = task;
        }
        spin_unlock(&task_timeout_lock);

        if (!expired_count) {
            return;
        }

        for (size_t i = 0; i < expired_count; i++) {
            task_t *task = expired[i];
            if (!task || task->state == TASK_DIED || task->arch_context->dead) {
                continue;
            }
            if (task->force_wakeup_ns != UINT64_MAX &&
                task->force_wakeup_ns <= now) {
                task_unblock(task, ETIMEDOUT);
            }
        }

        if (expired_count < (sizeof(expired) / sizeof(expired[0]))) {
            return;
        }
    }
}

static void task_enqueue_should_free_locked(task_t *task) {
    if (!task || !llist_empty(&task->free_node)) {
        return;
    }

    llist_append(&should_free_tasks, &task->free_node);
}

static void task_enqueue_should_free(task_t *task) {
    spin_lock(&should_free_lock);
    task_enqueue_should_free_locked(task);
    spin_unlock(&should_free_lock);
}

static task_t *task_dequeue_should_free(void) {
    task_t *task = NULL;

    spin_lock(&should_free_lock);
    if (!llist_empty(&should_free_tasks)) {
        struct llist_header *node = should_free_tasks.next;
        llist_delete(node);
        task = list_entry(node, task_t, free_node);
    }
    spin_unlock(&should_free_lock);

    return task;
}

size_t task_count(void) {
    size_t count;

    spin_lock(&task_queue_lock);
    count = hashmap_size(&task_pid_map);
    spin_unlock(&task_queue_lock);

    return count;
}

int task_kill_all(int sig) {
    int sent = 0;

    spin_lock(&task_queue_lock);
    if (task_pid_map.buckets) {
        for (size_t i = 0; i < task_pid_map.bucket_count; i++) {
            hashmap_entry_t *entry = &task_pid_map.buckets[i];
            if (!hashmap_entry_is_occupied(entry)) {
                continue;
            }

            task_t *task = (task_t *)entry->value;
            if (!task || task->is_kernel) {
                continue;
            }

            sent++;
            if (sig != 0) {
                task_send_signal(task, sig, SI_USER);
            }
        }
    }
    spin_unlock(&task_queue_lock);

    return sent;
}

static inline task_t *task_lookup_by_pid_nolock(uint64_t pid) {
    if (pid == 0)
        return NULL;

    return (task_t *)hashmap_get(&task_pid_map, pid);
}

task_t *task_find_by_pid(uint64_t pid) {
    spin_lock(&task_queue_lock);
    task_t *task = task_lookup_by_pid_nolock(pid);
    spin_unlock(&task_queue_lock);
    return task;
}

typedef struct task_timerfd_ref {
    struct llist_header node;
    vfs_node_t timerfd_node;
    uint64_t fd_ref_count;
} task_timerfd_ref_t;

static task_timerfd_ref_t *task_timerfd_find_ref(task_t *task,
                                                 vfs_node_t timerfd_node) {
    if (!task || !timerfd_node)
        return NULL;

    task_timerfd_ref_t *ref, *next;
    llist_for_each(ref, next, &task->timerfd_list, node) {
        if (ref->timerfd_node == timerfd_node)
            return ref;
    }

    return NULL;
}

static void task_timerfd_list_clear(task_t *task) {
    if (!task)
        return;

    task_timerfd_ref_t *ref, *next;
    llist_for_each(ref, next, &task->timerfd_list, node) {
        llist_delete(&ref->node);
        free(ref);
    }

    llist_init_head(&task->timerfd_list);
}

static void task_timerfd_track_fd_single(task_t *task, fd_t *fd) {
    if (!task || !fd || !fd->node || fd->node->fsid != timerfdfs_id)
        return;

    task_timerfd_ref_t *ref = task_timerfd_find_ref(task, fd->node);
    if (ref) {
        ref->fd_ref_count++;
        return;
    }

    task_timerfd_ref_t *new_ref = calloc(1, sizeof(task_timerfd_ref_t));
    if (!new_ref)
        return;

    llist_init_head(&new_ref->node);
    new_ref->timerfd_node = fd->node;
    new_ref->fd_ref_count = 1;
    llist_append(&task->timerfd_list, &new_ref->node);
}

void task_timerfd_track_fd(task_t *task, fd_t *fd) {
    if (!task || !fd || !fd->node || fd->node->fsid != timerfdfs_id)
        return;

    fd_info_t *shared_fd_info = task->fd_info;
    if (!shared_fd_info || shared_fd_info->ref_count <= 1) {
        task_timerfd_track_fd_single(task, fd);
        return;
    }

    // TODO: vfork
}

static void task_timerfd_untrack_fd_single(task_t *task, fd_t *fd) {
    if (!task || !fd || !fd->node || fd->node->fsid != timerfdfs_id)
        return;

    task_timerfd_ref_t *ref = task_timerfd_find_ref(task, fd->node);
    if (!ref)
        return;

    if (ref->fd_ref_count > 1) {
        ref->fd_ref_count--;
        return;
    }

    llist_delete(&ref->node);
    free(ref);
}

void task_timerfd_untrack_fd(task_t *task, fd_t *fd) {
    if (!task || !fd || !fd->node || fd->node->fsid != timerfdfs_id)
        return;

    fd_info_t *shared_fd_info = task->fd_info;
    if (!shared_fd_info || shared_fd_info->ref_count <= 1) {
        task_timerfd_untrack_fd_single(task, fd);
        return;
    }

    // TODO: vfork
}

void task_timerfd_rebuild_from_fd_info(task_t *task) {
    if (!task)
        return;

    task_timerfd_list_clear(task);
    if (!task->fd_info)
        return;

    with_fd_info_lock(task->fd_info, {
        for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
            fd_t *fd = task->fd_info->fds[i];
            if (!fd)
                continue;
            task_timerfd_track_fd_single(task, fd);
        }
    });
}

static int task_kill_process_group_internal(int pgid, int sig,
                                            bool skip_kernel) {
    int sent = 0;
    task_index_bucket_t *bucket =
        task_index_bucket_lookup(&task_pgid_map, (uint64_t)pgid);
    if (bucket) {
        struct llist_header *node = bucket->tasks.next;
        while (node != &bucket->tasks) {
            task_t *task = list_entry(node, task_t, pgid_node);
            node = node->next;
            if (!task || (skip_kernel && task->is_kernel)) {
                continue;
            }
            sent++;
            if (sig != 0) {
                task_send_signal(task, sig, SI_USER);
            }
        }
    }

    return sent;
}

void send_process_group_signal(int pgid, int signal) {
    if (!pgid) {
        return;
    }

    spin_lock(&task_queue_lock);
    task_kill_process_group_internal(pgid, signal, false);
    spin_unlock(&task_queue_lock);
}

int task_kill_process_group(int pgid, int sig) {
    int sent;

    if (!pgid) {
        return 0;
    }

    spin_lock(&task_queue_lock);
    sent = task_kill_process_group_internal(pgid, sig, true);
    spin_unlock(&task_queue_lock);
    return sent;
}

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

    task_timerfd_list_clear(ptr);

    vma_manager_exit_cleanup(&ptr->mm->task_vma_mgr);

    if (!ptr->is_kernel)
        free_page_table(ptr->mm);

    if (ptr->cmdline)
        free(ptr->cmdline);

    shm_exit(ptr);
    arch_context_free(ptr->arch_context);
    free(ptr->arch_context);

    free(ptr->sched_info);
    ptr->sched_info = NULL;

    free_frames_bytes((void *)(ptr->kernel_stack - STACK_SIZE), STACK_SIZE);
    free_frames_bytes((void *)(ptr->syscall_stack - STACK_SIZE), STACK_SIZE);

    free(ptr);
}

bool task_initialized = false;
bool can_schedule = false;

extern int unix_socket_fsid;
extern int unix_accept_fsid;

uint32_t cpu_idx = 0;

static inline struct timeval task_ns_to_timeval(uint64_t ns) {
    struct timeval tv;
    tv.tv_sec = (long)(ns / 1000000000ULL);
    tv.tv_usec = (long)((ns % 1000000000ULL) / 1000ULL);
    return tv;
}

static inline uint64_t task_self_user_ns(task_t *task) {
    if (!task)
        return 0;
    if (task->user_time_ns <= task->system_time_ns)
        return 0;
    return task->user_time_ns - task->system_time_ns;
}

static inline uint64_t task_total_user_ns(task_t *task) {
    if (!task)
        return 0;
    return task_self_user_ns(task) + task->child_user_time_ns;
}

static inline uint64_t task_total_system_ns(task_t *task) {
    if (!task)
        return 0;
    return task->system_time_ns + task->child_system_time_ns;
}

static inline void task_account_runtime_ns(task_t *task, uint64_t now_ns) {
    if (!task || !task->last_sched_in_ns || now_ns <= task->last_sched_in_ns)
        return;

    uint64_t delta = now_ns - task->last_sched_in_ns;
    task->last_sched_in_ns = now_ns;

    task->user_time_ns += delta;
}

static inline void task_aggregate_child_usage(task_t *parent, task_t *child) {
    if (!parent || !child)
        return;
    parent->child_user_time_ns += task_total_user_ns(child);
    parent->child_system_time_ns += task_total_system_ns(child);
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
            llist_init_head(&task->free_node);
            llist_init_head(&task->parent_node);
            llist_init_head(&task->pgid_node);
            llist_init_head(&task->timerfd_list);
            task->state = TASK_CREATING;
            task->pid = 0;
            task->cpu_id = i;
            idle_tasks[i] = task;
            can_schedule = true;
            return task;
        }
    }

    spin_lock(&task_queue_lock);

    uint64_t pid = next_task_pid;

    task_t *task = (task_t *)malloc(sizeof(task_t));
    if (!task) {
        spin_unlock(&task_queue_lock);
        return NULL;
    }
    memset(task, 0, sizeof(task_t));
    llist_init_head(&task->free_node);
    llist_init_head(&task->parent_node);
    llist_init_head(&task->pgid_node);
    llist_init_head(&task->timerfd_list);
    task->state = TASK_CREATING;
    task->pid = pid;
    task->cpu_id = alloc_cpu_id();
    task_pid_index_add_locked(task);
    next_task_pid++;
    spin_unlock(&task_queue_lock);
    return task;
}

task_t *task_create(const char *name, void (*entry)(uint64_t), uint64_t arg,
                    int priority) {
    arch_disable_interrupt();

    can_schedule = false;

    task_t *task = get_free_task();
    if (!task) {
        can_schedule = true;
        return NULL;
    }
    task->signal = malloc(sizeof(task_signal_info_t));
    memset(task->signal, 0, sizeof(task_signal_info_t));
    spin_init(&task->signal->signal_lock);
    task->ppid = task->pid;
    task->uid = 0;
    task->gid = 0;
    task->euid = 0;
    task->egid = 0;
    task->suid = 0;
    task->sgid = 0;
    task->pgid = 0;
    task->tgid = task->pid;
    task->sid = 0;
    task->priority = priority;
    task->kernel_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    task->syscall_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    task->signal_syscall_stack =
        (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    memset((void *)(task->kernel_stack - STACK_SIZE), 0, STACK_SIZE);
    memset((void *)(task->syscall_stack - STACK_SIZE), 0, STACK_SIZE);
    task->mm = malloc(sizeof(task_mm_info_t));
    task->mm->page_table_addr = virt_to_phys((uint64_t)get_kernel_page_dir());
    task->mm->ref_count = 1;
    memset(&task->mm->task_vma_mgr, 0, sizeof(vma_manager_t));
    task->mm->task_vma_mgr.initialized = false;
    task->mm->brk_start = USER_BRK_START;
    task->mm->brk_current = task->mm->brk_start;
    task->mm->brk_end = USER_BRK_END;
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
    mutex_init(&task->fd_info->fdt_lock);
    task->fd_info->fds[0] = malloc(sizeof(fd_t));
    memset(task->fd_info->fds[0], 0, sizeof(fd_t));
    task->fd_info->fds[0]->node = vfs_open("/dev/stdin", 0);
    task->fd_info->fds[0]->node->refcount++;
    task->fd_info->fds[0]->offset = 0;
    task->fd_info->fds[0]->flags = 0;
    task->fd_info->fds[1] = malloc(sizeof(fd_t));
    memset(task->fd_info->fds[1], 0, sizeof(fd_t));
    task->fd_info->fds[1]->node = vfs_open("/dev/stdout", 0);
    task->fd_info->fds[1]->node->refcount++;
    task->fd_info->fds[1]->offset = 0;
    task->fd_info->fds[1]->flags = 0;
    task->fd_info->fds[2] = malloc(sizeof(fd_t));
    memset(task->fd_info->fds[2], 0, sizeof(fd_t));
    task->fd_info->fds[2]->node = vfs_open("/dev/stderr", 0);
    task->fd_info->fds[2]->node->refcount++;
    task->fd_info->fds[2]->offset = 0;
    task->fd_info->fds[2]->flags = 0;
    task->fd_info->ref_count++;
    strncpy(task->name, name, TASK_NAME_MAX);
    task->shm_ids = NULL;

    memset(task->signal->actions, 0, sizeof(task->signal->actions));

    task->cmdline = NULL;

    task_init_default_rlimits(task);

    task->clone_flags = 0;

    task->child_vfork_done = false;
    task->is_clone = false;
    task->is_kernel = true;

    task->parent_death_sig = (uint64_t)-1;

    procfs_on_new_task(task);

    task->state = TASK_READY;
    task->current_state = TASK_READY;

    task->sched_info = calloc(1, sizeof(struct sched_entity));
    add_sched_entity(task, schedulers[task->cpu_id]);

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
    memset(idle_tasks, 0, sizeof(idle_tasks));
    ASSERT(hashmap_init(&task_pid_map, 512) == 0);
    ASSERT(hashmap_init(&task_parent_map, 512) == 0);
    ASSERT(hashmap_init(&task_pgid_map, 512) == 0);
    task_timeout_root = RB_ROOT_INIT;
    spin_init(&task_timeout_lock);
    llist_init_head(&should_free_tasks);
    spin_init(&should_free_lock);
    softirq_register(SOFTIRQ_TIMER, task_timeout_softirq);
    next_task_pid = 1;

    for (uint64_t cpu = 0; cpu < cpu_count; cpu++) {
        schedulers[cpu] = calloc(1, sizeof(sched_rq_t));
        schedulers[cpu]->sched_queue = create_llist_queue();
    }

    for (uint64_t cpu = 0; cpu < cpu_count; cpu++) {
        task_t *idle_task = task_create("idle", idle_entry, 0, IDLE_PRIORITY);
        idle_task->cpu_id = cpu;
        idle_task->state = TASK_READY;
        idle_task->current_state = TASK_RUNNING;
        idle_task->last_sched_in_ns = nano_time();
        schedulers[cpu]->idle = idle_task->sched_info;
        remove_sched_entity(idle_task, schedulers[cpu]);
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
                    uint64_t at_base, const char *execfn) {
    uint64_t tmp_stack = current_stack;

    const char *execfn_name = execfn ? execfn : task->name;
    size_t name_len = strlen(execfn_name) + 1;
    PUSH_BYTES_TO_STACK(tmp_stack, execfn_name, name_len);
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

    const size_t auxv_pairs = 19;
    size_t qwords_to_push =
        auxv_pairs * 2 + (size_t)argv_count + (size_t)envp_count + 3;

    tmp_stack &= ~0xFULL;
    if (qwords_to_push & 1)
        tmp_stack -= sizeof(uint64_t);

    PUSH_TO_STACK(tmp_stack, uint64_t, 0);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_NULL);

    PUSH_TO_STACK(tmp_stack, uint64_t, 0);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_SECURE);

    PUSH_TO_STACK(tmp_stack, uint64_t, 0);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_FLAGS);

    PUSH_TO_STACK(tmp_stack, uint64_t, DEFAULT_PAGE_SIZE);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_PAGESZ);

    PUSH_TO_STACK(tmp_stack, uint64_t, 0);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_SYSINFO_EHDR);

    PUSH_TO_STACK(tmp_stack, uint64_t, 0);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_HWCAP2);

    PUSH_TO_STACK(tmp_stack, uint64_t, 0);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_HWCAP);

    PUSH_TO_STACK(tmp_stack, uint64_t, 100);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_CLKTCK);

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

    PUSH_TO_STACK(tmp_stack, uint64_t, task->uid);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_UID);

    PUSH_TO_STACK(tmp_stack, uint64_t, task->euid);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_EUID);

    PUSH_TO_STACK(tmp_stack, uint64_t, task->gid);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_GID);

    PUSH_TO_STACK(tmp_stack, uint64_t, task->egid);
    PUSH_TO_STACK(tmp_stack, uint64_t, AT_EGID);

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
    uint64_t flags = vfork ? (CLONE_VFORK | CLONE_VM | CLONE_THREAD |
                              CLONE_SIGHAND | CLONE_FS | CLONE_FILES)
                           : 0;
    return sys_clone(regs, flags, 0, NULL, NULL, 0);
}

uint64_t get_node_size(vfs_node_t node) {
    if (node->type & file_symlink) {
        char linkpath[128];
        memset(linkpath, 0, sizeof(linkpath));
        int ret = vfs_readlink(node, linkpath, sizeof(linkpath));
        if (ret < 0) {
            return (uint64_t)-ENOENT;
        }

        vfs_node_t linknode = vfs_open_at(node->parent, linkpath, 0);
        if (!linknode) {
            return (uint64_t)-ENOENT;
        }

        return get_node_size(linknode);
    } else {
        return node->size;
    }
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

static int register_elf_load_vma(task_t *task, vfs_node_t node,
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
    vma->node = node;
    if (node)
        node->refcount++;
    if (name)
        vma->vm_name = strdup(name);

    if (vma_insert(&task->mm->task_vma_mgr, vma) != 0) {
        vma_free(vma);
        return -ENOMEM;
    }

    return 0;
}

static int read_task_file_into_user_memory(task_t *task, vfs_node_t node,
                                           uint64_t uaddr, size_t offset,
                                           size_t size);
static int zero_task_user_memory(task_t *task, uint64_t uaddr, size_t size);

uint64_t task_execve(const char *path_user, const char **argv,
                     const char **envp) {
    task_t *self = current_task;

    arch_disable_interrupt();

    char path[512];
    strncpy(path, path_user, sizeof(path));

    vfs_node_t node = vfs_open(path, 0);
    if (!node) {
        return (uint64_t)-ENOENT;
    }
    uint64_t size = node->size;

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

    if (self->is_clone && (self->clone_flags & CLONE_VM)) {
        if (self->mm->ref_count <= 1)
            vma_manager_exit_cleanup(&self->mm->task_vma_mgr);
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
    memset(&new_mm->task_vma_mgr, 0, sizeof(vma_manager_t));
    new_mm->task_vma_mgr.initialized = true;

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

    self->mm = new_mm;

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

            vfs_node_t interpreter_node = vfs_open(interp_name, 0);
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

                uint64_t final_flags =
                    elf_segment_pt_flags(interp_phdr[j].p_flags);
                uint64_t flags = final_flags | PT_FLAG_W;
                map_page_range(get_current_page_dir(true), aligned_addr,
                               (uint64_t)-1, alloc_size, flags);

                (void)read_task_file_into_user_memory(
                    self, interpreter_node, seg_addr, interp_phdr[j].p_offset,
                    file_size);

                if (seg_size > file_size) {
                    (void)zero_task_user_memory(self, seg_addr + file_size,
                                                seg_size - file_size);
                }

                if (flags != final_flags) {
                    map_change_attribute_range(get_current_page_dir(true),
                                               aligned_addr, alloc_size,
                                               final_flags);
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

            uint64_t final_flags = elf_segment_pt_flags(phdr[i].p_flags);
            uint64_t flags = final_flags | PT_FLAG_W;
            map_page_range(get_current_page_dir(true), aligned_addr,
                           (uint64_t)-1, alloc_size, flags);

            (void)read_task_file_into_user_memory(self, node, seg_addr,
                                                  phdr[i].p_offset, file_size);

            if (seg_size > file_size) {
                (void)zero_task_user_memory(self, seg_addr + file_size,
                                            seg_size - file_size);
            }

            if (flags != final_flags) {
                map_change_attribute_range(get_current_page_dir(true),
                                           aligned_addr, alloc_size,
                                           final_flags);
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

    node->refcount++;
    self->exec_node = node;

    map_page_range(get_current_page_dir(true), USER_STACK_START, (uint64_t)-1,
                   USER_STACK_END - USER_STACK_START,
                   PT_FLAG_R | PT_FLAG_W | PT_FLAG_U);

    uint64_t stack = push_infos(
        self, USER_STACK_END, (char **)new_argv, argv_count, (char **)new_envp,
        envp_count, e_entry, phdr_vaddr, ehdr->e_phnum,
        interpreter_entry ? INTERPRETER_BASE_ADDR : load_start, path);

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
        task_timerfd_rebuild_from_fd_info(self);
    }

    task_t *vfork_parent = task_find_by_pid(self->ppid);
    if (self->is_clone && (self->clone_flags & CLONE_VFORK) && vfork_parent &&
        !vfork_parent->child_vfork_done) {
        vfork_parent->child_vfork_done = true;
    }

    string_builder_t *builder = create_string_builder(DEFAULT_PAGE_SIZE);
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
                task_timerfd_untrack_fd(self, self->fd_info->fds[i]);
                vfs_close(self->fd_info->fds[i]->node);
                free(self->fd_info->fds[i]);
                self->fd_info->fds[i] = NULL;
                procfs_on_close_file(self, i);
            }
        }
    });

    bool ignore_sigchld =
        (self->signal->actions[SIGCHLD].sa_handler == SIG_IGN);
    if (self->signal)
        free(self->signal);
    self->signal = malloc(sizeof(task_signal_info_t));
    memset(self->signal, 0, sizeof(task_signal_info_t));
    spin_init(&self->signal->signal_lock);
    if (ignore_sigchld) {
        self->signal->actions[SIGCHLD].sa_handler = SIG_IGN;
    }

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
    stack_vma->vm_flags |= VMA_ANON | VMA_READ | VMA_WRITE;

    stack_vma->vm_type = VMA_TYPE_ANON;
    stack_vma->vm_name = strdup("[stack]");

    vma_t *region = vma_find_intersection(&self->mm->task_vma_mgr,
                                          USER_STACK_START, USER_STACK_END);
    if (!region) {
        vma_insert(&self->mm->task_vma_mgr, stack_vma);
    }

    self->clone_flags = 0;
    self->is_clone = false;
    self->is_kernel = false;

    arch_to_user_mode(self->arch_context,
                      interpreter_entry ? interpreter_entry : e_entry, stack);

    return (uint64_t)-EAGAIN;
}

void sys_yield() { schedule(SCHED_FLAG_YIELD); }

int task_block(task_t *task, task_state_t state, int64_t timeout_ns,
               const char *blocking_reason) {
    if (!task || task->cpu_id >= cpu_count) {
        return -EINVAL;
    }

    task->status = EOK;

    if (__atomic_exchange_n(&task->wake_pending, false, __ATOMIC_ACQ_REL)) {
        return task->status;
    }

    bool irq_state = arch_interrupt_enabled();

    arch_disable_interrupt();

    uint32_t target_cpu = task->cpu_id;
    bool should_trigger_sched_ipi = false;
    if (target_cpu != current_cpu_id && task->sched_info &&
        schedulers[target_cpu]) {
        struct sched_entity *curr =
            __atomic_load_n(&schedulers[target_cpu]->curr, __ATOMIC_ACQUIRE);
        should_trigger_sched_ipi =
            (curr == (struct sched_entity *)task->sched_info);
    }

    task->state = state;
    if (timeout_ns > 0)
        task->force_wakeup_ns = nano_time() + timeout_ns;
    else
        task->force_wakeup_ns = UINT64_MAX;

    if (timeout_ns > 0)
        task_timeout_arm(task);
    else
        task_timeout_cancel(task);

    task->blocking_reason = blocking_reason;

    remove_sched_entity(task, schedulers[task->cpu_id]);

    if (task->state != state) {
        task_timeout_cancel(task);
        task->force_wakeup_ns = UINT64_MAX;
        task->blocking_reason = NULL;
        if (task->state == TASK_READY)
            add_sched_entity(task, schedulers[task->cpu_id]);
        goto ret;
    }

    if (__atomic_exchange_n(&task->wake_pending, false, __ATOMIC_ACQ_REL)) {
        task_timeout_cancel(task);
        task->state = TASK_READY;
        task->force_wakeup_ns = UINT64_MAX;
        task->blocking_reason = NULL;
        add_sched_entity(task, schedulers[task->cpu_id]);
        goto ret;
    }

    if (should_trigger_sched_ipi) {
        write_barrier();
        irq_trigger_sched_ipi(target_cpu);
    }

    schedule(SCHED_FLAG_YIELD);

ret:
    if (irq_state) {
        arch_enable_interrupt();
    } else {
        arch_disable_interrupt();
    }

    return task->status;
}

void task_unblock(task_t *task, int reason) {
    if (!task || task->state == TASK_DIED || task->arch_context->dead) {
        return;
    }

    bool irq_state = arch_interrupt_enabled();

    arch_disable_interrupt();

    task_timeout_cancel(task);

    if (task->state != TASK_BLOCKING && task->state != TASK_READING_STDIO &&
        task->state != TASK_UNINTERRUPTABLE) {
        task->status = reason;
        task->force_wakeup_ns = UINT64_MAX;
        __atomic_store_n(&task->wake_pending, true, __ATOMIC_RELEASE);
        goto ret;
    }

    task->status = reason;
    task->state = TASK_READY;

    task->blocking_reason = NULL;
    task->force_wakeup_ns = UINT64_MAX;
    __atomic_store_n(&task->wake_pending, false, __ATOMIC_RELEASE);

    add_sched_entity(task, schedulers[task->cpu_id]);

ret:
    if (irq_state) {
        arch_enable_interrupt();
    } else {
        arch_disable_interrupt();
    }
}

extern spinlock_t futex_lock;
extern struct futex_wait futex_wait_list;

extern uint64_t sys_futex_wake(uint64_t addr, int val, uint32_t bitset);
static int write_task_user_memory(task_t *task, uint64_t uaddr, const void *src,
                                  size_t size);

extern int signalfdfs_id;

void task_cleanup_fd_info(task_t *task) {
    if (task->fd_info) {
        if (--task->fd_info->ref_count <= 0) {
            with_fd_info_lock(task->fd_info, {
                for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
                    if (task->fd_info->fds[i]) {
                        vfs_close(task->fd_info->fds[i]->node);
                        free(task->fd_info->fds[i]);

                        task->fd_info->fds[i] = NULL;

                        procfs_on_close_file(task, i);
                    }
                }
            });
            free(task->fd_info);
            task->fd_info = NULL;
        }
    }
}

void task_exit_inner(task_t *task, int64_t code) {
    arch_disable_interrupt();
    uint64_t before_user_ns = task ? task->user_time_ns : 0;
    task_account_runtime_ns(task, nano_time());
    if (task && task->user_time_ns > before_user_ns)
        task->system_time_ns += task->user_time_ns - before_user_ns;
    task->last_sched_in_ns = 0;

    struct sched_entity *entity = (struct sched_entity *)task->sched_info;
    remove_sched_entity(task, schedulers[task->cpu_id]);
    if (entity) {
        if (entity->node)
            __atomic_store_n(&entity->node->data, NULL, __ATOMIC_RELEASE);
        __atomic_store_n(&entity->task, NULL, __ATOMIC_RELEASE);
    }

    task->current_state = TASK_DIED;
    task->state = TASK_DIED;
    task_timeout_cancel(task);

    vfs_close(task->exec_node);

    spin_lock(&futex_lock);

    struct futex_wait *prev = &futex_wait_list;
    struct futex_wait *curr = futex_wait_list.next;
    while (curr) {
        if (curr->task == task) {
            prev->next = curr->next;
            curr->next = NULL;
            curr = prev->next;
            continue;
        }

        prev = curr;
        curr = curr->next;
    }

    spin_unlock(&futex_lock);

    if (task->tidptr) {
        int clear_tid = 0;
        write_task_user_memory(task, (uint64_t)task->tidptr, &clear_tid,
                               sizeof(clear_tid));
        sys_futex_wake((uint64_t)task->tidptr, INT32_MAX, 0xFFFFFFFF);
    }

    task_cleanup_fd_info(task);

    task_timerfd_list_clear(task);

    procfs_on_exit_task(task);

    task->fd_info = NULL;

    task->status = (uint64_t)code;

    task_t *waiting_task = task_lookup_by_pid_nolock(task->waitpid);
    if (waiting_task) {
        task_unblock(waiting_task, EOK);
    }

    task_t *parent = task_lookup_by_pid_nolock(task->ppid);
    if (!task->is_clone && task->ppid && task->pid != task->ppid && parent) {
        sigaction_t *sa = &parent->signal->actions[SIGCHLD];
        bool ignore_sigchld = (sa->sa_handler == SIG_IGN);

        // if (!ignore_sigchld) {
        //     siginfo_t sigchld_info;
        //     memset(&sigchld_info, 0, sizeof(siginfo_t));
        //     sigchld_info.si_signo = SIGCHLD;
        //     sigchld_info.si_errno = 0;
        //     sigchld_info._sifields._sigchld._pid = task->pid;
        //     sigchld_info._sifields._sigchld._uid = task->uid;
        //     sigchld_info._sifields._sigchld._utime = 0;
        //     sigchld_info._sifields._sigchld._stime = 0;
        //     if (code >= 128) {
        //         sigchld_info.si_code = CLD_KILLED;
        //         sigchld_info._sifields._sigchld._status = code - 128;
        //     } else {
        //         sigchld_info.si_code = CLD_EXITED;
        //         sigchld_info._sifields._sigchld._status = code;
        //     }
        //     task_commit_signal(parent, SIGCHLD, &sigchld_info);

        //     for (int i = 0; i < MAX_FD_NUM; i++) {
        //         fd_t *fd = parent->fd_info->fds[i];
        //         if (fd) {
        //             vfs_node_t node = fd->node;
        //             if (node && node->fsid == signalfdfs_id) {
        //                 struct signalfd_ctx *ctx = node->handle;
        //                 if (ctx) {
        //                     struct signalfd_siginfo info;
        //                     memset(&info, 0, sizeof(struct
        //                     signalfd_siginfo)); info.ssi_signo = SIGCHLD;
        //                     info.ssi_pid = task->pid;
        //                     info.ssi_uid = task->uid;
        //                     if (code >= 128) {
        //                         info.ssi_code = CLD_KILLED;
        //                         info.ssi_status = code - 128;
        //                     } else {
        //                         info.ssi_code = CLD_EXITED;
        //                         info.ssi_status = code;
        //                     }

        //                     memcpy(&ctx->queue[ctx->queue_head], &info,
        //                            sizeof(struct signalfd_siginfo));
        //                     ctx->queue_head =
        //                         (ctx->queue_head + 1) % ctx->queue_size;
        //                     if (ctx->queue_head == ctx->queue_tail) {
        //                         ctx->queue_tail =
        //                             (ctx->queue_tail + 1) % ctx->queue_size;
        //                     }
        //                 }
        //             }
        //         }
        //     }
        // }

        if (ignore_sigchld || (sa->sa_flags & SA_NOCLDWAIT))
            task_enqueue_should_free(task);

        task_unblock(parent, 128 + SIGCHLD);
    } else if (task->pid == task->ppid) {
        task_enqueue_should_free(task);
    }
}

uint64_t task_exit(int64_t code) {
    arch_disable_interrupt();

    can_schedule = false;

    task_t *vfork_parent = task_find_by_pid(current_task->ppid);
    if (current_task->is_clone && (current_task->clone_flags & CLONE_VFORK) &&
        vfork_parent && !vfork_parent->child_vfork_done) {
        vfork_parent->child_vfork_done = true;
    }

    spin_lock(&task_queue_lock);
    task_index_bucket_t *children =
        task_index_bucket_lookup(&task_parent_map, current_task->pid);
    struct llist_header *node = children ? children->tasks.next : NULL;
    while (children && node != &children->tasks) {
        task_t *task = list_entry(node, task_t, parent_node);
        node = node->next;
        if (task != current_task && (task->ppid != task->pid) &&
            (task->ppid == current_task->pid)) {
            if (task->fd_info == current_task->fd_info) {
                task_exit_inner(task, code);
            } else {
                task_set_ppid_locked(task, 1, false);
                if (task->parent_death_sig != (uint64_t)-1) {
                    task_send_signal(task, task->parent_death_sig,
                                     task->parent_death_sig + 128);
                    if (task->state == TASK_BLOCKING ||
                        task->state == TASK_READING_STDIO)
                        task_unblock(task, EOK);
                }
            }
        }
    }
    task_index_bucket_destroy_if_empty(&task_parent_map, current_task->pid);
    spin_unlock(&task_queue_lock);

    task_exit_inner(current_task, code);

    can_schedule = true;

    while (1) {
        schedule(SCHED_FLAG_YIELD);
    }

    // never return !!!

    return (uint64_t)-EAGAIN;
}

uint64_t sys_waitpid(uint64_t pid, int *status, uint64_t options,
                     struct rusage *rusage) {
    task_t *target = NULL;
    uint64_t ret = -ECHILD;
    int64_t wait_pid = (int64_t)pid;

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
        task_index_bucket_lookup(&task_parent_map, current_task->pid);
    has_children = children && children->count > 0;
    spin_unlock(&task_queue_lock);

    if (!has_children) {
        return -ECHILD;
    }

    while (1) {
        task_t *found_alive = NULL;
        task_t *found_dead = NULL;

        spin_lock(&task_queue_lock);
        task_index_bucket_t *children =
            task_index_bucket_lookup(&task_parent_map, current_task->pid);
        struct llist_header *node = children ? children->tasks.next : NULL;
        while (children && node != &children->tasks) {
            task_t *ptr = list_entry(node, task_t, parent_node);
            node = node->next;
            if (!ptr)
                continue;

            if (ptr->ppid == ptr->pid)
                continue;
            if (ptr->ppid != current_task->pid)
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

        if (found_dead) {
            target = found_dead;
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

    if (idtype < P_ALL || idtype > P_PIDFD)
        return -EINVAL;

    if (!(options & (WEXITED | WSTOPPED | WCONTINUED)))
        return -EINVAL;
    if (rusage &&
        check_user_overflow((uint64_t)rusage, sizeof(struct rusage))) {
        return -EFAULT;
    }

    bool has_children = false;
    spin_lock(&task_queue_lock);
    task_index_bucket_t *children =
        task_index_bucket_lookup(&task_parent_map, current_task->pid);
    has_children = children && children->count > 0;
    spin_unlock(&task_queue_lock);

    if (!has_children)
        return -ECHILD;

    while (1) {
        task_t *found_alive = NULL;
        task_t *found_dead = NULL;

        spin_lock(&task_queue_lock);
        task_index_bucket_t *children =
            task_index_bucket_lookup(&task_parent_map, current_task->pid);
        struct llist_header *node = children ? children->tasks.next : NULL;
        while (children && node != &children->tasks) {
            task_t *ptr = list_entry(node, task_t, parent_node);
            node = node->next;
            if (!ptr)
                continue;

            if (ptr->ppid == ptr->pid)
                continue;
            if (ptr->ppid != current_task->pid)
                continue;

            switch (idtype) {
            case P_PID:
                if (ptr->pid != id)
                    continue;
                break;
            case P_PGID:
                if (ptr->pgid != id)
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

        if (found_dead) {
            target = found_dead;
            break;
        }

        if (found_alive && (options & WNOHANG)) {
            if (infop) {
                memset(infop, 0, sizeof(siginfo_t));
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
            memset(infop, 0, sizeof(siginfo_t));
            infop->si_signo = SIGCHLD;
            infop->si_errno = 0;
            infop->_sifields._sigchld._pid = target->pid;
            infop->_sifields._sigchld._uid = target->uid;

            if (target->state == TASK_DIED) {
                if (target->status >= 128) {
                    infop->si_code = CLD_KILLED;
                    infop->_sifields._sigchld._status = target->status - 128;
                } else {
                    infop->si_code = CLD_EXITED;
                    infop->_sifields._sigchld._status = target->status;
                }
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
    if (args_size < sizeof(clone_args_t))
        return (uint64_t)-EINVAL;
    clone_args_t args;
    if (copy_from_user(&args, args_user, sizeof(clone_args_t)))
        return (uint64_t)-EFAULT;
    return sys_clone(regs, args.flags, args.stack, (int *)args.parent_tid,
                     (int *)args.child_tid, args.tls);
}

static int read_task_file_into_user_memory(task_t *task, vfs_node_t node,
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

static int write_task_user_memory(task_t *task, uint64_t uaddr, const void *src,
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

uint64_t sys_clone(struct pt_regs *regs, uint64_t flags, uint64_t newsp,
                   int *parent_tid, int *child_tid, uint64_t tls) {
    arch_disable_interrupt();

    if (flags & CLONE_VFORK) {
        flags |= CLONE_VM;
        flags |= CLONE_THREAD;
    }

    if ((flags & CLONE_PARENT_SETTID) &&
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

    child->signal = malloc(sizeof(task_signal_info_t));
    memset(child->signal, 0, sizeof(task_signal_info_t));
    spin_init(&child->signal->signal_lock);

    child->cpu_id = alloc_cpu_id();

    child->kernel_stack = (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    child->syscall_stack =
        (uint64_t)alloc_frames_bytes(STACK_SIZE) + STACK_SIZE;
    child->signal_syscall_stack =
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
    child->ppid = self->pid;
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
    child->cmdline = strdup(self->cmdline);

    child->exec_node = self->exec_node;
    if (child->exec_node)
        child->exec_node->refcount++;

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
    task_timerfd_rebuild_from_fd_info(child);

    spin_lock(&task_queue_lock);
    task_parent_index_attach_locked(child);
    task_pgid_index_attach_locked(child);
    spin_unlock(&task_queue_lock);

    procfs_on_new_task(child);
    for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
        if (child->fd_info->fds[i]) {
            procfs_on_open_file(child, i);
        }
    }

    child->shm_ids = NULL;

    child->signal->signal = 0;
    if (flags & CLONE_SIGHAND) {
        memcpy(child->signal->actions, self->signal->actions,
               sizeof(child->signal->actions));
        spin_lock(&self->signal->signal_lock);
        child->signal->blocked = self->signal->blocked;
        spin_unlock(&self->signal->signal_lock);
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

    child->parent_death_sig = (uint64_t)-1;

    if (flags & CLONE_THREAD) {
        child->tgid = self->tgid ? self->tgid : self->pid;
    } else {
        child->tgid = child->pid;
    }

    int child_tid_value = (int)child->pid;

    if (flags & CLONE_PARENT_SETTID) {
        copy_to_user(parent_tid, &child_tid_value, sizeof(child_tid_value));
    }

    if (flags & CLONE_CHILD_SETTID) {
        write_task_user_memory(child, (uint64_t)child_tid, &child_tid_value,
                               sizeof(child_tid_value));
    }

    if (child_tid && (flags & CLONE_CHILD_CLEARTID)) {
        child->tidptr = child_tid;
    }

    memcpy(child->rlim, self->rlim, sizeof(child->rlim));

    child->child_vfork_done = false;

    child->clone_flags = flags;
    child->is_clone = true;

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
        tm time;
        time_read(&time);
        return (uint64_t)mktime(&time) * 1000000000ULL;
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

    case PR_SET_PDEATHSIG:
        current_task->parent_death_sig = arg2;
        return 0;

    case PR_SET_SECUREBITS:
        return 0;

    case PR_SET_NO_NEW_PRIVS:
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
    if (current_task->state == TASK_DIED)
        return;

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

void sched_update_timerfd() {
    if (current_task->state == TASK_DIED ||
        llist_empty(&current_task->timerfd_list))
        return;

    task_timerfd_ref_t *ref, *tmp;
    llist_for_each(ref, tmp, &current_task->timerfd_list, node) {
        vfs_node_t node = ref->timerfd_node;

        if (!node || node->fsid != timerfdfs_id)
            continue;

        timerfd_t *tfd = node->handle;
        if (!tfd)
            continue;

        uint64_t now;
        if (tfd->timer.clock_type == CLOCK_MONOTONIC) {
            now = nano_time();
        } else {
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
            vfs_poll_notify(node, EPOLLIN);
        }
    }
}

void sched_check_wakeup() {
    uint64_t now = nano_time();

    spin_lock(&task_timeout_lock);
    task_t *first = task_timeout_first_locked();
    if (first && first->force_wakeup_ns <= now) {
        softirq_raise(SOFTIRQ_TIMER);
    }
    spin_unlock(&task_timeout_lock);
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
        task_t *task = task_find_by_pid(pid);
        return task ? task->pgid : -ESRCH;
    } else
        return current_task->pgid;
}

uint64_t sys_setpgid(uint64_t pid, uint64_t pgid) {
    spin_lock(&task_queue_lock);
    task_t *task = pid ? task_lookup_by_pid_nolock(pid) : current_task;
    if (!task) {
        spin_unlock(&task_queue_lock);
        return -ESRCH;
    }

    task_set_pgid_locked(task, pgid ? (int64_t)pgid : task->pgid);
    spin_unlock(&task_queue_lock);
    return 0;
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

void schedule(uint64_t sched_flags) {
    bool state = arch_interrupt_enabled();

    arch_disable_interrupt();

    sched_update_itimer();
    sched_update_timerfd();

    task_t *prev = current_task;
    int cpu_id = prev->cpu_id;
    uint64_t now_ns = nano_time();

    if (!prev->last_sched_in_ns && prev->current_state == TASK_RUNNING)
        prev->last_sched_in_ns = now_ns;

    task_t *next = NULL;
    if (sched_flags & SCHED_FLAG_YIELD) {
        next = sched_pick_next_task_excluding(schedulers[cpu_id], prev);

        if (next == prev) {
            next = idle_tasks[cpu_id];
        }
    } else {
        next = sched_pick_next_task(schedulers[cpu_id]);
    }

    if (next->state == TASK_DIED || next->arch_context->dead) {
        next = idle_tasks[cpu_id];
    }

    if (prev == next) {
        goto ret;
    }

    task_account_runtime_ns(prev, now_ns);
    prev->last_sched_in_ns = 0;

    prev->current_state = prev->state;
    next->current_state = TASK_RUNNING;
    next->last_sched_in_ns = now_ns;

    switch_mm(prev, next);
    switch_to(prev, next);

ret:
    if (state) {
        arch_enable_interrupt();
    } else {
        arch_disable_interrupt();
    }
}

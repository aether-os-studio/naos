#include <boot/boot.h>
#include <libs/rbtree.h>
#include <arch/arch.h>
#include <task/task.h>
#include <task/futex.h>
#include <task/ptrace.h>
#include <task/sched.h>
#include <drivers/logger.h>
#include <fs/vfs/vfs.h>
#include <fs/fs_syscall.h>
#include <arch/arch.h>
#include <mm/mm.h>
#include <mm/shm.h>
#include <net/socket.h>
#include <irq/irq_manager.h>
#include <irq/softirq.h>
#include <init/callbacks.h>
#include <task/keyring.h>
#include <task/ns.h>

sched_rq_t *schedulers[MAX_CPU_NUM];

spinlock_t task_queue_lock = SPIN_INIT;
task_t *idle_tasks[MAX_CPU_NUM];
uint64_t next_task_pid = 1;
hashmap_t task_pid_map = HASHMAP_INIT;
hashmap_t task_parent_map = HASHMAP_INIT;
hashmap_t task_pgid_map = HASHMAP_INIT;
rb_root_t task_timeout_root = RB_ROOT_INIT;
spinlock_t task_timeout_lock = SPIN_INIT;
static uint64_t task_timeout_next_ns = UINT64_MAX;
spinlock_t should_free_lock = SPIN_INIT;
DEFINE_LLIST(should_free_tasks);

task_t *init_task = NULL;
task_t *worker_tasks[MAX_WORKER_NUM];
uint32_t worker_task_count = 0;
struct llist_header worker_tick_queues[MAX_WORKER_NUM];
spinlock_t worker_tick_locks[MAX_WORKER_NUM];
uint32_t worker_slot_by_cpu[MAX_CPU_NUM];

struct vfs_process_fs *task_current_vfs_fs(void) {
    return current_task ? task_vfs_fs(current_task) : NULL;
}

struct vfs_file *task_get_file(task_t *task, int fd) {
    struct vfs_file *file = NULL;

    if (!task || !task->fd_info || fd < 0 || fd >= MAX_FD_NUM)
        return NULL;

    with_fd_info_lock(task->fd_info, {
        if (task->fd_info->fds[fd]) {
            file = vfs_file_get(task->fd_info->fds[fd]);
        }
    });

    return file;
}

int task_install_file(task_t *task, struct vfs_file *file,
                      unsigned int fd_flags, int min_fd) {
    int newfd = -EMFILE;

    if (!task || !task->fd_info || !file)
        return -EINVAL;
    if (min_fd < 0)
        min_fd = 0;

    with_fd_info_lock(task->fd_info, {
        for (int i = min_fd; i < MAX_FD_NUM; ++i) {
            if (task->fd_info->fds[i])
                continue;
            task->fd_info->fds[i] = vfs_file_get(file);
            task->fd_info->fd_flags[i] = fd_flags;
            newfd = i;
            break;
        }
    });

    if (newfd >= 0)
        on_open_file_call(task, newfd);
    return newfd;
}

int task_replace_file(task_t *task, int fd, struct vfs_file *file,
                      unsigned int fd_flags) {
    struct vfs_file *old = NULL;

    if (!task || !task->fd_info || !file || fd < 0 || fd >= MAX_FD_NUM)
        return -EINVAL;

    with_fd_info_lock(task->fd_info, {
        old = task->fd_info->fds[fd];
        task->fd_info->fds[fd] = vfs_file_get(file);
        task->fd_info->fd_flags[fd] = fd_flags;
    });

    if (old) {
        on_close_file_call(task, fd, old);
        vfs_close_file(old);
    } else {
        on_open_file_call(task, fd);
    }

    return fd;
}

int task_close_file_descriptor(task_t *task, int fd) {
    struct vfs_file *file = NULL;

    if (!task || !task->fd_info || fd < 0 || fd >= MAX_FD_NUM)
        return -EBADF;

    with_fd_info_lock(task->fd_info, {
        file = task->fd_info->fds[fd];
        task->fd_info->fds[fd] = NULL;
        task->fd_info->fd_flags[fd] = 0;
    });

    if (!file)
        return -EBADF;

    on_close_file_call(task, fd, file);
    return vfs_close_file(file);
}

static void sched_update_itimer_task(task_t *task, uint64_t now_ms);
static void task_reap_softirq(void);

static inline uint64_t task_timer_current_time_ns(clockid_t clock_type) {
    if (clock_type == CLOCK_REALTIME) {
        return boot_get_boottime() * 1000000000ULL + nano_time();
    }

    return nano_time();
}
void task_refresh_tick_work_state(task_t *task);

static task_sighand_t *task_sighand_alloc(void) {
    task_sighand_t *sighand = calloc(1, sizeof(task_sighand_t));
    if (!sighand)
        return NULL;

    spin_init(&sighand->siglock);
    sighand->ref_count = 1;
    return sighand;
}

static void task_sighand_get(task_sighand_t *sighand) {
    if (!sighand)
        return;

    __atomic_add_fetch(&sighand->ref_count, 1, __ATOMIC_RELAXED);
}

static void task_sighand_put(task_sighand_t *sighand) {
    if (!sighand)
        return;

    if (__atomic_sub_fetch(&sighand->ref_count, 1, __ATOMIC_ACQ_REL) == 0) {
        free(sighand);
    }
}

task_signal_info_t *task_signal_create_empty(void) {
    task_signal_info_t *signal = calloc(1, sizeof(task_signal_info_t));
    if (!signal)
        return NULL;

    signal->altstack.ss_flags = SS_DISABLE;
    signal->sighand = task_sighand_alloc();
    if (!signal->sighand) {
        free(signal);
        return NULL;
    }

    return signal;
}

task_signal_info_t *task_signal_clone(task_t *parent, uint64_t flags) {
    if (!parent || !parent->signal || !parent->signal->sighand)
        return NULL;

    task_signal_info_t *signal = task_signal_create_empty();
    if (!signal)
        return NULL;

    spin_lock(&parent->signal->sighand->siglock);
    if (flags & CLONE_SIGHAND) {
        task_sighand_put(signal->sighand);
        signal->sighand = parent->signal->sighand;
        task_sighand_get(signal->sighand);
    } else if (!(flags & CLONE_CLEAR_SIGHAND)) {
        memcpy(signal->sighand->actions, parent->signal->sighand->actions,
               sizeof(signal->sighand->actions));
    }

    signal->blocked = parent->signal->blocked;
    if ((flags & CLONE_VM) && !(flags & CLONE_VFORK)) {
        signal->altstack.ss_sp = NULL;
        signal->altstack.ss_size = 0;
        signal->altstack.ss_flags = SS_DISABLE;
    } else {
        signal->altstack = parent->signal->altstack;
        signal->altstack.ss_flags &= SS_AUTODISARM;
    }
    spin_unlock(&parent->signal->sighand->siglock);

    return signal;
}

task_signal_info_t *task_signal_reset_after_exec(task_t *task) {
    if (!task || !task->signal || !task->signal->sighand)
        return NULL;

    task_signal_info_t *signal = task_signal_create_empty();
    if (!signal)
        return NULL;

    spin_lock(&task->signal->sighand->siglock);
    if (task->signal->sighand->actions[SIGCHLD].sa_handler == SIG_IGN) {
        signal->sighand->actions[SIGCHLD].sa_handler = SIG_IGN;
    }
    signal->blocked = task->signal->blocked;
    signal->signal = task->signal->signal;
    signal->pending_signal = task->signal->pending_signal;
    spin_unlock(&task->signal->sighand->siglock);

    return signal;
}

void task_signal_free(task_signal_info_t *signal) {
    if (!signal)
        return;

    task_sighand_put(signal->sighand);
    free(signal);
}

static inline bool task_has_tick_work(task_t *task) {
    if (!task || task->state == TASK_DIED) {
        return false;
    }

    return task->tick_work_active;
}

void task_refresh_tick_work_state(task_t *task) {
    bool active = false;

    if (!task)
        return;

    if (task->itimer_real.at) {
        active = true;
        goto out;
    }

    for (int i = 0; i < MAX_TIMERS_NUM; i++) {
        kernel_timer_t *kt = task->timers[i];

        if (kt && kt->expires) {
            active = true;
            break;
        }
    }

out:
    task->tick_work_active = active;
}

void task_membarrier_checkpoint(task_t *task) {
    if (!task || !task->mm)
        return;

    task_mm_info_t *mm = task->mm;
    uint64_t seq = __atomic_load_n(&mm->membarrier_private_expedited_seq,
                                   __ATOMIC_ACQUIRE);
    if (seq == 0)
        return;

    uint64_t seen =
        __atomic_load_n(&task->membarrier_seen_seq, __ATOMIC_RELAXED);
    if (seen >= seq)
        return;

    memory_barrier();
    __atomic_store_n(&task->membarrier_seen_seq, seq, __ATOMIC_RELEASE);
}

static inline uint32_t sched_worker_slot_for_cpu(uint32_t cpu_id) {
    if (!worker_task_count)
        return 0;
    if (cpu_id < MAX_CPU_NUM && worker_slot_by_cpu[cpu_id] != UINT32_MAX)
        return worker_slot_by_cpu[cpu_id];
    return cpu_id % worker_task_count;
}

static bool sched_process_tick_work(uint32_t queue_id) {
    bool did_work = false;

    while (true) {
        task_t *task = NULL;
        spin_lock(&worker_tick_locks[queue_id]);

        if (!llist_empty(&worker_tick_queues[queue_id])) {
            struct llist_header *node = worker_tick_queues[queue_id].next;
            llist_delete(node);
            task = list_entry(node, task_t, tick_work_node);
            task->tick_work_queued = false;
            task->tick_work_queue_id = UINT32_MAX;
        }
        spin_unlock(&worker_tick_locks[queue_id]);

        if (!task) {
            break;
        }

        if (!task_has_tick_work(task)) {
            continue;
        }

        uint64_t now_mono_ns = nano_time();
        sched_update_itimer_task(task, now_mono_ns / 1000000);
        did_work = true;
    }

    return did_work;
}

static void task_tick_work_cancel(task_t *task) {
    if (!task || !task->tick_work_queued) {
        return;
    }

    uint32_t queue_id = task->tick_work_queue_id;
    if (queue_id >= worker_task_count)
        queue_id = sched_worker_slot_for_cpu(task->cpu_id);

    spin_lock(&worker_tick_locks[queue_id]);
    if (task->tick_work_queued) {
        llist_delete(&task->tick_work_node);
        task->tick_work_queued = false;
        task->tick_work_queue_id = UINT32_MAX;
    }
    spin_unlock(&worker_tick_locks[queue_id]);
}

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

static inline void task_timeout_refresh_next_locked(void) {
    task_t *first = task_timeout_first_locked();
    uint64_t next = first ? first->force_wakeup_ns : UINT64_MAX;
    __atomic_store_n(&task_timeout_next_ns, next, __ATOMIC_RELEASE);
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

void task_timeout_cancel(task_t *task) {
    spin_lock(&task_timeout_lock);
    task_timeout_remove_locked(task);
    task_timeout_refresh_next_locked();
    spin_unlock(&task_timeout_lock);
}

static void task_timeout_arm(task_t *task) {
    spin_lock(&task_timeout_lock);
    task_timeout_remove_locked(task);
    task_timeout_add_locked(task);
    task_timeout_refresh_next_locked();
    spin_unlock(&task_timeout_lock);
}

static void task_timeout_softirq(void) {
    task_t *expired[32];

    while (true) {
        size_t expired_count = 0;
        uint64_t now = nano_time();

        bool irq_state = arch_interrupt_enabled();

        arch_disable_interrupt();

        spin_lock(&task_timeout_lock);
        while (expired_count < (sizeof(expired) / sizeof(expired[0]))) {
            task_t *task = task_timeout_first_locked();
            if (!task || task->force_wakeup_ns > now) {
                break;
            }

            task_timeout_remove_locked(task);
            expired[expired_count++] = task;
        }
        task_timeout_refresh_next_locked();
        spin_unlock(&task_timeout_lock);

        arch_enable_interrupt();

        if (!expired_count) {
            return;
        }

        for (size_t i = 0; i < expired_count; i++) {
            task_t *task = expired[i];
            if (!task || task->state == TASK_DIED) {
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

static bool task_should_free_pending(void) {
    bool pending;

    spin_lock(&should_free_lock);
    pending = !llist_empty(&should_free_tasks);
    spin_unlock(&should_free_lock);

    return pending;
}

static void task_schedule_reap_softirq(void) {
    if (softirq_raise(SOFTIRQ_TASK_REAP))
        sched_wake_worker(0);
}

void task_schedule_reap(void) { task_schedule_reap_softirq(); }

void task_enqueue_should_free(task_t *task) {
    bool queued = false;

    spin_lock(&should_free_lock);
    if (task && llist_empty(&task->free_node)) {
        task_enqueue_should_free_locked(task);
        queued = true;
    }
    spin_unlock(&should_free_lock);

    if (queued)
        task_schedule_reap_softirq();
}

task_t *task_dequeue_should_free(void) {
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

static void task_reap_softirq(void) {
    const size_t reap_budget = 64;
    size_t reaped = task_reap_deferred(reap_budget);

    if (reaped > 0 && task_should_free_pending())
        task_schedule_reap_softirq();
}

size_t task_count(void) {
    size_t count;

    spin_lock(&task_queue_lock);
    count = hashmap_size(&task_pid_map);
    spin_unlock(&task_queue_lock);

    return count;
}

size_t task_thread_group_count(uint64_t tgid) {
    size_t count = 0;

    if (!tgid)
        return 0;

    spin_lock(&task_queue_lock);
    if (task_pid_map.buckets) {
        for (size_t i = 0; i < task_pid_map.bucket_count; i++) {
            hashmap_entry_t *entry = &task_pid_map.buckets[i];
            if (!hashmap_entry_is_occupied(entry))
                continue;

            task_t *task = (task_t *)entry->value;
            if (!task || task->state == TASK_DIED || !task->arch_context) {
                continue;
            }

            if (task_effective_tgid(task) == tgid) {
                count++;
            }
        }
    }
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

task_t *task_find_by_pid(uint64_t pid) {
    spin_lock(&task_queue_lock);
    task_t *task = task_lookup_by_pid_nolock(pid);
    spin_unlock(&task_queue_lock);
    return task;
}

void task_complete_vfork(task_t *task) {
    if (!task || !(task->clone_flags & CLONE_VFORK)) {
        return;
    }

    uint64_t parent_pid = task_parent_pid(task);
    if (!parent_pid) {
        return;
    }

    spin_lock(&task_queue_lock);
    task_t *parent = task_lookup_by_pid_nolock(parent_pid);
    if (!parent || parent->child_vfork_done) {
        spin_unlock(&task_queue_lock);
        return;
    }

    parent->child_vfork_done = true;
    spin_unlock(&task_queue_lock);
}

static void task_pid_index_add_locked(task_t *task) {
    if (!task || !task->pid) {
        return;
    }

    ASSERT(hashmap_put(&task_pid_map, task->pid, task) == 0);
}

task_index_bucket_t *task_index_bucket_get_or_create(hashmap_t *map,
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

void task_index_bucket_destroy_if_empty(hashmap_t *map, uint64_t key) {
    task_index_bucket_t *bucket = task_index_bucket_lookup(map, key);
    if (!bucket || bucket->count || !llist_empty(&bucket->tasks)) {
        return;
    }

    hashmap_remove(map, key);
    free(bucket);
}

void task_parent_index_attach_locked(task_t *task) {
    if (!task_should_index_parent(task) || !llist_empty(&task->parent_node)) {
        return;
    }

    uint64_t parent_key = task_parent_wait_key(task);
    task_index_bucket_t *bucket =
        task_index_bucket_get_or_create(&task_parent_map, parent_key);
    if (!bucket) {
        return;
    }

    llist_append(&bucket->tasks, &task->parent_node);
    bucket->count++;
}

void task_parent_index_detach_locked(task_t *task, bool prune_bucket) {
    if (!task_should_index_parent(task) || llist_empty(&task->parent_node)) {
        return;
    }

    uint64_t parent_pid = task_parent_wait_key(task);
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

static void task_set_parent_locked(task_t *task, task_t *parent,
                                   bool prune_old_bucket) {
    uint64_t new_parent_pid = task_effective_tgid(parent);

    if (!task ||
        (task->parent == parent && task->parent_pid == new_parent_pid)) {
        return;
    }

    task_parent_index_detach_locked(task, prune_old_bucket);
    task->parent = parent;
    task->parent_pid = new_parent_pid;
    task_parent_index_attach_locked(task);
}

static inline bool task_is_live_locked(task_t *task) {
    return task && task->state != TASK_DIED;
}

static task_t *task_pick_reaper_locked(task_t *task) {
    if (!task) {
        return NULL;
    }

    uint64_t current_tgid = task_effective_tgid(task);
    task_t *leader = task_lookup_by_pid_nolock(current_tgid);
    if (task_is_live_locked(leader) && leader != task) {
        return leader;
    }

    if (task_pid_map.buckets) {
        for (size_t i = 0; i < task_pid_map.bucket_count; i++) {
            hashmap_entry_t *entry = &task_pid_map.buckets[i];
            if (!hashmap_entry_is_occupied(entry)) {
                continue;
            }

            task_t *candidate = (task_t *)entry->value;
            if (!task_is_live_locked(candidate) || candidate == task) {
                continue;
            }

            if (task_effective_tgid(candidate) == current_tgid) {
                return candidate;
            }
        }
    }

    task_t *init = task_lookup_by_pid_nolock(1);
    return init == task ? NULL : init;
}

static void task_notify_parent_death_locked(task_t *task) {
    if (!task || task->parent_death_sig == (uint64_t)-1) {
        return;
    }

    task_send_signal(task, task->parent_death_sig,
                     task->parent_death_sig + 128);
    if (task->state == TASK_BLOCKING || task->state == TASK_READING_STDIO) {
        task_unblock(task, EOK);
    }
}

static void task_reparent_children_locked(task_t *owner, task_t *new_parent,
                                          bool process_wide) {
    if (!owner) {
        return;
    }

    uint64_t owner_tgid = task_effective_tgid(owner);
    task_index_bucket_t *children =
        task_index_bucket_lookup(&task_parent_map, owner_tgid);
    if (!children) {
        return;
    }

    task_t *task, *tmp;
    llist_for_each(task, tmp, &children->tasks, parent_node) {
        if (!task || task == owner || !task_has_parent(task)) {
            continue;
        }

        if (process_wide) {
            if (task_parent_pid(task) != owner_tgid) {
                continue;
            }
        } else if (task->parent != owner) {
            continue;
        }

        task_set_parent_locked(task, new_parent, false);
        task_notify_parent_death_locked(task);
    }

    task_index_bucket_destroy_if_empty(&task_parent_map, owner_tgid);
}

void task_detach_children_from_parent_locked(task_t *owner) {
    if (!owner) {
        return;
    }

    uint64_t owner_tgid = task_effective_tgid(owner);
    task_index_bucket_t *children =
        task_index_bucket_lookup(&task_parent_map, owner_tgid);
    if (!children) {
        return;
    }

    task_t *task, *tmp;
    llist_for_each(task, tmp, &children->tasks, parent_node) {
        if (!task || task == owner || task->parent != owner) {
            continue;
        }

        task_set_parent_locked(task, NULL, false);
    }

    task_index_bucket_destroy_if_empty(&task_parent_map, owner_tgid);
}

void task_detach_children_from_parent(task_t *owner) {
    spin_lock(&task_queue_lock);
    task_detach_children_from_parent_locked(owner);
    spin_unlock(&task_queue_lock);
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
            llist_init_head(&task->free_node);
            llist_init_head(&task->parent_node);
            llist_init_head(&task->pgid_node);
            llist_init_head(&task->tick_work_node);
            spin_init(&task->block_lock);
            task->tick_work_queue_id = UINT32_MAX;
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
    llist_init_head(&task->tick_work_node);
    spin_init(&task->block_lock);
    task->tick_work_queue_id = UINT32_MAX;
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
    task->signal = task_signal_create_empty();
    if (!task->signal) {
        goto fail;
    }
    task->parent = NULL;
    task->parent_pid = 0;
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

    void *kernel_stack_base = alloc_frames_bytes(STACK_SIZE);
    if (!kernel_stack_base)
        goto fail;
    task->kernel_stack_base = kernel_stack_base;
    task->kernel_stack = (uint64_t)kernel_stack_base + STACK_SIZE;

    void *syscall_stack_base = alloc_frames_bytes(STACK_SIZE);
    if (!syscall_stack_base)
        goto fail;
    task->syscall_stack_base = syscall_stack_base;
    task->syscall_stack = (uint64_t)syscall_stack_base + STACK_SIZE;

    memset(task->kernel_stack_base, 0, STACK_SIZE);
    memset(task->syscall_stack_base, 0, STACK_SIZE);
    task->mm = calloc(1, sizeof(task_mm_info_t));
    if (!task->mm)
        goto fail;
    task->mm->page_table_addr = (uint64_t)virt_to_phys(get_kernel_page_dir());
    task->mm->ref_count = 1;
    spin_init(&task->mm->lock);
    vma_manager_init(&task->mm->task_vma_mgr, false);
    task->mm->brk_start = USER_BRK_START;
    task->mm->brk_current = task->mm->brk_start;
    task->mm->brk_end = USER_BRK_END;
    task->arch_context = calloc(1, sizeof(arch_context_t));
    if (!task->arch_context)
        goto fail;
    arch_context_init(task->arch_context, virt_to_phys(get_kernel_page_dir()),
                      (uint64_t)entry, task->kernel_stack, false, arg);

    task->signal->signal = 0;
    task->status = 0;
    task->fs = task_fs_create(&vfs_root_path, &vfs_root_path);
    if (!task->fs) {
        goto fail;
    }
    task->nsproxy = task_ns_proxy_create_initial();
    if (!task->nsproxy) {
        goto fail;
    }
    task->fd_info = calloc(1, sizeof(fd_info_t));
    if (!task->fd_info)
        goto fail;
    mutex_init(&task->fd_info->fdt_lock);
    {
        struct vfs_open_how in_how = {.flags = O_RDONLY};
        struct vfs_open_how out_how = {.flags = O_WRONLY};
        struct vfs_file *stdin_file = NULL;
        struct vfs_file *stdout_file = NULL;
        struct vfs_file *stderr_file = NULL;

        if (vfs_openat(AT_FDCWD, "/dev/console", &in_how, &stdin_file) == 0)
            task_replace_file(task, 0, stdin_file, 0);
        if (vfs_openat(AT_FDCWD, "/dev/console", &out_how, &stdout_file) == 0)
            task_replace_file(task, 1, stdout_file, 0);
        if (vfs_openat(AT_FDCWD, "/dev/console", &out_how, &stderr_file) == 0)
            task_replace_file(task, 2, stderr_file, 0);
        if (stdin_file)
            vfs_file_put(stdin_file);
        if (stdout_file)
            vfs_file_put(stdout_file);
        if (stderr_file)
            vfs_file_put(stderr_file);
    }
    task->fd_info->ref_count++;
    strncpy(task->name, name, TASK_NAME_MAX);
    task->shm_ids = NULL;

    task->arg_start = 0;
    task->arg_end = 0;
    task->env_start = 0;
    task->env_end = 0;

    spin_init(&task->timers_lock);

    task_init_default_rlimits(task);

    task->clone_flags = 0;

    task->child_vfork_done = false;
    task->is_clone = false;
    task->is_kernel = true;

    task->parent_death_sig = (uint64_t)-1;

    task->state = TASK_READY;
    task->current_state = TASK_READY;

    task->sched_info = calloc(1, sizeof(struct sched_entity));
    if (!task->sched_info)
        goto fail;
    add_sched_entity(task, schedulers[task->cpu_id]);

    on_new_task_call(task);

    can_schedule = true;

    return task;

fail:
    can_schedule = true;
    task_cleanup_partial(task, true);
    return NULL;
}

void idle_entry(uint64_t arg) {
    while (1) {
        arch_enable_interrupt();
        arch_wait_for_interrupt();
    }
}

extern void init_thread(uint64_t arg);

extern bool system_initialized;

void worker_thread(uint64_t arg) {
    uint32_t queue_id = (uint32_t)arg;
    while (true) {
        arch_enable_interrupt();

        bool did_work = sched_process_tick_work(queue_id);

        if (current_cpu_id == 0 && softirq_has_pending()) {
            softirq_handle_pending();
            did_work = true;
        }

        if (!did_work) {
            task_block(current_task, TASK_BLOCKING, -1,
                       "worker_wait_for_event");
        }
    }
}

void task_init() {
    memset(idle_tasks, 0, sizeof(idle_tasks));
    memset(worker_tasks, 0, sizeof(worker_tasks));
    for (uint32_t i = 0; i < MAX_CPU_NUM; i++)
        worker_slot_by_cpu[i] = UINT32_MAX;
    ASSERT(hashmap_init(&task_pid_map, 512) == 0);
    ASSERT(hashmap_init(&task_parent_map, 512) == 0);
    ASSERT(hashmap_init(&task_pgid_map, 512) == 0);
    task_timeout_root = RB_ROOT_INIT;
    __atomic_store_n(&task_timeout_next_ns, UINT64_MAX, __ATOMIC_RELEASE);
    spin_init(&task_timeout_lock);
    llist_init_head(&should_free_tasks);
    spin_init(&should_free_lock);
    softirq_register(SOFTIRQ_TIMER, task_timeout_softirq);
    softirq_register(SOFTIRQ_TASK_REAP, task_reap_softirq);
    next_task_pid = 1;

    for (uint64_t cpu = 0; cpu < cpu_count; cpu++) {
        schedulers[cpu] = calloc(1, sizeof(sched_rq_t));
        schedulers[cpu]->sched_queue = create_llist_queue();
        spin_init(&schedulers[cpu]->lock);
    }
    for (uint32_t i = 0; i < MAX_WORKER_NUM; i++) {
        llist_init_head(&worker_tick_queues[i]);
        spin_init(&worker_tick_locks[i]);
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

    init_task = task_create("init", init_thread, 0, NORMAL_PRIORITY);

    worker_task_count = MIN((uint32_t)cpu_count, (uint32_t)MAX_WORKER_NUM);
    if (worker_task_count == 0)
        worker_task_count = 1;

    for (uint32_t i = 0; i < worker_task_count; i++) {
        char name[32];
        snprintf(name, sizeof(name), "worker%d", i);
        worker_tasks[i] = task_create(name, worker_thread, i, KTHREAD_PRIORITY);
        worker_tasks[i]->state = TASK_BLOCKING;
        worker_tasks[i]->blocking_reason = "worker_wait_for_event";
        if (worker_tasks[i]->cpu_id < MAX_CPU_NUM)
            worker_slot_by_cpu[worker_tasks[i]->cpu_id] = i;
    }

    arch_set_current(idle_tasks[current_cpu_id]);
    task_mark_on_cpu(idle_tasks[current_cpu_id], true);
    task_mm_mark_cpu_active(idle_tasks[current_cpu_id]->mm, current_cpu_id);

    task_initialized = true;

    can_schedule = true;
}

void sys_yield() { schedule(SCHED_FLAG_YIELD); }

int task_block(task_t *task, task_state_t state, int64_t timeout_ns,
               const char *blocking_reason) {
    if (!task || task->cpu_id >= cpu_count) {
        return -EINVAL;
    }

    bool should_sleep = false;
    int result = EOK;
    uint32_t target_cpu = task->cpu_id;
    bool should_trigger_sched_ipi = false;

    bool lock_irq_state = arch_interrupt_enabled();

    arch_disable_interrupt();

    spin_lock(&task->block_lock);

    if (task->wake_pending) {
        task->wake_pending = false;
        result = task->status;
        spin_unlock(&task->block_lock);
        goto ret;
    }

    task->status = EOK;

    if (target_cpu != current_task->cpu_id && task->sched_info &&
        schedulers[target_cpu]) {
        spin_lock(&schedulers[target_cpu]->lock);
        should_trigger_sched_ipi = (schedulers[target_cpu]->curr ==
                                    (struct sched_entity *)task->sched_info);
        spin_unlock(&schedulers[target_cpu]->lock);
    }

    task->state = state;
    task->force_wakeup_ns =
        (timeout_ns > 0) ? (nano_time() + timeout_ns) : UINT64_MAX;
    task->blocking_reason = blocking_reason;

    if (timeout_ns > 0)
        task_timeout_arm(task);
    else
        task_timeout_cancel(task);

    remove_sched_entity(task, schedulers[task->cpu_id]);

    if (task->wake_pending) {
        task->wake_pending = false;
        task_timeout_cancel(task);
        task->state = TASK_READY;
        task->force_wakeup_ns = UINT64_MAX;
        task->blocking_reason = NULL;
        add_sched_entity(task, schedulers[task->cpu_id]);
        result = task->status;
    } else {
        should_sleep = true;
    }

    spin_unlock(&task->block_lock);

    if (!should_sleep)
        goto ret;

    if (should_trigger_sched_ipi) {
        write_barrier();
        irq_trigger_sched_ipi(target_cpu);
    }

    if (lock_irq_state)
        arch_enable_interrupt();

    schedule(SCHED_FLAG_YIELD);

    result = task->status;

ret:
    return result;
}

void task_unblock(task_t *task, int reason) {
    if (!task || task->state == TASK_DIED) {
        return;
    }

    bool irq_state = arch_interrupt_enabled();
    bool should_trigger_sched_ipi = false;

    bool lock_irq_state = arch_interrupt_enabled();

    arch_disable_interrupt();

    spin_lock(&task->block_lock);

    task_timeout_cancel(task);

    if (task->state != TASK_BLOCKING && task->state != TASK_READING_STDIO &&
        task->state != TASK_UNINTERRUPTABLE) {
        task->status = reason;
        task->force_wakeup_ns = UINT64_MAX;
        task->wake_pending = true;
        spin_unlock(&task->block_lock);
        goto ret;
    }

    task->status = reason;
    task->state = TASK_READY;

    task->blocking_reason = NULL;
    task->force_wakeup_ns = UINT64_MAX;
    task->wake_pending = false;

    add_sched_entity(task, schedulers[task->cpu_id]);
    should_trigger_sched_ipi =
        task->cpu_id != current_task->cpu_id && task->cpu_id < cpu_count;

    spin_unlock(&task->block_lock);

    if (should_trigger_sched_ipi)
        irq_trigger_sched_ipi(task->cpu_id);

ret:
    if (irq_state) {
        arch_enable_interrupt();
    }
}

void task_cleanup_fd_info(task_t *task) {
    if (task->fd_info) {
        if (--task->fd_info->ref_count <= 0) {
            with_fd_info_lock(task->fd_info, {
                for (uint64_t i = 0; i < MAX_FD_NUM; i++) {
                    if (task->fd_info->fds[i]) {
                        struct vfs_file *entry = task->fd_info->fds[i];
                        task->fd_info->fds[i] = NULL;
                        task->fd_info->fd_flags[i] = 0;
                        on_close_file_call(task, i, entry);
                        vfs_close_file(entry);
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
        entity->task = NULL;
    }

    task->current_state = TASK_DIED;
    task->state = TASK_DIED;
    task_timeout_cancel(task);
    task_tick_work_cancel(task);

    if (task->exec_file)
        vfs_close_file(task->exec_file);

    task_cleanup_fd_info(task);
    task_fs_put(task->fs);
    task->fs = NULL;
    task_ns_proxy_put(task->nsproxy);
    task->nsproxy = NULL;

    futex_on_exit_task(task);
    pidfd_on_task_exit(task);
    on_exit_task_call(task);

    task->fd_info = NULL;

    task->status = (uint64_t)code;

    task_t *waiting_task = task_lookup_by_pid_nolock(task->waitpid);
    if (waiting_task) {
        task_unblock(waiting_task, EOK);
    }
    if (ptrace_is_traced(task) && task->ptrace_tracer_pid != task->waitpid) {
        task_t *tracer = task_lookup_by_pid_nolock(task->ptrace_tracer_pid);
        if (tracer)
            task_unblock(tracer, EOK);
    }

    if (!task->is_clone && task_has_parent(task)) {
        sigaction_t sa = {0};
        bool sigchld_blocked = false;
        spin_lock(&task_queue_lock);
        task_t *parent = task_lookup_by_pid_nolock(task_parent_pid(task));
        if (!parent) {
            task_parent_index_detach_locked(task, true);
            task->parent = NULL;
            task->parent_pid = 0;
        }
        if (parent && parent->signal && parent->signal->sighand) {
            spin_lock(&parent->signal->sighand->siglock);
            sa = parent->signal->sighand->actions[SIGCHLD];
            sigchld_blocked =
                signal_sigset_has(parent->signal->blocked, SIGCHLD);
            spin_unlock(&parent->signal->sighand->siglock);
        }
        bool ignore_sigchld = (sa.sa_handler == SIG_IGN);

        if (parent && !ignore_sigchld) {
            siginfo_t sigchld_info;
            memset(&sigchld_info, 0, sizeof(siginfo_t));
            sigchld_info.si_signo = SIGCHLD;
            sigchld_info.si_errno = 0;
            sigchld_info._sifields._sigchld._pid = task->pid;
            sigchld_info._sifields._sigchld._uid = task->uid;
            sigchld_info._sifields._sigchld._utime = 0;
            sigchld_info._sifields._sigchld._stime = 0;
            if (code >= 128) {
                sigchld_info.si_code = CLD_KILLED;
                sigchld_info._sifields._sigchld._status = code - 128;
            } else {
                sigchld_info.si_code = CLD_EXITED;
                sigchld_info._sifields._sigchld._status = code;
            }
            task_commit_signal(parent, SIGCHLD, &sigchld_info);
        }

        if (!parent || ignore_sigchld || (sa.sa_flags & SA_NOCLDWAIT)) {
            if (task_try_mark_reaped(task))
                task_enqueue_should_free(task);
        }

        if (parent && !ignore_sigchld && !sigchld_blocked)
            task_unblock(parent, 128 + SIGCHLD);
        spin_unlock(&task_queue_lock);
    } else if (!task_has_parent(task)) {
        if (task_try_mark_reaped(task))
            task_enqueue_should_free(task);
    }
}

uint64_t task_exit_thread(int64_t code) {
    arch_disable_interrupt();

    task_t *self = current_task;

    spin_lock(&task_queue_lock);
    task_t *new_parent = task_pick_reaper_locked(self);
    task_reparent_children_locked(self, new_parent, false);
    spin_unlock(&task_queue_lock);

    task_complete_vfork(self);

    task_exit_inner(self, code);

    can_schedule = true;

    while (1) {
        arch_enable_interrupt();
        schedule(SCHED_FLAG_YIELD);
    }
}

uint64_t task_exit(int64_t code) {
    arch_disable_interrupt();

    task_t *self = current_task;
    task_complete_vfork(self);

    uint64_t current_tgid = self->tgid > 0 ? (uint64_t)self->tgid : self->pid;

    spin_lock(&task_queue_lock);
    if (task_pid_map.buckets) {
        for (size_t i = 0; i < task_pid_map.bucket_count; i++) {
            hashmap_entry_t *entry = &task_pid_map.buckets[i];
            if (!hashmap_entry_is_occupied(entry)) {
                continue;
            }

            task_t *task = (task_t *)entry->value;
            if (!task || task == self || task->state == TASK_DIED ||
                !task->arch_context) {
                continue;
            }

            uint64_t task_tgid =
                task->tgid > 0 ? (uint64_t)task->tgid : task->pid;
            if (task_tgid != current_tgid) {
                continue;
            }

            task->procfs_thread_path = NULL;
            task_send_signal(task, SIGKILL, SI_USER);
        }
    }

    task_t *init = task_lookup_by_pid_nolock(1);
    task_reparent_children_locked(self, init, true);
    spin_unlock(&task_queue_lock);

    task_exit_inner(self, code);

    can_schedule = true;

    while (1) {
        arch_enable_interrupt();
        schedule(SCHED_FLAG_YIELD);
    }
}

static void sched_update_itimer_task(task_t *task, uint64_t now_ms) {
    if (!task || task->state == TASK_DIED)
        return;

    uint64_t rtAt = task->itimer_real.at;
    uint64_t rtReset = task->itimer_real.reset;

    if (rtAt && rtAt <= now_ms) {
        task_commit_signal(task, SIGALRM, NULL);

        if (rtReset) {
            task->itimer_real.at = now_ms + rtReset;
        } else {
            task->itimer_real.at = 0;
        }
    }

    for (int j = 0; j < MAX_TIMERS_NUM; j++) {
        if (task->timers[j] == NULL)
            continue;
        kernel_timer_t *kt = task->timers[j];
        uint64_t now_ns = task_timer_current_time_ns(kt->clock_type);

        if (kt->expires && now_ns >= kt->expires) {
            if (kt->sigev_notify == SIGEV_SIGNAL) {
                siginfo_t info;
                memset(&info, 0, sizeof(info));
                info.si_signo = kt->sigev_signo;
                info.si_code = SI_TIMER;
                info._sifields._timer._tid = j;
                info._sifields._timer._overrun = 0;
                info._sifields._timer._sigval = kt->sigev_value;
                task_commit_signal(task, kt->sigev_signo, &info);
            }

            if (kt->interval) {
                uint64_t delta = now_ns - kt->expires;
                uint64_t periods = delta / kt->interval + 1;
                kt->expires += periods * kt->interval;
            } else {
                kt->expires = 0;
            }
        }
    }

    task_refresh_tick_work_state(task);
}

void sched_wake_worker(uint32_t cpu_id) {
    if (!worker_task_count) {
        return;
    }

    uint32_t slot = sched_worker_slot_for_cpu(cpu_id);
    task_t *worker = worker_tasks[slot];
    if (!worker)
        return;

    uint32_t worker_cpu = worker->cpu_id;
    task_unblock(worker, EOK);
    if (worker_cpu < cpu_count && worker_cpu != current_task->cpu_id) {
        irq_trigger_sched_ipi(worker_cpu);
    }
}

void sched_defer_tick(void) {
    task_t *task = current_task;
    if (!task || !task_has_tick_work(task)) {
        return;
    }

    bool expected = false;
    if (!__atomic_compare_exchange_n(&task->tick_work_queued, &expected, true,
                                     false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE)) {
        return;
    }

    uint32_t queue_id = sched_worker_slot_for_cpu(task->cpu_id);
    task->tick_work_queue_id = queue_id;
    spin_lock(&worker_tick_locks[queue_id]);
    llist_append(&worker_tick_queues[queue_id], &task->tick_work_node);
    spin_unlock(&worker_tick_locks[queue_id]);

    sched_wake_worker(task->cpu_id);
}

void sched_check_wakeup() {
    uint64_t next = __atomic_load_n(&task_timeout_next_ns, __ATOMIC_ACQUIRE);
    if (next != UINT64_MAX && next <= nano_time()) {
        if (softirq_raise(SOFTIRQ_TIMER))
            sched_wake_worker(0);
    }
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

void schedule(uint64_t sched_flags) {
    bool state = arch_interrupt_enabled();

    arch_disable_interrupt();

    task_t *prev = current_task;
    if (prev->preempt_count) {
        goto ret;
    }

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

    if (next->state == TASK_DIED) {
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

    if (prev->mm != next->mm) {
        task_mm_mark_cpu_inactive(prev->mm, cpu_id);
        task_mm_mark_cpu_active(next->mm, cpu_id);
    }

    arch_set_current(next);
    switch_mm(prev, next);
    switch_to(prev, next);

ret:
    if (state) {
        arch_enable_interrupt();
    }
}

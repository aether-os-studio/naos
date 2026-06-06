#include "netserver_internal.h"

typedef struct lwip_thread_bootstrap {
    lwip_thread_fn fn;
    void *arg;
} lwip_thread_bootstrap_t;

static spinlock_t naos_lwip_protect_lock = SPIN_INIT;
static uintptr_t naos_lwip_protect_owner = 0;
static uint32_t naos_lwip_protect_depth = 0;

static uintptr_t naos_lwip_protect_owner_id(void) {
    task_t *task = current_task;

    if (task) {
        return ((uintptr_t)task << 1) | 1UL;
    }

    return ((uintptr_t)(current_cpu_id + 1) << 1);
}

static bool naos_lwip_sem_trywait(sys_sem_t sem) {
    bool acquired = false;

    if (!sem || !sem->valid) {
        return false;
    }

    spin_lock(&sem->sem.lock);
    if (sem->sem.cnt > 0) {
        sem->sem.cnt--;
        acquired = true;
    }
    spin_unlock(&sem->sem.lock);

    return acquired;
}

static void naos_lwip_sem_wait_enqueue_locked(sys_sem_t sem,
                                              wait_node_t *node) {
    if (!sem || !node || node->queued) {
        return;
    }

    node->next = NULL;
    node->queued = true;
    if (sem->wait_tail) {
        sem->wait_tail->next = node;
    } else {
        sem->wait_head = node;
    }
    sem->wait_tail = node;
}

static void naos_lwip_sem_wait_remove_locked(sys_sem_t sem,
                                             wait_node_t *target) {
    wait_node_t *prev = NULL;
    wait_node_t *curr = NULL;

    if (!sem || !target || !target->queued) {
        return;
    }

    curr = sem->wait_head;
    while (curr) {
        if (curr == target) {
            if (prev) {
                prev->next = curr->next;
            } else {
                sem->wait_head = curr->next;
            }
            if (sem->wait_tail == curr) {
                sem->wait_tail = prev;
            }
            curr->next = NULL;
            curr->queued = false;
            return;
        }
        prev = curr;
        curr = curr->next;
    }

    target->next = NULL;
    target->queued = false;
}

static wait_node_t *naos_lwip_sem_wait_dequeue_locked(sys_sem_t sem) {
    wait_node_t *node = NULL;

    if (!sem || !sem->wait_head) {
        return NULL;
    }

    node = sem->wait_head;
    sem->wait_head = node->next;
    if (!sem->wait_head) {
        sem->wait_tail = NULL;
    }
    node->next = NULL;
    node->queued = false;
    return node;
}

sys_prot_t naos_lwip_protect_enter(void) {
    uintptr_t owner = naos_lwip_protect_owner_id();
    sys_prot_t level = naos_lwip_protect_depth;

    if (naos_lwip_protect_depth && naos_lwip_protect_owner == owner) {
        naos_lwip_protect_depth++;
        return level;
    }

    spin_lock(&naos_lwip_protect_lock);
    naos_lwip_protect_owner = owner;
    naos_lwip_protect_depth = 1;
    return 0;
}

void naos_lwip_protect_leave(sys_prot_t level) {
    (void)level;

    uintptr_t owner = naos_lwip_protect_owner_id();

    if (!naos_lwip_protect_depth || naos_lwip_protect_owner != owner) {
        return;
    }

    naos_lwip_protect_depth--;
    if (naos_lwip_protect_depth == 0) {
        naos_lwip_protect_owner = 0;
        spin_unlock(&naos_lwip_protect_lock);
    }
}

void sys_init(void) {}

err_t sys_sem_new(sys_sem_t *sem, u8_t count) {
    sys_sem_t created = calloc(1, sizeof(*created));
    if (!created) {
        return ERR_MEM;
    }

    spin_init(&created->sem.lock);
    created->sem.cnt = count;
    created->sem.invalid = false;
    created->wait_head = NULL;
    created->wait_tail = NULL;
    created->valid = true;
    *sem = created;
    return ERR_OK;
}

void sys_sem_signal(sys_sem_t *sem) {
    wait_node_t *node = NULL;
    task_t *waiter = NULL;

    if (!sem || !*sem || !(*sem)->valid) {
        return;
    }

    spin_lock(&(*sem)->sem.lock);
    (*sem)->sem.cnt++;
    while ((node = naos_lwip_sem_wait_dequeue_locked(*sem))) {
        waiter = node->task;
        node->task = NULL;
        if (waiter && waiter->state != TASK_DIED) {
            break;
        }
        waiter = NULL;
    }
    spin_unlock(&(*sem)->sem.lock);

    if (waiter) {
        task_unblock(waiter, EOK);
    }
}

u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout) {
    uint64_t start = nano_time();
    uint64_t timeout_ns = timeout ? (uint64_t)timeout * 1000000ULL : 0;
    sys_sem_t s = NULL;
    wait_node_t wait_node;

    if (!sem || !*sem || !(*sem)->valid) {
        return SYS_ARCH_TIMEOUT;
    }
    s = *sem;
    memset(&wait_node, 0, sizeof(wait_node));
    wait_node.task = current_task;

    for (;;) {
        uint64_t now = 0;
        int64_t block_ns = -1;
        int reason = EOK;

        spin_lock(&s->sem.lock);
        if (!s->valid) {
            naos_lwip_sem_wait_remove_locked(s, &wait_node);
            spin_unlock(&s->sem.lock);
            return SYS_ARCH_TIMEOUT;
        }
        if (s->sem.cnt > 0) {
            s->sem.cnt--;
            naos_lwip_sem_wait_remove_locked(s, &wait_node);
            spin_unlock(&s->sem.lock);
            break;
        }

        now = nano_time();
        if (timeout_ns && now - start >= timeout_ns) {
            naos_lwip_sem_wait_remove_locked(s, &wait_node);
            spin_unlock(&s->sem.lock);
            return SYS_ARCH_TIMEOUT;
        }

        wait_node.task = current_task;
        naos_lwip_sem_wait_enqueue_locked(s, &wait_node);
        if (timeout_ns) {
            uint64_t elapsed = now - start;
            block_ns = (int64_t)(timeout_ns - elapsed);
        }
        spin_unlock(&s->sem.lock);

        bool irq = arch_interrupt_enabled();
        arch_enable_interrupt();
        arch_wait_for_interrupt();
        if (!irq)
            arch_disable_interrupt();
    }

    if (!timeout) {
        return 0;
    }

    return (u32_t)((nano_time() - start) / 1000000ULL);
}

void sys_sem_free(sys_sem_t *sem) {
    wait_node_t *node = NULL;
    bool has_waiters = false;

    if (!sem || !*sem) {
        return;
    }

    spin_lock(&(*sem)->sem.lock);
    has_waiters = (*sem)->wait_head != NULL;
    (*sem)->valid = false;
    node = naos_lwip_sem_wait_dequeue_locked(*sem);
    spin_unlock(&(*sem)->sem.lock);

    while (node) {
        task_t *waiter = node->task;
        node->task = NULL;
        if (waiter && waiter->state != TASK_DIED) {
            task_unblock(waiter, EOK);
        }

        spin_lock(&(*sem)->sem.lock);
        node = naos_lwip_sem_wait_dequeue_locked(*sem);
        spin_unlock(&(*sem)->sem.lock);
    }

    if (has_waiters) {
        *sem = NULL;
        return;
    }

    free(*sem);
    *sem = NULL;
}

int sys_sem_valid(sys_sem_t *sem) { return sem && *sem && (*sem)->valid; }

void sys_sem_set_invalid(sys_sem_t *sem) {
    if (sem) {
        *sem = NULL;
    }
}

err_t sys_mutex_new(sys_mutex_t *mutex) {
    sys_mutex_t created = calloc(1, sizeof(*created));
    if (!created) {
        return ERR_MEM;
    }

    mutex_init(&created->lock);
    created->valid = true;
    *mutex = created;
    return ERR_OK;
}

void sys_mutex_lock(sys_mutex_t *mutex) {
    if (mutex && *mutex && (*mutex)->valid) {
        mutex_lock(&(*mutex)->lock);
    }
}

void sys_mutex_unlock(sys_mutex_t *mutex) {
    if (mutex && *mutex && (*mutex)->valid) {
        mutex_unlock(&(*mutex)->lock);
    }
}

void sys_mutex_free(sys_mutex_t *mutex) {
    if (!mutex || !*mutex) {
        return;
    }
    (*mutex)->valid = false;
    free(*mutex);
    *mutex = NULL;
}

int sys_mutex_valid(sys_mutex_t *mutex) {
    return mutex && *mutex && (*mutex)->valid;
}

void sys_mutex_set_invalid(sys_mutex_t *mutex) {
    if (mutex) {
        *mutex = NULL;
    }
}

err_t sys_mbox_new(sys_mbox_t *mbox, int size) {
    sys_mbox_t created = calloc(1, sizeof(*created));
    if (!created) {
        return ERR_MEM;
    }
    if (size <= 0) {
        size = 1;
    }

    created->entries = calloc((size_t)size, sizeof(void *));
    if (!created->entries) {
        free(created);
        return ERR_MEM;
    }

    created->size = (u32_t)size;
    created->valid = true;

    if (sys_sem_new(&created->not_empty, 0) != ERR_OK ||
        sys_sem_new(&created->not_full, (u8_t)MIN(size, 255)) != ERR_OK ||
        sys_mutex_new(&created->lock) != ERR_OK) {
        sys_sem_free(&created->not_empty);
        sys_sem_free(&created->not_full);
        sys_mutex_free(&created->lock);
        free(created->entries);
        free(created);
        return ERR_MEM;
    }

    for (int i = 255; i < size; i++) {
        sem_post(&created->not_full->sem);
    }

    *mbox = created;
    return ERR_OK;
}

void sys_mbox_post(sys_mbox_t *mbox, void *msg) {
    if (!mbox || !*mbox || !(*mbox)->valid) {
        return;
    }

    while (sys_arch_sem_wait(&(*mbox)->not_full, 0) == SYS_ARCH_TIMEOUT) {
    }

    sys_mutex_lock(&(*mbox)->lock);
    (*mbox)->entries[(*mbox)->tail] = msg;
    (*mbox)->tail = ((*mbox)->tail + 1U) % (*mbox)->size;
    sys_mutex_unlock(&(*mbox)->lock);
    sys_sem_signal(&(*mbox)->not_empty);
}

err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg) {
    if (!mbox || !*mbox || !(*mbox)->valid) {
        return ERR_VAL;
    }
    if (!naos_lwip_sem_trywait((*mbox)->not_full)) {
        return ERR_MEM;
    }

    sys_mutex_lock(&(*mbox)->lock);
    (*mbox)->entries[(*mbox)->tail] = msg;
    (*mbox)->tail = ((*mbox)->tail + 1U) % (*mbox)->size;
    sys_mutex_unlock(&(*mbox)->lock);
    sys_sem_signal(&(*mbox)->not_empty);
    return ERR_OK;
}

err_t sys_mbox_trypost_fromisr(sys_mbox_t *mbox, void *msg) {
    return sys_mbox_trypost(mbox, msg);
}

u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout) {
    u32_t waited = 0;

    if (!mbox || !*mbox || !(*mbox)->valid) {
        return SYS_ARCH_TIMEOUT;
    }

    waited = sys_arch_sem_wait(&(*mbox)->not_empty, timeout);
    if (waited == SYS_ARCH_TIMEOUT) {
        if (msg) {
            *msg = NULL;
        }
        return SYS_ARCH_TIMEOUT;
    }

    sys_mutex_lock(&(*mbox)->lock);
    if (msg) {
        *msg = (*mbox)->entries[(*mbox)->head];
    }
    (*mbox)->entries[(*mbox)->head] = NULL;
    (*mbox)->head = ((*mbox)->head + 1U) % (*mbox)->size;
    sys_mutex_unlock(&(*mbox)->lock);
    sys_sem_signal(&(*mbox)->not_full);

    return waited;
}

u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg) {
    if (!mbox || !*mbox || !(*mbox)->valid) {
        return SYS_MBOX_EMPTY;
    }
    if (!naos_lwip_sem_trywait((*mbox)->not_empty)) {
        if (msg) {
            *msg = NULL;
        }
        return SYS_MBOX_EMPTY;
    }

    sys_mutex_lock(&(*mbox)->lock);
    if (msg) {
        *msg = (*mbox)->entries[(*mbox)->head];
    }
    (*mbox)->entries[(*mbox)->head] = NULL;
    (*mbox)->head = ((*mbox)->head + 1U) % (*mbox)->size;
    sys_mutex_unlock(&(*mbox)->lock);
    sys_sem_signal(&(*mbox)->not_full);
    return 0;
}

void sys_mbox_free(sys_mbox_t *mbox) {
    if (!mbox || !*mbox) {
        return;
    }
    (*mbox)->valid = false;
    sys_sem_free(&(*mbox)->not_empty);
    sys_sem_free(&(*mbox)->not_full);
    sys_mutex_free(&(*mbox)->lock);
    free((*mbox)->entries);
    free(*mbox);
    *mbox = NULL;
}

int sys_mbox_valid(sys_mbox_t *mbox) { return mbox && *mbox && (*mbox)->valid; }

void sys_mbox_set_invalid(sys_mbox_t *mbox) {
    if (mbox) {
        *mbox = NULL;
    }
}

static void lwip_sys_thread_entry(uint64_t arg) {
    lwip_thread_bootstrap_t *bootstrap = (lwip_thread_bootstrap_t *)arg;
    lwip_thread_fn fn = bootstrap->fn;
    void *thread_arg = bootstrap->arg;

    free(bootstrap);
    arch_enable_interrupt();
    fn(thread_arg);
    arch_disable_interrupt();
}

sys_thread_t sys_thread_new(const char *name, lwip_thread_fn thread, void *arg,
                            int stacksize, int prio) {
    LWIP_UNUSED_ARG(stacksize);
    LWIP_UNUSED_ARG(prio);

    lwip_thread_bootstrap_t *bootstrap = malloc(sizeof(*bootstrap));
    if (!bootstrap) {
        return NULL;
    }

    bootstrap->fn = thread;
    bootstrap->arg = arg;

    task_t *task = task_create(name ? name : "lwip", lwip_sys_thread_entry,
                               (uint64_t)bootstrap, KTHREAD_PRIORITY);
    if (!task) {
        free(bootstrap);
        return NULL;
    }
    return task;
}

u32_t sys_now(void) { return (u32_t)(nano_time() / 1000000ULL); }

u32_t sys_jiffies(void) { return (u32_t)(nano_time() / 1000000ULL); }

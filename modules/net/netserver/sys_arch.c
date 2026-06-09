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

static bool naos_lwip_sem_has_waiters(sys_sem_t sem) {
    bool has_waiters = false;

    if (!sem) {
        return false;
    }

    spin_lock(&sem->sem.lock);
    has_waiters = sem->wait_head != NULL;
    spin_unlock(&sem->sem.lock);

    return has_waiters;
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

static void naos_lwip_mutex_wait_enqueue_locked(sys_mutex_t mutex,
                                                wait_node_t *node) {
    if (!mutex || !node || node->queued) {
        return;
    }

    node->next = NULL;
    node->queued = true;
    if (mutex->wait_tail) {
        mutex->wait_tail->next = node;
    } else {
        mutex->wait_head = node;
    }
    mutex->wait_tail = node;
}

static void naos_lwip_mutex_wait_remove_locked(sys_mutex_t mutex,
                                               wait_node_t *target) {
    wait_node_t *prev = NULL;
    wait_node_t *curr = NULL;

    if (!mutex || !target || !target->queued) {
        return;
    }

    curr = mutex->wait_head;
    while (curr) {
        if (curr == target) {
            if (prev) {
                prev->next = curr->next;
            } else {
                mutex->wait_head = curr->next;
            }
            if (mutex->wait_tail == curr) {
                mutex->wait_tail = prev;
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

static wait_node_t *naos_lwip_mutex_wait_dequeue_locked(sys_mutex_t mutex) {
    wait_node_t *node = NULL;

    if (!mutex || !mutex->wait_head) {
        return NULL;
    }

    node = mutex->wait_head;
    mutex->wait_head = node->next;
    if (!mutex->wait_head) {
        mutex->wait_tail = NULL;
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

        task_prepare_block(current_task);
        spin_lock(&s->sem.lock);
        if (!s->valid) {
            naos_lwip_sem_wait_remove_locked(s, &wait_node);
            spin_unlock(&s->sem.lock);
            task_cancel_block_prepare(current_task);
            return SYS_ARCH_TIMEOUT;
        }
        if (s->sem.cnt > 0) {
            s->sem.cnt--;
            naos_lwip_sem_wait_remove_locked(s, &wait_node);
            spin_unlock(&s->sem.lock);
            task_cancel_block_prepare(current_task);
            break;
        }

        now = nano_time();
        if (timeout_ns && now - start >= timeout_ns) {
            naos_lwip_sem_wait_remove_locked(s, &wait_node);
            spin_unlock(&s->sem.lock);
            task_cancel_block_prepare(current_task);
            return SYS_ARCH_TIMEOUT;
        }

        wait_node.task = current_task;
        naos_lwip_sem_wait_enqueue_locked(s, &wait_node);
        if (timeout_ns) {
            uint64_t elapsed = now - start;
            block_ns = (int64_t)(timeout_ns - elapsed);
        }
        spin_unlock(&s->sem.lock);

        reason =
            task_block(current_task, TASK_BLOCKING, block_ns, "lwip_sem_wait");
        if (reason == ETIMEDOUT && timeout_ns) {
            spin_lock(&s->sem.lock);
            naos_lwip_sem_wait_remove_locked(s, &wait_node);
            spin_unlock(&s->sem.lock);
            task_cancel_block_prepare(current_task);
            return SYS_ARCH_TIMEOUT;
        }
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

    spin_init(&created->lock);
    created->wait_head = NULL;
    created->wait_tail = NULL;
    created->owner = 0;
    created->depth = 0;
    created->locked = false;
    created->valid = true;
    *mutex = created;
    return ERR_OK;
}

void sys_spin_lock(sys_mutex_t *mutex) {
    sys_mutex_t m = NULL;
    wait_node_t wait_node;
    uintptr_t owner = naos_lwip_protect_owner_id();

    if (!mutex || !*mutex || !(*mutex)->valid) {
        return;
    }
    m = *mutex;

    if (!current_task || current_task->preempt_count) {
        for (;;) {
            bool acquired = false;

            spin_lock(&m->lock);
            if (!m->valid) {
                spin_unlock(&m->lock);
                return;
            }
            if (!m->locked) {
                m->locked = true;
                m->owner = owner;
                m->depth = 1;
                acquired = true;
            } else if (m->owner == owner) {
                m->depth++;
                acquired = true;
            }
            spin_unlock(&m->lock);

            if (acquired) {
                return;
            }
            arch_pause();
        }
    }

    memset(&wait_node, 0, sizeof(wait_node));
    wait_node.task = current_task;

    for (;;) {
        int reason = EOK;

        task_prepare_block(current_task);
        spin_lock(&m->lock);
        if (!m->valid) {
            naos_lwip_mutex_wait_remove_locked(m, &wait_node);
            spin_unlock(&m->lock);
            task_cancel_block_prepare(current_task);
            return;
        }
        if (!m->locked) {
            m->locked = true;
            m->owner = owner;
            m->depth = 1;
            naos_lwip_mutex_wait_remove_locked(m, &wait_node);
            spin_unlock(&m->lock);
            task_cancel_block_prepare(current_task);
            return;
        }
        if (m->owner == owner) {
            m->depth++;
            naos_lwip_mutex_wait_remove_locked(m, &wait_node);
            spin_unlock(&m->lock);
            task_cancel_block_prepare(current_task);
            return;
        }

        wait_node.task = current_task;
        naos_lwip_mutex_wait_enqueue_locked(m, &wait_node);
        spin_unlock(&m->lock);

        reason = task_block(current_task, TASK_BLOCKING, -1, "lwip_mutex_lock");
        if (reason < 0) {
            spin_lock(&m->lock);
            naos_lwip_mutex_wait_remove_locked(m, &wait_node);
            spin_unlock(&m->lock);
            task_cancel_block_prepare(current_task);
            return;
        }
    }
}

void sys_spin_unlock(sys_mutex_t *mutex) {
    sys_mutex_t m = NULL;
    uintptr_t owner = naos_lwip_protect_owner_id();
    wait_node_t *node = NULL;
    task_t *waiter = NULL;

    if (!mutex || !*mutex || !(*mutex)->valid) {
        return;
    }
    m = *mutex;

    spin_lock(&m->lock);
    if (!m->locked || m->owner != owner) {
        spin_unlock(&m->lock);
        return;
    }

    if (m->depth > 1) {
        m->depth--;
        spin_unlock(&m->lock);
        return;
    }

    while ((node = naos_lwip_mutex_wait_dequeue_locked(m))) {
        waiter = node->task;
        node->task = NULL;
        if (waiter && waiter->state != TASK_DIED) {
            break;
        }
        waiter = NULL;
    }

    m->locked = false;
    m->owner = 0;
    m->depth = 0;
    spin_unlock(&m->lock);

    if (waiter) {
        task_unblock(waiter, EOK);
    }
}

void sys_mutex_free(sys_mutex_t *mutex) {
    wait_node_t *node = NULL;
    bool has_waiters = false;

    if (!mutex || !*mutex) {
        return;
    }

    spin_lock(&(*mutex)->lock);
    has_waiters = (*mutex)->wait_head != NULL;
    (*mutex)->valid = false;
    (*mutex)->locked = false;
    (*mutex)->owner = 0;
    (*mutex)->depth = 0;
    node = naos_lwip_mutex_wait_dequeue_locked(*mutex);
    spin_unlock(&(*mutex)->lock);

    while (node) {
        task_t *waiter = node->task;
        node->task = NULL;
        if (waiter && waiter->state != TASK_DIED) {
            task_unblock(waiter, EOK);
        }

        spin_lock(&(*mutex)->lock);
        node = naos_lwip_mutex_wait_dequeue_locked(*mutex);
        spin_unlock(&(*mutex)->lock);
    }

    if (has_waiters) {
        *mutex = NULL;
        return;
    }

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
    sys_mbox_t m = NULL;

    if (!mbox || !*mbox || !(*mbox)->valid) {
        return;
    }
    m = *mbox;

    while (sys_arch_sem_wait(&m->not_full, 0) == SYS_ARCH_TIMEOUT) {
        return;
    }

    sys_spin_lock(&m->lock);
    if (!m->valid || m->count >= m->size) {
        sys_spin_unlock(&m->lock);
        sys_sem_signal(&m->not_full);
        return;
    }
    m->entries[m->tail] = msg;
    m->tail = (m->tail + 1U) % m->size;
    m->count++;
    sys_spin_unlock(&m->lock);
    sys_sem_signal(&m->not_empty);
}

err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg) {
    sys_mbox_t m = NULL;

    if (!mbox || !*mbox || !(*mbox)->valid) {
        return ERR_VAL;
    }
    m = *mbox;
    if (!naos_lwip_sem_trywait(m->not_full)) {
        return ERR_MEM;
    }

    sys_spin_lock(&m->lock);
    if (!m->valid || m->count >= m->size) {
        sys_spin_unlock(&m->lock);
        sys_sem_signal(&m->not_full);
        return ERR_VAL;
    }
    m->entries[m->tail] = msg;
    m->tail = (m->tail + 1U) % m->size;
    m->count++;
    sys_spin_unlock(&m->lock);
    sys_sem_signal(&m->not_empty);
    return ERR_OK;
}

err_t sys_mbox_trypost_fromisr(sys_mbox_t *mbox, void *msg) {
    return sys_mbox_trypost(mbox, msg);
}

u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout) {
    u32_t waited = 0;
    sys_mbox_t m = NULL;

    if (!mbox || !*mbox || !(*mbox)->valid) {
        if (msg) {
            *msg = NULL;
        }
        return SYS_ARCH_TIMEOUT;
    }
    m = *mbox;

    waited = sys_arch_sem_wait(&m->not_empty, timeout);
    if (waited == SYS_ARCH_TIMEOUT) {
        if (msg) {
            *msg = NULL;
        }
        return SYS_ARCH_TIMEOUT;
    }

    sys_spin_lock(&m->lock);
    if (!m->valid || m->count == 0) {
        sys_spin_unlock(&m->lock);
        if (msg) {
            *msg = NULL;
        }
        if (m->valid) {
            sys_sem_signal(&m->not_empty);
        }
        return SYS_ARCH_TIMEOUT;
    }
    if (msg) {
        *msg = m->entries[m->head];
    }
    m->entries[m->head] = NULL;
    m->head = (m->head + 1U) % m->size;
    m->count--;
    sys_spin_unlock(&m->lock);
    sys_sem_signal(&m->not_full);

    return waited;
}

u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg) {
    sys_mbox_t m = NULL;

    if (!mbox || !*mbox || !(*mbox)->valid) {
        if (msg) {
            *msg = NULL;
        }
        return SYS_MBOX_EMPTY;
    }
    m = *mbox;
    if (!naos_lwip_sem_trywait(m->not_empty)) {
        if (msg) {
            *msg = NULL;
        }
        return SYS_MBOX_EMPTY;
    }

    sys_spin_lock(&m->lock);
    if (!m->valid || m->count == 0) {
        sys_spin_unlock(&m->lock);
        if (msg) {
            *msg = NULL;
        }
        if (m->valid) {
            sys_sem_signal(&m->not_empty);
        }
        return SYS_MBOX_EMPTY;
    }
    if (msg) {
        *msg = m->entries[m->head];
    }
    m->entries[m->head] = NULL;
    m->head = (m->head + 1U) % m->size;
    m->count--;
    sys_spin_unlock(&m->lock);
    sys_sem_signal(&m->not_full);
    return 0;
}

void sys_mbox_free(sys_mbox_t *mbox) {
    sys_mbox_t m = NULL;
    bool has_waiters = false;

    if (!mbox || !*mbox) {
        return;
    }
    m = *mbox;
    *mbox = NULL;
    has_waiters = naos_lwip_sem_has_waiters(m->not_empty) ||
                  naos_lwip_sem_has_waiters(m->not_full);

    sys_spin_lock(&m->lock);
    m->valid = false;
    m->count = 0;
    sys_spin_unlock(&m->lock);

    sys_sem_free(&m->not_empty);
    sys_sem_free(&m->not_full);
    if (has_waiters) {
        return;
    }

    sys_mutex_free(&m->lock);
    free(m->entries);
    free(m);
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

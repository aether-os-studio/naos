#include "netserver_internal.h"

typedef struct lwip_thread_bootstrap {
    lwip_thread_fn fn;
    void *arg;
} lwip_thread_bootstrap_t;

static spinlock_t naos_lwip_protect_lock = SPIN_INIT;

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

void naos_lwip_protect_enter(void) { spin_lock(&naos_lwip_protect_lock); }

void naos_lwip_protect_leave(void) { spin_unlock(&naos_lwip_protect_lock); }

void sys_init(void) {}

err_t sys_sem_new(sys_sem_t *sem, u8_t count) {
    sys_sem_t created = calloc(1, sizeof(*created));
    if (!created) {
        return ERR_MEM;
    }

    spin_init(&created->sem.lock);
    created->sem.cnt = count;
    created->sem.invalid = false;
    created->valid = true;
    *sem = created;
    return ERR_OK;
}

void sys_sem_signal(sys_sem_t *sem) {
    if (!sem || !*sem || !(*sem)->valid) {
        return;
    }
    sem_post(&(*sem)->sem);
}

u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout) {
    uint64_t start = nano_time();
    uint64_t timeout_ns = timeout ? (uint64_t)timeout * 1000000ULL : 0;

    if (!sem || !*sem || !(*sem)->valid) {
        return SYS_ARCH_TIMEOUT;
    }

    while (!naos_lwip_sem_trywait(*sem)) {
        if (timeout_ns && nano_time() - start >= timeout_ns) {
            return SYS_ARCH_TIMEOUT;
        }
        task_block(current_task, TASK_BLOCKING, 1000000, "lwip_sem_wait");
    }

    if (!timeout) {
        return 0;
    }

    return (u32_t)((nano_time() - start) / 1000000ULL);
}

void sys_sem_free(sys_sem_t *sem) {
    if (!sem || !*sem) {
        return;
    }
    (*sem)->valid = false;
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
    task_exit_thread(0);
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

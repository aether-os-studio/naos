#pragma once

#include <libs/mutex.h>
#include <libs/klibc.h>
#include <task/task.h>

typedef unsigned long sys_prot_t;

typedef struct naos_lwip_sem {
    sem_t sem;
    bool valid;
} *sys_sem_t;

typedef struct naos_lwip_mutex {
    mutex_t lock;
    bool valid;
} *sys_mutex_t;

typedef struct naos_lwip_mbox {
    void **entries;
    u32_t size;
    u32_t head;
    u32_t tail;
    sys_sem_t not_empty;
    sys_sem_t not_full;
    sys_mutex_t lock;
    bool valid;
} *sys_mbox_t;

typedef task_t *sys_thread_t;

void naos_lwip_protect_enter(void);
void naos_lwip_protect_leave(void);

#define SYS_ARCH_DECL_PROTECT(level) sys_prot_t level
#define SYS_ARCH_PROTECT(level)                                                \
    do {                                                                       \
        (void)(level);                                                         \
        naos_lwip_protect_enter();                                             \
    } while (0)
#define SYS_ARCH_UNPROTECT(level)                                              \
    do {                                                                       \
        (void)(level);                                                         \
        naos_lwip_protect_leave();                                             \
    } while (0)

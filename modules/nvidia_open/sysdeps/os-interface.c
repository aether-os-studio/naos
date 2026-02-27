#include "nvidia_open.h"

#include <boot/boot.h>
#include <libs/aether/acpi.h>
#include <libs/aether/mm.h>
#include <libs/aether/smbios.h>
#include <libs/aether/stdio.h>
#include <libs/aether/task.h>
#include <libs/aether/time.h>
#include <libs/klibc.h>
#include <fs/vfs/vfs.h>

#include <nv.h>
#include <nv-firmware.h>
#include <os-interface.h>

#if defined(__x86_64__)
#include <arch/x64/io.h>
#endif

#define STUBBED                                                                \
    {                                                                          \
        ASSERT(!"Unimplemented");                                              \
    }

NvU32 os_page_size = DEFAULT_PAGE_SIZE;
NvU64 os_page_mask = ~(DEFAULT_PAGE_SIZE - 1);
NvU8 os_page_shift = 12;
NvBool os_cc_enabled = 0;
NvBool os_cc_sev_snp_enabled = 0;
NvBool os_cc_snp_vtom_enabled = 0;
NvBool os_cc_tdx_enabled = 0;
NvBool os_cc_sme_enabled = 0;

spinlock_t timerLock = SPIN_INIT;

typedef struct os_wait_entry {
    task_t *task;
    struct os_wait_entry *next;
    bool queued;
    bool woken;
} os_wait_entry_t;

struct os_wait_queue {
    spinlock_t lock;
    os_wait_entry_t *head;
    os_wait_entry_t *tail;
    NvU32 pending;
};

static void os_wait_queue_push(os_wait_queue *wq, os_wait_entry_t *entry) {
    entry->next = NULL;
    entry->queued = true;

    if (wq->tail) {
        wq->tail->next = entry;
    } else {
        wq->head = entry;
    }
    wq->tail = entry;
}

static os_wait_entry_t *os_wait_queue_pop(os_wait_queue *wq) {
    os_wait_entry_t *entry = wq->head;
    if (!entry) {
        return NULL;
    }

    wq->head = entry->next;
    if (!wq->head) {
        wq->tail = NULL;
    }
    entry->next = NULL;
    entry->queued = false;
    return entry;
}

static void os_wait_common(os_wait_queue *wq, const char *reason) {
    if (!wq || !current_task) {
        return;
    }

    os_wait_entry_t entry = {
        .task = current_task,
        .next = NULL,
        .queued = false,
        .woken = false,
    };

    while (true) {
        spin_lock(&wq->lock);
        if (wq->pending > 0) {
            wq->pending--;
            spin_unlock(&wq->lock);
            return;
        }
        if (!entry.queued) {
            os_wait_queue_push(wq, &entry);
        }
        spin_unlock(&wq->lock);

        (void)task_block(current_task, TASK_BLOCKING, -1, reason);

        spin_lock(&wq->lock);
        if (entry.woken) {
            spin_unlock(&wq->lock);
            return;
        }
        spin_unlock(&wq->lock);
    }
}

typedef struct {
    sem_t sem;
} os_mutex_t;

typedef struct {
    sem_t sem;
} os_semaphore_t;

typedef struct {
    sem_t sem;
} os_rwlock_t;

static void os_sem_init(sem_t *sem, NvU32 initial) {
    memset(sem, 0, sizeof(*sem));
    spin_init(&sem->lock);
    sem->cnt = initial;
    sem->invalid = false;
}

static NvBool os_sem_try_acquire(sem_t *sem) {
    NvBool acquired = NV_FALSE;

    spin_lock(&sem->lock);
    if (sem->cnt > 0) {
        sem->cnt--;
        acquired = NV_TRUE;
    }
    spin_unlock(&sem->lock);

    return acquired;
}

static NvBool os_in_interrupt_context(void) { return NV_FALSE; }

NV_STATUS NV_API_CALL os_alloc_mem(void **address, NvU64 size) {
    if (!address)
        return NV_ERR_INVALID_ARGUMENT;

    *address = malloc(size);
    return ((*address != NULL) ? NV_OK : NV_ERR_NO_MEMORY);
}

void NV_API_CALL os_free_mem(void *ptr) {
    if (ptr)
        free(ptr);
}

NV_STATUS NV_API_CALL os_get_current_time(NvU32 *sec, NvU32 *usec) {
    tm time;
    time_read(&time);
    *sec = mktime(&time);
    *usec = 0;
    return NV_OK;
}

NvU64 NV_API_CALL os_get_current_tick(void) { return nano_time(); }

NvU64 NV_API_CALL os_get_current_tick_hr(void) { return nano_time(); }

NvU64 NV_API_CALL os_get_tick_resolution(void) { return 1; }

static void delay(uint64_t ns) {
    uint64_t start = nano_time();
    while (nano_time() - start < ns) {
        schedule(SCHED_FLAG_YIELD);
    }
}

NV_STATUS NV_API_CALL os_delay(NvU32 ms) {
    delay(ms * 1000000);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_delay_us(NvU32 us) {
    delay(us * 1000);
    return NV_OK;
}

NvU64 NV_API_CALL os_get_cpu_frequency(void) { return 0; }

NvU32 NV_API_CALL os_get_current_process(void) {
    if (!current_task) {
        return 0;
    }
    return (NvU32)current_task->pid;
}

void NV_API_CALL os_get_current_process_name(char *buf, NvU32 len) {
    if (!buf || len == 0) {
        return;
    }

    strncpy(buf, "NVIDIA_OPEN", len - 1);
    buf[len - 1] = '\0';
}

NV_STATUS NV_API_CALL os_get_current_thread(NvU64 *tid) {
    if (!tid) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (!current_task) {
        *tid = 0;
    } else {
        *tid = (NvU64)current_task->pid;
    }

    return NV_OK;
}

char *NV_API_CALL os_string_copy(char *dst, const char *src) {
    strcpy(dst, src);
    return dst;
}

NvU32 NV_API_CALL os_string_length(const char *str) { return strlen(str); }

unsigned long strtoul(const char *nptr, char **endptr, register int base) {
    register const char *s = nptr;
    register unsigned long acc;
    register int c;
    register unsigned long cutoff;
    register int neg = 0, any, cutlim;

    /*
     * See strtol for comments as to the logic used.
     */
    do {
        c = *s++;
    } while (c == ' ' || c == '\t');
    if (c == '-') {
        neg = 1;
        c = *s++;
    } else if (c == '+')
        c = *s++;
    if ((base == 0 || base == 16) && c == '0' && (*s == 'x' || *s == 'X')) {
        c = s[1];
        s += 2;
        base = 16;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;
    cutoff = (unsigned long)ULONG_MAX / (unsigned long)base;
    cutlim = (unsigned long)ULONG_MAX % (unsigned long)base;
    for (acc = 0, any = 0;; c = *s++) {
        if (c >= '0' && c <= '9')
            c -= '0';
        else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
            c -= (c >= 'A' && c <= 'Z') ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = ULONG_MAX;
    } else if (neg)
        acc = -acc;
    if (endptr != 0)
        *endptr = (char *)(any ? s - 1 : nptr);
    return (acc);
}

NvBool NV_API_CALL os_is_isr(void) { return os_in_interrupt_context(); }

NvU32 NV_API_CALL os_strtoul(const char *str, char **endp, NvU32 base) {
    return strtoul(str, endp, base);
}

NvS32 NV_API_CALL os_string_compare(const char *a, const char *b) {
    return strcmp(a, b);
}

NvS32 NV_API_CALL os_snprintf(char *buf, NvU32 size, const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    int ret = vsnprintf(buf, size, fmt, va);
    va_end(va);
    return ret;
}

NvS32 NV_API_CALL os_vsnprintf(char *buf, NvU32 size, const char *fmt,
                               va_list va) {
    return vsnprintf(buf, size, fmt, va);
}

void NV_API_CALL os_log_error(const char *fmt, va_list ap) {
    uint32_t pid = current_task ? (uint32_t)current_task->pid : 0;
    printk("NVIDIA_OPEN: [%u ERROR] ", pid);
    char buf[2048];
    vsprintf(buf, fmt, ap);
    printk("%s", buf);
}

void *os_mem_copy(void *dst, const void *src, NvU32 length) {
    return memcpy(dst, src, length);
}

NV_STATUS NV_API_CALL os_memcpy_from_user(void *dst, const void *src,
                                          NvU32 length) {
    if (!dst || !src) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    return copy_from_user(dst, src, length) ? NV_ERR_INVALID_ADDRESS : NV_OK;
}

NV_STATUS NV_API_CALL os_memcpy_to_user(void *dst, const void *src,
                                        NvU32 length) {
    if (!dst || !src) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    return copy_to_user(dst, src, length) ? NV_ERR_INVALID_ADDRESS : NV_OK;
}

void *os_mem_set(void *dst, NvU8 c, NvU32 length) {
    return memset(dst, (int)c, length);
}

NvS32 os_mem_cmp(const NvU8 *a, const NvU8 *b, NvU32 l) {
    return memcmp(a, b, l);
}

void *NV_API_CALL os_pci_init_handle(NvU32 domain, NvU8 bus, NvU8 slot,
                                     NvU8 func, NvU16 *vendor, NvU16 *dev) {
    pci_device_t *pci_dev = pci_find_bdfs(bus, slot, func, domain);
    if (!pci_dev)
        return NULL;

    if (vendor)
        *vendor = pci_dev->vendor_id;
    if (dev)
        *dev = pci_dev->device_id;

    return pci_dev;
}

NV_STATUS NV_API_CALL os_pci_read_byte(void *handle, NvU32 offset,
                                       NvU8 *pReturnValue) {
    pci_device_t *pci_dev = handle;

    *pReturnValue = (uint8_t)pci_dev->op->read8(
        pci_dev->bus, pci_dev->slot, pci_dev->func, pci_dev->segment, offset);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_read_word(void *handle, NvU32 offset,
                                       NvU16 *pReturnValue) {
    pci_device_t *pci_dev = handle;

    *pReturnValue = (uint16_t)pci_dev->op->read16(
        pci_dev->bus, pci_dev->slot, pci_dev->func, pci_dev->segment, offset);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_read_dword(void *handle, NvU32 offset,
                                        NvU32 *pReturnValue) {
    pci_device_t *pci_dev = handle;

    *pReturnValue = pci_dev->op->read32(
        pci_dev->bus, pci_dev->slot, pci_dev->func, pci_dev->segment, offset);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_byte(void *handle, NvU32 offset,
                                        NvU8 value) {
    pci_device_t *pci_dev = handle;

    pci_dev->op->write8(pci_dev->bus, pci_dev->slot, pci_dev->func,
                        pci_dev->segment, offset, value);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_word(void *handle, NvU32 offset,
                                        NvU16 value) {
    pci_device_t *pci_dev = handle;

    pci_dev->op->write16(pci_dev->bus, pci_dev->slot, pci_dev->func,
                         pci_dev->segment, offset, value);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_dword(void *handle, NvU32 offset,
                                         NvU32 value) {
    pci_device_t *pci_dev = handle;

    pci_dev->op->write32(pci_dev->bus, pci_dev->slot, pci_dev->func,
                         pci_dev->segment, offset, value);
    return NV_OK;
}

NvBool NV_API_CALL os_pci_remove_supported(void) { return NV_FALSE; }
void NV_API_CALL os_pci_remove(void *handle) { (void)handle; }

void *NV_API_CALL os_map_kernel_space(NvU64 start, NvU64 size_bytes,
                                      NvU32 mode) {
    if (!start || !size_bytes) {
        return NULL;
    }

    uint64_t aligned_start = start & ~0xFFFULL;
    uint64_t offset = start & 0xFFFULL;
    uint64_t aligned_size = ((offset + size_bytes + 0xFFFULL) & ~0xFFFULL);
    uint64_t virt = phys_to_virt(aligned_start);

    uint64_t flags = PT_FLAG_R | PT_FLAG_W;
    switch (mode) {
    case NV_MEMORY_CACHED:
        break;
    case NV_MEMORY_DEFAULT:
    case NV_MEMORY_UNCACHED:
    case NV_MEMORY_WRITECOMBINED:
    default:
        flags |= PT_FLAG_UNCACHEABLE;
        break;
    }

    map_page_range(get_current_page_dir(false), virt, aligned_start,
                   aligned_size, flags);

    return (void *)(virt + offset);
}

void NV_API_CALL os_unmap_kernel_space(void *ptr, NvU64 len) {
    // uint64_t alignedAddr = (uintptr_t)ptr & ~0xFFFULL;
    // uint64_t alignedSize =
    //     (((uintptr_t)ptr + len + 0xFFFULL) & ~0xFFFULL) - alignedAddr;
    // unmap_page_range(get_current_page_dir(false), alignedAddr, alignedSize);
}

NV_STATUS NV_API_CALL os_flush_cpu_cache_all(void) {
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_flush_user_cache(void) { return NV_ERR_NOT_SUPPORTED; }

void NV_API_CALL os_flush_cpu_write_combine_buffer(void) {
    asm volatile("sfence" ::: "memory");
}

NvU8 NV_API_CALL os_io_read_byte(NvU32 address) {
#if defined(__x86_64__)
    return io_in8((uint16_t)address);
#else
    (void)address;
    return 0;
#endif
}

NvU16 NV_API_CALL os_io_read_word(NvU32 address) {
#if defined(__x86_64__)
    return io_in16((uint16_t)address);
#else
    (void)address;
    return 0;
#endif
}

NvU32 NV_API_CALL os_io_read_dword(NvU32 address) {
#if defined(__x86_64__)
    return io_in32((uint16_t)address);
#else
    (void)address;
    return 0;
#endif
}

void NV_API_CALL os_io_write_byte(NvU32 address, NvU8 value) {
#if defined(__x86_64__)
    io_out8((uint16_t)address, value);
#else
    (void)address;
    (void)value;
#endif
}

void NV_API_CALL os_io_write_word(NvU32 address, NvU16 value) {
#if defined(__x86_64__)
    io_out16((uint16_t)address, value);
#else
    (void)address;
    (void)value;
#endif
}

void NV_API_CALL os_io_write_dword(NvU32 address, NvU32 value) {
#if defined(__x86_64__)
    io_out32((uint16_t)address, value);
#else
    (void)address;
    (void)value;
#endif
}

NvBool NV_API_CALL os_is_administrator(void) { return NV_TRUE; }

NvBool NV_API_CALL os_check_access(RsAccessRight) { return NV_FALSE; }

void NV_API_CALL os_dbg_init(void) {}

void NV_API_CALL os_dbg_breakpoint(void) {}

void NV_API_CALL os_dbg_set_level(NvU32 level) { (void)level; }

NvU32 NV_API_CALL os_get_cpu_count(void) { return 1; }

NvU32 NV_API_CALL os_get_cpu_number(void) { return 0; }

void NV_API_CALL os_disable_console_access(void) {}
void NV_API_CALL os_enable_console_access(void) {}

NV_STATUS NV_API_CALL os_registry_init(void) {
    const char NVreg_RmMsg[] = "";

    rm_write_registry_string(NULL, NULL, "RmMsg", NVreg_RmMsg,
                             strlen(NVreg_RmMsg));

    return NV_OK;
}

NvU64 NV_API_CALL os_get_max_user_va(void) { return (1ULL << 47) - 0x1000; }

NV_STATUS NV_API_CALL os_schedule(void) {
    schedule(SCHED_FLAG_YIELD);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_alloc_spinlock(void **spinlock) {
    *spinlock = malloc(sizeof(spinlock_t));
    memset(*spinlock, 0, sizeof(spinlock_t));
    return NV_OK;
}

void NV_API_CALL os_free_spinlock(void *spinlock) { free(spinlock); }

NvU64 NV_API_CALL os_acquire_spinlock(void *spinlock) {
    spin_lock(spinlock);
    return 0;
}

void NV_API_CALL os_release_spinlock(void *spinlock, NvU64) {
    spin_unlock(spinlock);
}

NV_STATUS NV_API_CALL os_queue_work_item(struct os_work_queue *queue,
                                         void *data) {
    (void)queue;
    rm_execute_work_item(NULL, data);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_flush_work_queue(struct os_work_queue *queue,
                                          NvBool is_unload) {
    (void)queue;
    (void)is_unload;
    return NV_OK;
}

NvBool NV_API_CALL os_is_queue_flush_ongoing(struct os_work_queue *queue) {
    (void)queue;
    return NV_FALSE;
}

NV_STATUS NV_API_CALL os_alloc_mutex(void **mutex) {
    if (!mutex) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    NV_STATUS status = os_alloc_mem(mutex, sizeof(os_mutex_t));
    if (status != NV_OK) {
        return status;
    }

    os_mutex_t *pm = (os_mutex_t *)(*mutex);
    os_sem_init(&pm->sem, 1);

    return NV_OK;
}

void NV_API_CALL os_free_mutex(void *mutex) {
    if (mutex) {
        os_mutex_t *pm = (os_mutex_t *)(mutex);
        pm->sem.invalid = true;
        free(pm);
    }
}

NV_STATUS NV_API_CALL os_acquire_mutex(void *mutex) {
    if (!mutex) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    if (os_is_isr()) {
        return NV_ERR_INVALID_REQUEST;
    }

    os_mutex_t *pm = (os_mutex_t *)(mutex);
    return sem_wait(&pm->sem, 0) ? NV_OK : NV_ERR_TIMEOUT;
}

NV_STATUS NV_API_CALL os_cond_acquire_mutex(void *mutex) {
    if (!mutex) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    if (os_is_isr()) {
        return NV_ERR_INVALID_REQUEST;
    }
    os_mutex_t *pm = (os_mutex_t *)(mutex);
    if (!os_sem_try_acquire(&pm->sem)) {
        return NV_ERR_TIMEOUT_RETRY;
    }
    return NV_OK;
}

void NV_API_CALL os_release_mutex(void *mutex) {
    if (!mutex) {
        return;
    }
    os_mutex_t *pm = (os_mutex_t *)(mutex);
    sem_post(&pm->sem);
}

void *NV_API_CALL os_alloc_semaphore(NvU32 initial) {
    os_semaphore_t *s = NULL;
    NV_STATUS status = os_alloc_mem((void **)(&s), sizeof(os_semaphore_t));
    if (status != NV_OK) {
        return NULL;
    }

    os_sem_init(&s->sem, initial);
    return s;
}

void NV_API_CALL os_free_semaphore(void *s) {
    if (!s) {
        return;
    }
    os_semaphore_t *sem = (os_semaphore_t *)(s);
    sem->sem.invalid = true;
    free(sem);
}

NV_STATUS NV_API_CALL os_acquire_semaphore(void *s) {
    if (!s) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    if (os_is_isr()) {
        return NV_ERR_INVALID_REQUEST;
    }
    os_semaphore_t *sem = (os_semaphore_t *)(s);
    return sem_wait(&sem->sem, 0) ? NV_OK : NV_ERR_TIMEOUT;
}

NV_STATUS NV_API_CALL os_cond_acquire_semaphore(void *s) {
    if (!s) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    os_semaphore_t *sem = (os_semaphore_t *)(s);
    if (!os_sem_try_acquire(&sem->sem)) {
        return NV_ERR_TIMEOUT_RETRY;
    }
    return NV_OK;
}

NV_STATUS NV_API_CALL os_release_semaphore(void *s) {
    if (!s) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    os_semaphore_t *sem = (os_semaphore_t *)(s);
    sem_post(&sem->sem);
    return NV_OK;
}

void *NV_API_CALL os_alloc_rwlock(void) {
    os_rwlock_t *rwlock = NULL;

    NV_STATUS status = os_alloc_mem((void **)(&rwlock), sizeof(os_rwlock_t));
    if (status != NV_OK) {
        return NULL;
    }

    os_sem_init(&rwlock->sem, 1);

    return rwlock;
}

void NV_API_CALL os_free_rwlock(void *lock) {
    if (lock) {
        os_rwlock_t *rwlock = (os_rwlock_t *)(lock);
        rwlock->sem.invalid = true;
        free(rwlock);
    }
}

NV_STATUS NV_API_CALL os_acquire_rwlock_read(void *l) {
    if (!l) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    if (os_is_isr()) {
        return NV_ERR_INVALID_REQUEST;
    }
    os_rwlock_t *rwlock = (os_rwlock_t *)(l);
    return sem_wait(&rwlock->sem, 0) ? NV_OK : NV_ERR_TIMEOUT;
}

NV_STATUS NV_API_CALL os_acquire_rwlock_write(void *l) {
    if (!l) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    if (os_is_isr()) {
        return NV_ERR_INVALID_REQUEST;
    }
    os_rwlock_t *rwlock = (os_rwlock_t *)(l);
    return sem_wait(&rwlock->sem, 0) ? NV_OK : NV_ERR_TIMEOUT;
}

NV_STATUS NV_API_CALL os_cond_acquire_rwlock_read(void *l) {
    if (!l) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    os_rwlock_t *rwlock = (os_rwlock_t *)(l);
    return os_sem_try_acquire(&rwlock->sem) ? NV_OK : NV_ERR_TIMEOUT_RETRY;
}

NV_STATUS NV_API_CALL os_cond_acquire_rwlock_write(void *l) {
    if (!l) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    os_rwlock_t *rwlock = (os_rwlock_t *)(l);
    return os_sem_try_acquire(&rwlock->sem) ? NV_OK : NV_ERR_TIMEOUT_RETRY;
}

void NV_API_CALL os_release_rwlock_read(void *l) {
    if (!l) {
        return;
    }
    os_rwlock_t *rwlock = (os_rwlock_t *)(l);
    sem_post(&rwlock->sem);
}

void NV_API_CALL os_release_rwlock_write(void *l) {
    if (!l) {
        return;
    }
    os_rwlock_t *rwlock = (os_rwlock_t *)(l);
    sem_post(&rwlock->sem);
}

NvBool NV_API_CALL os_semaphore_may_sleep(void) { return !os_is_isr(); }

NV_STATUS NV_API_CALL os_get_version_info(os_version_info *info) {
    (void)info;
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_get_is_openrm(NvBool *bIsOpenRm) {
    *bIsOpenRm = NV_TRUE;
    return NV_OK;
}

NvBool NV_API_CALL os_pat_supported(void) { return NV_FALSE; }

void NV_API_CALL os_dump_stack(void) STUBBED;

NvBool NV_API_CALL os_is_efi_enabled(void) { return NV_TRUE; }

NvBool NV_API_CALL os_is_xen_dom0(void) { return NV_FALSE; }

NvBool NV_API_CALL os_is_vgx_hyper(void) { return NV_FALSE; }

NV_STATUS NV_API_CALL os_inject_vgx_msi(NvU16, NvU64, NvU32) {
    return NV_ERR_NOT_SUPPORTED;
}

NvBool NV_API_CALL os_is_grid_supported(void) { return NV_FALSE; }

NvU32 NV_API_CALL os_get_grid_csp_support(void) { return 0; }

void NV_API_CALL os_bug_check(NvU32, const char *) STUBBED;
NV_STATUS NV_API_CALL os_lock_user_pages(void *, NvU64, void **, NvU32) STUBBED;
NV_STATUS NV_API_CALL os_lookup_user_io_memory(void *, NvU64, NvU64 **) STUBBED;
NV_STATUS NV_API_CALL os_unlock_user_pages(NvU64, void *, NvU32) STUBBED;
NV_STATUS NV_API_CALL os_match_mmap_offset(void *, NvU64, NvU64 *) STUBBED;
NV_STATUS NV_API_CALL os_get_euid(NvU32 *pEuid) {
    if (!pEuid) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    *pEuid = current_task ? (NvU32)current_task->uid : 0;
    return NV_OK;
}
NV_STATUS NV_API_CALL os_get_smbios_header(NvU64 *pSmbsAddr) {
    if (!pSmbsAddr) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    *pSmbsAddr = 0;
    return NV_ERR_NOT_SUPPORTED;
}
NV_STATUS NV_API_CALL os_get_acpi_rsdp_from_uefi(NvU32 *pRsdpAddr) {
    uint64_t rsdp = get_rsdp_paddr();
    if (rsdp) {
        *pRsdpAddr = (NvU32)rsdp;
        return NV_OK;
    }
    return NV_ERR_NOT_SUPPORTED;
};
void NV_API_CALL os_add_record_for_crashLog(void *, NvU32) {}
void NV_API_CALL os_delete_record_for_crashLog(void *) {}
NV_STATUS NV_API_CALL os_call_vgpu_vfio(void *, NvU32) STUBBED;
NV_STATUS NV_API_CALL os_device_vm_present(void) STUBBED;
NV_STATUS NV_API_CALL os_numa_memblock_size(NvU64 *) STUBBED;
NV_STATUS NV_API_CALL os_alloc_pages_node(NvS32, NvU32, NvU32, NvU64 *) STUBBED;
NV_STATUS NV_API_CALL os_get_page(NvU64 address) STUBBED;
NV_STATUS NV_API_CALL os_put_page(NvU64 address) STUBBED;
NvU32 NV_API_CALL os_get_page_refcount(NvU64 address) STUBBED;
NvU32 NV_API_CALL os_count_tail_pages(NvU64 address) STUBBED;
void NV_API_CALL os_free_pages_phys(NvU64, NvU32) STUBBED;
NV_STATUS NV_API_CALL os_open_temporary_file(void **ppFile) {
    (void)ppFile;
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL os_close_file(void *file) {
    if (!file) {
        return;
    }
    // vfs_close((vfs_node_t)file);
}

NV_STATUS NV_API_CALL os_write_file(void *file, NvU8 *buf, NvU64 count,
                                    NvU64 offset) {
    if (!file || !buf) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    ssize_t written =
        vfs_write((vfs_node_t)file, buf, (size_t)offset, (size_t)count);
    if (written < 0 || (NvU64)written != count) {
        return NV_ERR_OPERATING_SYSTEM;
    }

    return NV_OK;
}

NV_STATUS NV_API_CALL os_read_file(void *file, NvU8 *buf, NvU64 count,
                                   NvU64 offset) {
    if (!file || !buf) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    ssize_t read =
        vfs_read((vfs_node_t)file, buf, (size_t)offset, (size_t)count);
    if (read < 0 || (NvU64)read != count) {
        return NV_ERR_OPERATING_SYSTEM;
    }

    return NV_OK;
}

NV_STATUS NV_API_CALL os_open_readonly_file(const char *filename,
                                            void **ppFile) {
    if (!filename || !ppFile) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    vfs_node_t file = vfs_open(filename, 0);
    if (!file) {
        return NV_ERR_OPERATING_SYSTEM;
    }

    *ppFile = file;
    return NV_OK;
}

NV_STATUS NV_API_CALL os_open_and_read_file(const char *filename, NvU8 *buf,
                                            NvU64 count) {
    void *file = NULL;
    NV_STATUS status = os_open_readonly_file(filename, &file);
    if (status != NV_OK) {
        return status;
    }

    status = os_read_file(file, buf, count, 0);
    os_close_file(file);
    return status;
}

NvBool NV_API_CALL os_is_nvswitch_present(void) { return NV_FALSE; }

NV_STATUS NV_API_CALL os_get_random_bytes(NvU8 *buf, NvU16 numBytes) {
    if (!buf) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    uint64_t state = nano_time() ^ (uint64_t)(uintptr_t)buf;
    for (NvU16 i = 0; i < numBytes; i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        buf[i] = (NvU8)(state & 0xFF);
    }

    return NV_OK;
}
NV_STATUS NV_API_CALL os_alloc_wait_queue(os_wait_queue **ppWq) {
    if (!ppWq) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    os_wait_queue *wq = calloc(1, sizeof(*wq));
    if (!wq) {
        return NV_ERR_NO_MEMORY;
    }

    wq->lock = SPIN_INIT;
    *ppWq = wq;
    return NV_OK;
}

void NV_API_CALL os_free_wait_queue(os_wait_queue *wq) {
    if (!wq) {
        return;
    }

    spin_lock(&wq->lock);
    while (wq->head) {
        os_wait_entry_t *entry = os_wait_queue_pop(wq);
        entry->woken = true;
        if (entry->task && entry->task->state == TASK_BLOCKING) {
            task_unblock(entry->task, EOK);
        }
    }
    spin_unlock(&wq->lock);

    free(wq);
}

void NV_API_CALL os_wait_uninterruptible(os_wait_queue *wq) {
    os_wait_common(wq, "nvidia_wait_queue");
}

void NV_API_CALL os_wait_interruptible(os_wait_queue *wq) {
    os_wait_common(wq, "nvidia_wait_queue_intr");
}

void NV_API_CALL os_wake_up(os_wait_queue *wq) {
    task_t *task = NULL;
    os_wait_entry_t *entry = NULL;

    if (!wq) {
        return;
    }

    spin_lock(&wq->lock);
    entry = os_wait_queue_pop(wq);
    if (entry) {
        entry->woken = true;
        task = entry->task;
    } else {
        wq->pending++;
    }
    spin_unlock(&wq->lock);

    if (task && task->state == TASK_BLOCKING) {
        task_unblock(task, EOK);
    }
}

nv_cap_t *NV_API_CALL os_nv_cap_init(const char *) STUBBED;
nv_cap_t *NV_API_CALL os_nv_cap_create_dir_entry(nv_cap_t *, const char *,
                                                 int) STUBBED;
nv_cap_t *NV_API_CALL os_nv_cap_create_file_entry(nv_cap_t *, const char *,
                                                  int) STUBBED;
void NV_API_CALL os_nv_cap_destroy_entry(nv_cap_t *) STUBBED;
int NV_API_CALL os_nv_cap_validate_and_dup_fd(const nv_cap_t *, int) STUBBED;
void NV_API_CALL os_nv_cap_close_fd(int) STUBBED;
NvS32 NV_API_CALL os_imex_channel_get(NvU64) STUBBED;
NvS32 NV_API_CALL os_imex_channel_count(void) STUBBED;

NV_STATUS NV_API_CALL
os_enable_pci_req_atomics(void *, enum os_pci_req_atomics_type) STUBBED;
void NV_API_CALL os_pci_trigger_flr(void *handle) STUBBED;
NV_STATUS NV_API_CALL os_get_numa_node_memory_usage(NvS32, NvU64 *,
                                                    NvU64 *) STUBBED;
NV_STATUS NV_API_CALL os_numa_add_gpu_memory(void *, NvU64, NvU64,
                                             NvU32 *) STUBBED;
NV_STATUS NV_API_CALL os_numa_remove_gpu_memory(void *, NvU64, NvU64,
                                                NvU32) STUBBED;
NV_STATUS NV_API_CALL os_offline_page_at_address(NvU64 address) STUBBED;
void *NV_API_CALL os_get_pid_info(void) STUBBED;
void NV_API_CALL os_put_pid_info(void *pid_info) {}
NV_STATUS NV_API_CALL os_find_ns_pid(void *pid_info, NvU32 *ns_pid) STUBBED;
NvBool NV_API_CALL os_is_init_ns(void) STUBBED;

void NV_API_CALL out_string(const char *str) { printk("%s", str); }

int NV_API_CALL nv_printf(NvU32 debuglevel, const char *printf_format, ...) {
    char buf[2048];
    va_list args;
    va_start(args, printf_format);
    int ret = vsprintf(buf, printf_format, args);
    va_end(args);

    out_string(buf);

    return ret;
}

NvU32 NV_API_CALL nv_get_dev_minor(nv_state_t *) { return 0; }

typedef struct alloc_info {
    uint64_t base;
    size_t length;
} AllocInfo;

void *NV_API_CALL nv_alloc_kernel_mapping(nv_state_t *, void *pAllocPrivate,
                                          NvU64 pageIndex, NvU32 pageOffset,
                                          NvU64 size, void **pPrivate) {
    AllocInfo *info = (AllocInfo *)(pAllocPrivate);
    return (void *)(info->base + pageOffset);
}

NV_STATUS NV_API_CALL nv_free_kernel_mapping(nv_state_t *, void *pAllocPrivate,
                                             void *address, void *pPrivate) {
    AllocInfo *info = (AllocInfo *)(pAllocPrivate);
    return NV_OK;
}

NV_STATUS NV_API_CALL nv_alloc_user_mapping(nv_state_t *, void *, NvU64, NvU32,
                                            NvU64, NvU32, NvU64 *,
                                            void **) STUBBED;
NV_STATUS NV_API_CALL nv_free_user_mapping(nv_state_t *, void *, NvU64,
                                           void *) STUBBED;
NV_STATUS NV_API_CALL
nv_add_mapping_context_to_file(nv_state_t *, nv_usermap_access_params_t *,
                               NvU32, void *, NvU64, NvU32) STUBBED;

NvU64 NV_API_CALL nv_get_kern_phys_address(NvU64) STUBBED;
NvU64 NV_API_CALL nv_get_user_phys_address(NvU64) STUBBED;
nv_state_t *NV_API_CALL nv_get_adapter_state(NvU32, NvU8, NvU8) STUBBED;
nv_state_t *NV_API_CALL nv_get_ctl_state(void) STUBBED;

void NV_API_CALL nv_set_dma_address_size(nv_state_t *, NvU32 bits) {}

NV_STATUS NV_API_CALL nv_alias_pages(nv_state_t *, NvU32, NvU64, NvU32, NvU32,
                                     NvU64, NvU64 *, NvBool, void **) STUBBED;

NV_STATUS NV_API_CALL nv_alloc_pages(nv_state_t *, NvU32 page_count,
                                     NvU64 page_size, NvBool contiguous,
                                     NvU32 cache_type, NvBool zeroed,
                                     NvBool unencrypted, NvS32 node_id,
                                     NvU64 *pte_array, void **priv_data) {
    ASSERT(node_id == -1);

    void *p = alloc_frames_bytes(page_count * DEFAULT_PAGE_SIZE);
    if (!p)
        return NV_ERR_NO_MEMORY;

    uint64_t virt = (uint64_t)p;

    AllocInfo *info = malloc(sizeof(AllocInfo));
    info->base = virt;
    info->length = page_count * DEFAULT_PAGE_SIZE;

    for (size_t i = 0; i < ((contiguous) ? 1 : page_count); i++) {
        pte_array[i] =
            translate_address(get_current_page_dir(false),
                              (uintptr_t)virt + i * DEFAULT_PAGE_SIZE);
    }

    if (zeroed)
        memset((void *)virt, 0, info->length);

    *(AllocInfo **)priv_data = info;

    return NV_OK;
}

NV_STATUS NV_API_CALL nv_free_pages(nv_state_t *, NvU32 page_count,
                                    NvBool contiguous, NvU32 cache_type,
                                    void *priv_data) {
    AllocInfo *info = (AllocInfo *)(priv_data);
    (void)contiguous;
    (void)cache_type;

    if (page_count * DEFAULT_PAGE_SIZE == info->length) {
        free_frames_bytes((void *)info->base, page_count * DEFAULT_PAGE_SIZE);
        free(info);
    }

    return NV_OK;
}

NV_STATUS NV_API_CALL nv_register_user_pages(nv_state_t *, NvU64, NvU64 *,
                                             void *, void **, NvBool) STUBBED;
void NV_API_CALL nv_unregister_user_pages(nv_state_t *, NvU64, void **,
                                          void **) STUBBED;

NV_STATUS NV_API_CALL nv_register_peer_io_mem(nv_state_t *, NvU64 *, NvU64,
                                              void **) STUBBED;
void NV_API_CALL nv_unregister_peer_io_mem(nv_state_t *, void *) STUBBED;

struct sg_table;

NV_STATUS NV_API_CALL nv_register_sgt(nv_state_t *, NvU64 *, NvU64, NvU32,
                                      void **, struct sg_table *,
                                      void *) STUBBED;
void NV_API_CALL nv_unregister_sgt(nv_state_t *, struct sg_table **, void **,
                                   void *) STUBBED;
NV_STATUS NV_API_CALL nv_register_phys_pages(nv_state_t *, NvU64 *, NvU64,
                                             NvU32, void **) STUBBED;
void NV_API_CALL nv_unregister_phys_pages(nv_state_t *, void *) STUBBED;

NV_STATUS NV_API_CALL nv_dma_map_sgt(nv_dma_device_t *, NvU64, NvU64 *, NvU32,
                                     void **) STUBBED;

NV_STATUS NV_API_CALL nv_dma_map_alloc(nv_dma_device_t *, NvU64, NvU64 *,
                                       NvBool, void **) STUBBED;
NV_STATUS NV_API_CALL nv_dma_unmap_alloc(nv_dma_device_t *, NvU64, NvU64 *,
                                         void **) STUBBED;

NV_STATUS NV_API_CALL nv_dma_map_peer(nv_dma_device_t *, nv_dma_device_t *,
                                      NvU8, NvU64, NvU64 *) STUBBED;
void NV_API_CALL nv_dma_unmap_peer(nv_dma_device_t *, NvU64, NvU64) STUBBED;

NV_STATUS NV_API_CALL nv_dma_map_mmio(nv_dma_device_t *, NvU64,
                                      NvU64 *) STUBBED;
void NV_API_CALL nv_dma_unmap_mmio(nv_dma_device_t *, NvU64, NvU64) STUBBED;

void NV_API_CALL nv_dma_cache_invalidate(nv_dma_device_t *, void *) STUBBED;

NvS32 NV_API_CALL nv_start_rc_timer(nv_state_t *nv) {
    nvidia_device_t *gfx = nv->os_state;
    spin_lock(&timerLock);

    if (nv->rc_timer_enabled) {
        spin_unlock(&timerLock);
        return -1;
    }

    nv->rc_timer_enabled = 1;

    spin_unlock(&timerLock);

    return 0;
}

NvS32 NV_API_CALL nv_stop_rc_timer(nv_state_t *nv) {
    nvidia_device_t *gfx = nv->os_state;
    spin_lock(&timerLock);

    if (!nv->rc_timer_enabled) {
        spin_unlock(&timerLock);
        return -1;
    }

    nv->rc_timer_enabled = 0;

    spin_unlock(&timerLock);

    return 0;
}

void NV_API_CALL nv_post_event(nv_event_t *, NvHandle, NvU32, NvU32, NvU16,
                               NvBool) STUBBED;
NvS32 NV_API_CALL nv_get_event(nv_file_private_t *, nv_event_t *,
                               NvU32 *) STUBBED;

void *NV_API_CALL nv_i2c_add_adapter(nv_state_t *, NvU32) { return NULL; }

void NV_API_CALL nv_i2c_del_adapter(nv_state_t *, void *) {}

void NV_API_CALL nv_acpi_methods_init(NvU32 *handlePresent) {
    *handlePresent = 0;
}

void NV_API_CALL nv_acpi_methods_uninit(void) {};

NV_STATUS NV_API_CALL nv_acpi_method(NvU32, NvU32, NvU32, void *, NvU16,
                                     NvU32 *, void *, NvU16 *) {
    return NV_ERR_NOT_SUPPORTED;
}
NV_STATUS NV_API_CALL nv_acpi_d3cold_dsm_for_upstream_port(nv_state_t *, NvU8 *,
                                                           NvU32, NvU32,
                                                           NvU32 *) {
    return NV_ERR_NOT_SUPPORTED;
}

#define NV_MAX_ACPI_DSM_PARAM_SIZE 1024
NV_STATUS NV_API_CALL nv_acpi_dsm_method(
    nv_state_t *nv, NvU8 *pAcpiDsmGuid, NvU32 acpiDsmRev,
    NvBool acpiNvpcfDsmFunction, NvU32 acpiDsmSubFunction, void *pInParams,
    NvU16 inParamSize, NvU32 *outStatus, void *pOutData, NvU16 *pSize) {
    if (!nv || !pAcpiDsmGuid || !pInParams || !pOutData || !pSize ||
        inParamSize > NV_MAX_ACPI_DSM_PARAM_SIZE) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    nvidia_device_t *nv_dev = nv->os_state;
    if (!nv_dev || !nv_dev->pci_dev) {
        return NV_ERR_INVALID_ARGUMENT;
    }

    uint32_t out_size = *pSize;
    int ret = acpi_eval_dsm_for_pci(
        nv_dev->pci_dev->segment, nv_dev->pci_dev->bus, nv_dev->pci_dev->slot,
        nv_dev->pci_dev->func, pAcpiDsmGuid, acpiDsmRev, !!acpiNvpcfDsmFunction,
        acpiDsmSubFunction, pInParams, inParamSize, false, outStatus, pOutData,
        &out_size);

    if (out_size > 0xFFFFU) {
        *pSize = 0xFFFFU;
    } else {
        *pSize = (NvU16)out_size;
    }

    if (ret == 0) {
        return NV_OK;
    }

    if (ret == -ENOBUFS) {
        return NV_ERR_BUFFER_TOO_SMALL;
    }
    if (ret == -ENOMEM) {
        return NV_ERR_NO_MEMORY;
    }
    if (ret == -EINVAL) {
        return NV_ERR_INVALID_ARGUMENT;
    }
    if (ret == -ENOENT || ret == -ENOTSUP) {
        return NV_ERR_NOT_SUPPORTED;
    }

    return NV_ERR_OPERATING_SYSTEM;
}

NV_STATUS NV_API_CALL nv_acpi_ddc_method(nv_state_t *, void *, NvU32 *,
                                         NvBool) {
    return NV_ERR_NOT_SUPPORTED;
}
NV_STATUS NV_API_CALL nv_acpi_dod_method(nv_state_t *, NvU32 *, NvU32 *) {
    return NV_ERR_NOT_SUPPORTED;
}
NV_STATUS NV_API_CALL nv_acpi_rom_method(nv_state_t *, NvU32 *, NvU32 *) {
    return NV_ERR_NOT_SUPPORTED;
}
NV_STATUS NV_API_CALL nv_acpi_get_powersource(NvU32 *) {
    return NV_ERR_NOT_SUPPORTED;
}

NvBool NV_API_CALL nv_acpi_is_battery_present(void) { return false; }

NV_STATUS NV_API_CALL nv_acpi_mux_method(nv_state_t *, NvU32 *, NvU32,
                                         const char *) STUBBED;

NV_STATUS NV_API_CALL nv_log_error(nv_state_t *, NvU32, const char *,
                                   va_list) STUBBED;

NV_STATUS NV_API_CALL nv_set_primary_vga_status(nv_state_t *) { return NV_OK; };

NvBool NV_API_CALL nv_requires_dma_remap(nv_state_t *) { return NV_FALSE; }

NvBool NV_API_CALL nv_is_rm_firmware_active(nv_state_t *) STUBBED;

typedef struct nv_firmware_handle {
    void *addr;
    uint64_t size;
} nv_firmware_handle_t;

const void *NV_API_CALL
nv_get_firmware(nv_state_t *nv, nv_firmware_type_t fw_type,
                nv_firmware_chip_family_t fw_chip_family, const void **fw_buf,
                NvU32 *fw_size) {
    nvidia_device_t *gfx = nv->os_state;
    ASSERT(gfx);

    const char *path = nv_firmware_for_chip_family(fw_type, fw_chip_family);
    printk("NVIDIA_OPEN: Getting firmware %s\n", path);

    vfs_node_t node = vfs_open(path, 0);
    if (!node) {
        return NULL;
    }

    *fw_size = node->size;
    void *addr = alloc_frames_bytes(node->size);
    *fw_buf = addr;
    vfs_read(node, addr, 0, node->size);

    nv_firmware_handle_t *handle = malloc(sizeof(nv_firmware_handle_t));
    handle->addr = addr;
    handle->size = node->size;
    return (const void *)handle;
}

void NV_API_CALL nv_put_firmware(const void *handle) {
    if (!handle)
        return;

    nv_firmware_handle_t *fw_handle = (nv_firmware_handle_t *)handle;
    free_frames_bytes(fw_handle->addr, fw_handle->size);
    free((void *)fw_handle);
}

nv_file_private_t *NV_API_CALL nv_get_file_private(NvS32, NvBool,
                                                   void **) STUBBED;
void NV_API_CALL nv_put_file_private(void *) STUBBED;

NV_STATUS NV_API_CALL nv_get_device_memory_config(nv_state_t *, NvU64 *,
                                                  NvU64 *, NvU64 *, NvU32 *,
                                                  NvS32 *) {
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_get_egm_info(nv_state_t *, NvU64 *, NvU64 *,
                                      NvS32 *) STUBBED;

void NV_API_CALL nv_p2p_free_platform_data(void *data) STUBBED;

NV_STATUS NV_API_CALL nv_revoke_gpu_mappings(nv_state_t *) STUBBED;
void NV_API_CALL nv_acquire_mmap_lock(nv_state_t *) STUBBED;
void NV_API_CALL nv_release_mmap_lock(nv_state_t *) STUBBED;
NvBool NV_API_CALL nv_get_all_mappings_revoked_locked(nv_state_t *) STUBBED;
void NV_API_CALL nv_set_safe_to_mmap_locked(nv_state_t *, NvBool) STUBBED;

NV_STATUS NV_API_CALL nv_indicate_idle(nv_state_t *) STUBBED;
NV_STATUS NV_API_CALL nv_indicate_not_idle(nv_state_t *) STUBBED;
void NV_API_CALL nv_idle_holdoff(nv_state_t *) STUBBED;

NvBool NV_API_CALL nv_dynamic_power_available(nv_state_t *) STUBBED;

void NV_API_CALL nv_audio_dynamic_power(nv_state_t *) {}

void NV_API_CALL nv_control_soc_irqs(nv_state_t *, NvBool bEnable) STUBBED;
NV_STATUS NV_API_CALL nv_get_current_irq_priv_data(nv_state_t *,
                                                   NvU32 *) STUBBED;

NV_STATUS NV_API_CALL nv_acquire_fabric_mgmt_cap(int, int *) STUBBED;
int NV_API_CALL nv_cap_drv_init(void) STUBBED;
void NV_API_CALL nv_cap_drv_exit(void) STUBBED;
NvBool NV_API_CALL nv_is_gpu_accessible(nv_state_t *) STUBBED;
NvBool NV_API_CALL nv_match_gpu_os_info(nv_state_t *, void *) STUBBED;

void NV_API_CALL nv_get_updated_emu_seg(NvU32 *start, NvU32 *end) STUBBED;

void NV_API_CALL nv_get_screen_info(nv_state_t *nv, NvU64 *pPhysicalAddress,
                                    NvU32 *pFbWidth, NvU32 *pFbHeight,
                                    NvU32 *pFbDepth, NvU32 *pFbPitch,
                                    NvU64 *pFbSize) {
    *pPhysicalAddress = 0;
    *pFbWidth = 0;
    *pFbHeight = 0;
    *pFbDepth = 0;
    *pFbPitch = 0;
    *pFbSize = 0;
}

NV_STATUS NV_API_CALL nv_dma_import_sgt(nv_dma_device_t *, struct sg_table *,
                                        struct drm_gem_object *) STUBBED;
void NV_API_CALL nv_dma_release_sgt(struct sg_table *,
                                    struct drm_gem_object *) STUBBED;
NV_STATUS NV_API_CALL nv_dma_import_dma_buf(nv_dma_device_t *, struct dma_buf *,
                                            NvU32 *, struct sg_table **,
                                            nv_dma_buf_t **) STUBBED;
NV_STATUS NV_API_CALL nv_dma_import_from_fd(nv_dma_device_t *, NvS32, NvU32 *,
                                            struct sg_table **,
                                            nv_dma_buf_t **) STUBBED;
void NV_API_CALL nv_dma_release_dma_buf(nv_dma_buf_t *) STUBBED;

void NV_API_CALL nv_schedule_uvm_isr(nv_state_t *) STUBBED;

NV_STATUS NV_API_CALL nv_schedule_uvm_drain_p2p(NvU8 *) STUBBED;
void NV_API_CALL nv_schedule_uvm_resume_p2p(NvU8 *) STUBBED;

NvBool NV_API_CALL nv_platform_supports_s0ix(void) STUBBED;
NvBool NV_API_CALL nv_s2idle_pm_configured(void) STUBBED;

typedef struct nv_smbios_type3 {
    smbios_structure_header_t hdr;
    uint8_t manufacturer;
    uint8_t chassis_type;
} __attribute__((packed)) nv_smbios_type3_t;

static NvBool nv_is_mobile_chassis_type(uint8_t chassis_type) {
    switch (chassis_type) {
    case 0x08: // Portable
    case 0x09: // Laptop
    case 0x0A: // Notebook
    case 0x0E: // Sub Notebook
    case 0x1E: // Tablet
    case 0x1F: // Convertible
    case 0x20: // Detachable
        return NV_TRUE;
    default:
        return NV_FALSE;
    }
}

NvBool NV_API_CALL nv_is_chassis_notebook(void) {
    if (!smbios_available()) {
        return NV_FALSE;
    }

    for (size_t index = 0;; index++) {
        const smbios_structure_header_t *hdr = smbios_find_type(3, index);
        if (!hdr) {
            break;
        }

        if (hdr->length < sizeof(nv_smbios_type3_t)) {
            continue;
        }

        const nv_smbios_type3_t *type3 = (const nv_smbios_type3_t *)hdr;
        uint8_t chassis_type = type3->chassis_type & 0x7F;
        if (nv_is_mobile_chassis_type(chassis_type)) {
            return NV_TRUE;
        }
    }

    return NV_FALSE;
}

void NV_API_CALL nv_allow_runtime_suspend(nv_state_t *nv) STUBBED;
void NV_API_CALL nv_disallow_runtime_suspend(nv_state_t *nv) STUBBED;

NV_STATUS NV_API_CALL nv_get_num_phys_pages(void *, NvU32 *) STUBBED;
NV_STATUS NV_API_CALL nv_get_phys_pages(void *, void *, NvU32 *) STUBBED;

void NV_API_CALL nv_get_disp_smmu_stream_ids(nv_state_t *,
                                             NvU32 *dispIsoStreamId,
                                             NvU32 *dispNisoStreamId) {
    *dispIsoStreamId = UINT32_MAX;
    *dispNisoStreamId = UINT32_MAX;
}

NV_STATUS NV_API_CALL nv_clk_get_handles(nv_state_t *) STUBBED;
void NV_API_CALL nv_clk_clear_handles(nv_state_t *) STUBBED;
NV_STATUS NV_API_CALL nv_enable_clk(nv_state_t *, TEGRASOC_WHICH_CLK) STUBBED;
void NV_API_CALL nv_disable_clk(nv_state_t *, TEGRASOC_WHICH_CLK) STUBBED;
NV_STATUS NV_API_CALL nv_get_curr_freq(nv_state_t *, TEGRASOC_WHICH_CLK,
                                       NvU32 *) STUBBED;
NV_STATUS NV_API_CALL nv_get_max_freq(nv_state_t *, TEGRASOC_WHICH_CLK,
                                      NvU32 *) STUBBED;
NV_STATUS NV_API_CALL nv_get_min_freq(nv_state_t *, TEGRASOC_WHICH_CLK,
                                      NvU32 *) STUBBED;
NV_STATUS NV_API_CALL nv_set_freq(nv_state_t *, TEGRASOC_WHICH_CLK,
                                  NvU32) STUBBED;

NV_STATUS NV_API_CALL nv_check_usermap_access_params(
    nv_state_t *, const nv_usermap_access_params_t *) {
    return NV_OK;
}

nv_soc_irq_type_t NV_API_CALL nv_get_current_irq_type(nv_state_t *) STUBBED;
void NV_API_CALL nv_flush_coherent_cpu_cache_range(nv_state_t *nv,
                                                   NvU64 cpu_virtual,
                                                   NvU64 size) STUBBED;

nv_parm_t nv_parms[] = {{NULL, NULL}};

nv_cap_t *nvidia_caps_root = NULL;
NvBool os_dma_buf_enabled = NV_FALSE;
NvBool os_imex_channel_is_supported = NV_FALSE;

void NV_API_CALL nv_create_nano_timer(nv_state_t *, void *pTmrEvent,
                                      nv_nano_timer_t **) STUBBED;
void NV_API_CALL nv_start_nano_timer(nv_state_t *nv, nv_nano_timer_t *,
                                     NvU64 timens) STUBBED;
void NV_API_CALL nv_cancel_nano_timer(nv_state_t *, nv_nano_timer_t *) STUBBED;
void NV_API_CALL nv_destroy_nano_timer(nv_state_t *nv,
                                       nv_nano_timer_t *) STUBBED;

NV_STATUS nv_get_syncpoint_aperture(NvU32 syncpointId, NvU64 *physAddr,
                                    NvU64 *limit, NvU32 *offset) {
    return NV_ERR_NOT_SUPPORTED;
}

#include "nvidia_open.h"

#include <libs/klibc.h>

#include <libs/klibc.h>
#include <libs/aether/mm.h>
#include <libs/aether/stdio.h>
#include <libs/aether/task.h>
#include <libs/aether/time.h>

#include <nv.h>
#include <nv-firmware.h>
#include <os-interface.h>

#define STUBBED                                                                \
    {                                                                          \
        ASSERT(!"Unimplemented");                                              \
    }

NvU32 os_page_size = 0x1000;
NvU64 os_page_mask = ~0xFFF;
NvU8 os_page_shift = 12;
NvBool os_cc_enabled = 0;
NvBool os_cc_sev_snp_enabled = 0;
NvBool os_cc_snp_vtom_enabled = 0;
NvBool os_cc_tdx_enabled = 0;
NvBool os_cc_sme_enabled = 0;

NV_STATUS NV_API_CALL os_alloc_mem(void **address, NvU64 size) {
    if (!address)
        return NV_ERR_INVALID_ARGUMENT;

    *address = malloc(size);
    return ((*address != NULL) ? NV_OK : NV_ERR_NO_MEMORY);
}

void NV_API_CALL os_free_mem(void *ptr) { free(ptr); }

NV_STATUS NV_API_CALL os_get_current_time(NvU32 *sec, NvU32 *usec) {
    tm time;
    time_read(&time);
    *sec = mktime(&time);
    *usec = 0;
    return NV_OK;
}

NvU64 NV_API_CALL os_get_current_tick(void) { return nanoTime(); }

NvU64 NV_API_CALL os_get_current_tick_hr(void) { return nanoTime(); }

NvU64 NV_API_CALL os_get_tick_resolution(void) { return 1; }

static void delay(uint64_t ns) {
    uint64_t start = nanoTime();
    while (nanoTime() - start < ns) {
        arch_yield();
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

NvU32 NV_API_CALL os_get_current_process(void) { return 1; }

void NV_API_CALL os_get_current_process_name(char *buf, NvU32 len) {
    strncpy(buf, "NVIDIA_OPEN", len - 1);
    buf[len - 1] = '\0';
}

NV_STATUS NV_API_CALL os_get_current_thread(NvU64 *tid) {
    *tid = 0;
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

NvBool NV_API_CALL os_is_isr() { return NV_FALSE; }

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
    printk("NVIDIA_OPEN: [%d ERROR] ", current_task->pid);
    char buf[2048];
    vsprintf(buf, fmt, ap);
    printk(buf);
}

void *os_mem_copy(void *dst, const void *src, NvU32 length) {
    return memcpy(dst, src, length);
}

NV_STATUS NV_API_CALL os_memcpy_from_user(void *, const void *, NvU32) STUBBED;
NV_STATUS NV_API_CALL os_memcpy_to_user(void *, const void *, NvU32) STUBBED;

void *os_mem_set(void *dst, NvU8 c, NvU32 length) {
    return memset(dst, (int)c, length);
}

NvS32 os_mem_cmp(const NvU8 *a, const NvU8 *b, NvU32 l) {
    return memcmp(a, b, l);
}

void *NV_API_CALL os_pci_init_handle(NvU32 domain, NvU8 bus, NvU8 slot,
                                     NvU8 func, NvU16 *vendor, NvU16 *dev) {
    return NULL;
}

NV_STATUS NV_API_CALL os_pci_read_byte(void *handle, NvU32 offset,
                                       NvU8 *pReturnValue) {
    nvidia_device_t *gfx = (handle);
    ASSERT(gfx);

    *pReturnValue = (uint8_t)gfx->pci_dev->op->read(
        gfx->pci_dev->bus, gfx->pci_dev->slot, gfx->pci_dev->func,
        gfx->pci_dev->segment, offset);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_read_word(void *handle, NvU32 offset,
                                       NvU16 *pReturnValue) {
    nvidia_device_t *gfx = (handle);
    ASSERT(gfx);

    *pReturnValue = (uint16_t)gfx->pci_dev->op->read(
        gfx->pci_dev->bus, gfx->pci_dev->slot, gfx->pci_dev->func,
        gfx->pci_dev->segment, offset);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_read_dword(void *handle, NvU32 offset,
                                        NvU32 *pReturnValue) {
    nvidia_device_t *gfx = (handle);
    ASSERT(gfx);

    *pReturnValue = gfx->pci_dev->op->read(
        gfx->pci_dev->bus, gfx->pci_dev->slot, gfx->pci_dev->func,
        gfx->pci_dev->segment, offset);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_byte(void *handle, NvU32 offset,
                                        NvU8 value) {
    nvidia_device_t *gfx = (handle);
    ASSERT(gfx);

    uint32_t old = gfx->pci_dev->op->read(gfx->pci_dev->bus, gfx->pci_dev->slot,
                                          gfx->pci_dev->func,
                                          gfx->pci_dev->segment, offset);

    gfx->pci_dev->op->write(gfx->pci_dev->bus, gfx->pci_dev->slot,
                            gfx->pci_dev->func, gfx->pci_dev->segment, offset,
                            value | (old & 0xFFFFFF00));
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_word(void *handle, NvU32 offset,
                                        NvU16 value) {
    nvidia_device_t *gfx = (handle);
    ASSERT(gfx);

    uint32_t old = gfx->pci_dev->op->read(gfx->pci_dev->bus, gfx->pci_dev->slot,
                                          gfx->pci_dev->func,
                                          gfx->pci_dev->segment, offset);

    gfx->pci_dev->op->write(gfx->pci_dev->bus, gfx->pci_dev->slot,
                            gfx->pci_dev->func, gfx->pci_dev->segment, offset,
                            value | (old & 0xFFFF0000));
    return NV_OK;
}

NV_STATUS NV_API_CALL os_pci_write_dword(void *handle, NvU32 offset,
                                         NvU32 value) {
    nvidia_device_t *gfx = (handle);
    ASSERT(gfx);

    gfx->pci_dev->op->write(gfx->pci_dev->bus, gfx->pci_dev->slot,
                            gfx->pci_dev->func, gfx->pci_dev->segment, offset,
                            value);
    return NV_OK;
}

NvBool NV_API_CALL os_pci_remove_supported(void) STUBBED;
void NV_API_CALL os_pci_remove(void *) STUBBED;

void *NV_API_CALL os_map_kernel_space(NvU64 start, NvU64 size_bytes,
                                      NvU32 mode) {
    uint64_t virt = phys_to_virt(start);
    map_page_range(get_current_page_dir(false), virt, start, size_bytes,
                   PT_FLAG_R | PT_FLAG_W);
    return (void *)virt;
}

void NV_API_CALL os_unmap_kernel_space(void *ptr, NvU64 len) {
    uint64_t alignedAddr = (uintptr_t)ptr & ~0xFFF;
    uint64_t alignedSize =
        (((uintptr_t)ptr + len + 0xFFF) & ~0xFFF) - alignedAddr;
    unmap_page_range(get_current_page_dir(false), alignedAddr, alignedSize);
}

NV_STATUS NV_API_CALL os_flush_cpu_cache_all(void) {
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_flush_user_cache(void) { return NV_ERR_NOT_SUPPORTED; }

void NV_API_CALL os_flush_cpu_write_combine_buffer(void) {
    asm volatile("sfence" ::: "memory");
}

NvU8 NV_API_CALL os_io_read_byte(NvU32) STUBBED;
NvU16 NV_API_CALL os_io_read_word(NvU32) STUBBED;
NvU32 NV_API_CALL os_io_read_dword(NvU32) STUBBED;
void NV_API_CALL os_io_write_byte(NvU32, NvU8) STUBBED;
void NV_API_CALL os_io_write_word(NvU32, NvU16) STUBBED;
void NV_API_CALL os_io_write_dword(NvU32, NvU32) STUBBED;
NvBool NV_API_CALL os_is_administrator(void) STUBBED;

NvBool NV_API_CALL os_check_access(RsAccessRight) { return NV_FALSE; }

void NV_API_CALL os_dbg_init(void) {}

void NV_API_CALL os_dbg_breakpoint(void) {}

void NV_API_CALL os_dbg_set_level(NvU32) STUBBED;

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

NV_STATUS NV_API_CALL os_schedule(void) { return NV_OK; }

NV_STATUS NV_API_CALL os_alloc_spinlock(void **spinlock) {
    *spinlock = malloc(sizeof(spinlock_t));
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

NV_STATUS NV_API_CALL os_queue_work_item(struct os_work_queue *,
                                         void *) STUBBED;
NV_STATUS NV_API_CALL os_flush_work_queue(struct os_work_queue *,
                                          NvBool) STUBBED;
NvBool NV_API_CALL os_is_queue_flush_ongoing(struct os_work_queue *) STUBBED;

NV_STATUS NV_API_CALL os_alloc_mutex(void **mutex) {
    NV_STATUS status = os_alloc_mem(mutex, sizeof(spinlock_t));
    if (status != NV_OK) {
        return status;
    }

    spinlock_t *pm = (spinlock_t *)(*mutex);
    pm->lock = 0;

    return NV_OK;
}

void NV_API_CALL os_free_mutex(void *mutex) {
    if (mutex) {
        spinlock_t *pm = (spinlock_t *)(mutex);
        free(pm);
    }
}

NV_STATUS NV_API_CALL os_acquire_mutex(void *mutex) {
    ASSERT(mutex);
    spinlock_t *pm = (spinlock_t *)(mutex);

    spin_lock(pm);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_cond_acquire_mutex(void *mutex) {
    ASSERT(mutex);
    spinlock_t *pm = (spinlock_t *)(mutex);

    if (pm->lock != 0)
        return NV_ERR_TIMEOUT_RETRY;

    spin_lock(pm);
    return NV_OK;
}

void NV_API_CALL os_release_mutex(void *mutex) {
    ASSERT(mutex);
    spinlock_t *pm = (spinlock_t *)(mutex);
    spin_unlock(pm);
}

void *NV_API_CALL os_alloc_semaphore(NvU32 initial) {
    spinlock_t *s;
    NV_STATUS status = os_alloc_mem((void **)(&s), sizeof(spinlock_t));
    if (status != NV_OK) {
        return NULL;
    }

    s->lock = 0;
    return s;
}

void NV_API_CALL os_free_semaphore(void *s) {
    spinlock_t *sem = (spinlock_t *)(s);
    free(sem);
}

NV_STATUS NV_API_CALL os_acquire_semaphore(void *s) {
    spinlock_t *sem = (spinlock_t *)(s);
    ASSERT(s);
    spin_lock(sem);
    spin_unlock(sem);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_cond_acquire_semaphore(void *s) {
    spinlock_t *sem = (spinlock_t *)(s);
    ASSERT(s);
    if (sem->lock == 1) {
        return NV_ERR_TIMEOUT_RETRY;
    }

    spin_lock(sem);
    spin_unlock(sem);
}

NV_STATUS NV_API_CALL os_release_semaphore(void *s) {
    spinlock_t *sem = (spinlock_t *)(s);
    ASSERT(s);
    spin_unlock(sem);
    return NV_OK;
}

void *NV_API_CALL os_alloc_rwlock(void) {
    spinlock_t *rwlock = NULL;

    NV_STATUS status = os_alloc_mem((void **)(&rwlock), sizeof(spin_lock));
    if (status != NV_OK) {
        return NULL;
    }

    rwlock->lock = 0;

    return rwlock;
}

void NV_API_CALL os_free_rwlock(void *lock) {
    if (lock) {
        spinlock_t *rwlock = (spinlock_t *)(lock);
        free(rwlock);
    }
}

NV_STATUS NV_API_CALL os_acquire_rwlock_read(void *l) {
    spinlock_t *rwlock = (spinlock_t *)(l);

    // int ret = pthread_rwlock_rdlock(rwlock);
    // ASSERT(ret == 0);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_acquire_rwlock_write(void *l) {
    spinlock_t *rwlock = (spinlock_t *)(l);

    // int ret = pthread_rwlock_wrlock(rwlock);
    // ASSERT(ret == 0);
    return NV_OK;
}

NV_STATUS NV_API_CALL os_cond_acquire_rwlock_read(void *) STUBBED;
NV_STATUS NV_API_CALL os_cond_acquire_rwlock_write(void *) STUBBED;

void NV_API_CALL os_release_rwlock_read(void *l) {
    spinlock_t *rwlock = (spinlock_t *)(l);
}

void NV_API_CALL os_release_rwlock_write(void *l) {
    spinlock_t *rwlock = (spinlock_t *)(l);
}

NvBool NV_API_CALL os_semaphore_may_sleep(void) { return true; }

NV_STATUS NV_API_CALL os_get_version_info(os_version_info *) STUBBED;

NV_STATUS NV_API_CALL os_get_is_openrm(NvBool *bIsOpenRm) {
    *bIsOpenRm = NV_TRUE;
    return NV_OK;
}

NvBool NV_API_CALL os_pat_supported(void) { return NV_FALSE; }

void NV_API_CALL os_dump_stack(void) STUBBED;

NvBool NV_API_CALL os_is_efi_enabled(void) { return NV_FALSE; }

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
NV_STATUS NV_API_CALL os_get_euid(NvU32 *) STUBBED;
NV_STATUS NV_API_CALL os_get_smbios_header(NvU64 *pSmbsAddr) STUBBED;
NV_STATUS NV_API_CALL os_get_acpi_rsdp_from_uefi(NvU32 *) STUBBED;
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
NV_STATUS NV_API_CALL os_open_temporary_file(void **) STUBBED;
void NV_API_CALL os_close_file(void *) STUBBED;
NV_STATUS NV_API_CALL os_write_file(void *, NvU8 *, NvU64, NvU64) STUBBED;
NV_STATUS NV_API_CALL os_read_file(void *, NvU8 *, NvU64, NvU64) STUBBED;
NV_STATUS NV_API_CALL os_open_readonly_file(const char *, void **) STUBBED;
NV_STATUS NV_API_CALL os_open_and_read_file(const char *, NvU8 *,
                                            NvU64) STUBBED;

NvBool NV_API_CALL os_is_nvswitch_present(void) { return NV_FALSE; }

NV_STATUS NV_API_CALL os_get_random_bytes(NvU8 *, NvU16) STUBBED;
NV_STATUS NV_API_CALL os_alloc_wait_queue(os_wait_queue **) STUBBED;
void NV_API_CALL os_free_wait_queue(os_wait_queue *) STUBBED;
void NV_API_CALL os_wait_uninterruptible(os_wait_queue *) STUBBED;
void NV_API_CALL os_wait_interruptible(os_wait_queue *) STUBBED;
void NV_API_CALL os_wake_up(os_wait_queue *) STUBBED;
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

    size_t pages = (size + 0xFFF) / 0x1000;

    uint64_t ptr = phys_to_virt(pageIndex << 12);
    map_page_range(get_current_page_dir(false), ptr, pageIndex << 12,
                   pages << 12, PT_FLAG_R | PT_FLAG_W);

    info->base = ptr;
    *pPrivate = (void *)pages;

    return (void *)((uintptr_t)ptr + pageOffset);
}

NV_STATUS NV_API_CALL nv_free_kernel_mapping(nv_state_t *, void *pAllocPrivate,
                                             void *address, void *pPrivate) {
    AllocInfo *info = (AllocInfo *)(pAllocPrivate);
    size_t page_count = (uintptr_t)pPrivate;

    uintptr_t alignedStart = ((uintptr_t)address + 0xFFF) & ~0xFFF;
    uintptr_t alignedEnd = ((uintptr_t)address + (page_count << 12)) & ~0xFFF;

    unmap_page_range(get_current_page_dir(false), alignedStart,
                     alignedEnd - alignedStart);

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

    uint64_t virt =
        (uint64_t)alloc_frames_bytes(page_count * DEFAULT_PAGE_SIZE);

    AllocInfo *info = malloc(sizeof(AllocInfo));
    info->base = virt;
    info->length = page_count * DEFAULT_PAGE_SIZE;

    for (size_t i = 0; i < ((contiguous) ? 1 : page_count); i++) {
        pte_array[i] =
            translate_address(get_current_page_dir(false),
                              (uintptr_t)virt + i * DEFAULT_PAGE_SIZE);
    }

    *(AllocInfo **)priv_data = info;

    return NV_OK;
}

NV_STATUS NV_API_CALL nv_free_pages(nv_state_t *, NvU32 page_count,
                                    NvBool contiguous, NvU32 cache_type,
                                    void *priv_data) {
    AllocInfo *info = (AllocInfo *)(priv_data);
    (void)contiguous;
    (void)cache_type;

    free_frames_bytes((void *)info->base, page_count * DEFAULT_PAGE_SIZE);

    free(info);

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
    spin_lock(&gfx->timerLock);

    if (nv->rc_timer_enabled) {
        spin_unlock(&gfx->timerLock);
        return -1;
    }

    nv->rc_timer_enabled = 1;

    spin_unlock(&gfx->timerLock);

    return 0;
}

NvS32 NV_API_CALL nv_stop_rc_timer(nv_state_t *nv) {
    nvidia_device_t *gfx = nv->os_state;
    spin_lock(&gfx->timerLock);

    if (!nv->rc_timer_enabled) {
        spin_unlock(&gfx->timerLock);
        return -1;
    }

    nv->rc_timer_enabled = 0;

    spin_unlock(&gfx->timerLock);

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

void NV_API_CALL nv_acpi_methods_uninit(void) STUBBED;

NV_STATUS NV_API_CALL nv_acpi_method(NvU32, NvU32, NvU32, void *, NvU16,
                                     NvU32 *, void *, NvU16 *) {
    return NV_ERR_NOT_SUPPORTED;
}
NV_STATUS NV_API_CALL nv_acpi_d3cold_dsm_for_upstream_port(nv_state_t *, NvU8 *,
                                                           NvU32, NvU32,
                                                           NvU32 *) {
    return NV_ERR_NOT_SUPPORTED;
}
NV_STATUS NV_API_CALL nv_acpi_dsm_method(nv_state_t *, NvU8 *, NvU32, NvBool,
                                         NvU32, void *, NvU16, NvU32 *, void *,
                                         NvU16 *) {
    return NV_ERR_NOT_SUPPORTED;
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

    vfs_node_t node = vfs_open(path);
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
    nv_firmware_handle_t *h = (nv_firmware_handle_t *)handle;
    free_frames_bytes((void *)h->addr, h->size);
    free(h);
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

NvBool NV_API_CALL nv_is_chassis_notebook(void) {
    return NV_TRUE; // TODO: SMBIOS
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

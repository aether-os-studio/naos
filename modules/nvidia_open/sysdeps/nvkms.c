#include "nvidia_open.h"

#include <libs/klibc.h>
#include <libs/aether/stdio.h>
#include <libs/aether/task.h>

#include "nv.h"
#include "nvkms.h"
#include "nvkms-kapi-internal.h"
#include "nvidia-modeset-os-interface.h"

spinlock_t nvKmsLock = {0};
const char *const pNV_KMS_ID = "aether-os nvidia driver";

#define STUBBED                                                                \
    {                                                                          \
        ASSERT(!"unimplemented");                                              \
    }

struct nvkms_per_open {
    void *data;
    enum NvKmsClientType type;
    struct NvKmsKapiDevice *device;
};

static void delay(uint64_t ns) {
    uint64_t start = nanoTime();
    while (nanoTime() - start < ns) {
        arch_yield();
    }
}

void *nvkms_memset(void *ptr, NvU8 c, size_t size) {
    return memset(ptr, c, size);
}

void *nvkms_memcpy(void *dest, const void *src, size_t n) {
    return memcpy(dest, src, n);
}

void *nvkms_memmove(void *dest, const void *src, size_t n) {
    return memmove(dest, src, n);
}

int nvkms_memcmp(const void *s1, const void *s2, size_t n) {
    return memcmp(s1, s2, n);
}

size_t nvkms_strlen(const char *s) { return strlen(s); }

int nvkms_strcmp(const char *s1, const char *s2) { return strcmp(s1, s2); }

char *nvkms_strncpy(char *dest, const char *src, size_t n) {
    strncpy(dest, src, n);
    return dest;
}

int nvkms_snprintf(char *str, size_t size, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    int ret = vsprintf(str, format, ap);
    va_end(ap);

    return ret;
}

int nvkms_vsnprintf(char *str, size_t size, const char *format, va_list ap) {
    return vsprintf(str, format, ap);
}

void nvkms_log(const int level, const char *gpuPrefix, const char *msg) {
    const char *levelPrefix;

    switch (level) {
    case NVKMS_LOG_LEVEL_WARN:
        levelPrefix = "WARNING: ";
        break;
    case NVKMS_LOG_LEVEL_ERROR:
        levelPrefix = "ERROR: ";
        break;
    case NVKMS_LOG_LEVEL_INFO:
    default:
        levelPrefix = "";
        break;
    }

    printk("NVIDIA_OPEN [%d]: %s%s%s\n", level, levelPrefix, gpuPrefix, msg);
}

void nvkms_call_rm(void *ops) { rm_kernel_rmapi_op(NULL, ops); }

void nvkms_free(void *ptr, size_t) { free(ptr); }

void *nvkms_alloc(size_t size, NvBool zero) {
    void *ptr = malloc(size);

    if (ptr && zero)
        memset(ptr, 0, size);

    return ptr;
}

void nvkms_usleep(NvU64 usec) { delay(usec * 1000); }

NvU64 nvkms_get_usec(void) {
    tm time;
    time_read(&time);
    return mktime(&time) * 1000000;
}

int nvkms_copyin(void *kptr, NvU64 uaddr, size_t n) STUBBED;
int nvkms_copyout(NvU64 uaddr, const void *kptr, size_t n) STUBBED;

void nvkms_yield(void) {}

void nvkms_dump_stack(void) STUBBED;
NvBool nvkms_syncpt_op(enum NvKmsSyncPtOp op,
                       NvKmsSyncPtOpParams *params) STUBBED;

NvBool nvkms_test_fail_alloc_core_channel(enum FailAllocCoreChannelMethod) {
    return NV_FALSE;
}

NvBool nvkms_conceal_vrr_caps(void) { return NV_TRUE; }

NvBool nvkms_output_rounding_fix(void) { return NV_TRUE; }

NvBool nvkms_disable_hdmi_frl(void) { return NV_FALSE; }

NvBool nvkms_disable_vrr_memclk_switch(void) STUBBED;

NvBool nvkms_hdmi_deepcolor(void) { return NV_TRUE; }

NvBool nvkms_vblank_sem_control(void) { return NV_TRUE; }

NvBool nvkms_opportunistic_display_sync(void) { return NV_TRUE; }

enum NvKmsDebugForceColorSpace nvkms_debug_force_color_space(void) {
    return NVKMS_DEBUG_FORCE_COLOR_SPACE_NONE;
}

NvBool nvkms_enable_overlay_layers(void) { return NV_FALSE; }

struct nvkms_ref_ptr {
    void *pointer;
    size_t refcount;
};

struct nvkms_ref_ptr *nvkms_alloc_ref_ptr(void *ptr) {
    struct nvkms_ref_ptr *ref_ptr = malloc(sizeof(struct nvkms_ref_ptr));
    ref_ptr->pointer = ptr;
    ref_ptr->refcount = 1;
    return ref_ptr;
}

void nvkms_free_ref_ptr(struct nvkms_ref_ptr *ref_ptr) { free(ref_ptr); }

void nvkms_inc_ref(struct nvkms_ref_ptr *ref_ptr) { ref_ptr->refcount++; }

void *nvkms_dec_ref(struct nvkms_ref_ptr *ref_ptr) {
    void *ptr = ref_ptr->pointer;
    ref_ptr->refcount--;
    return ptr;
}

struct nvkmsTimer {
    nvkms_timer_proc_t *proc;
    void *dataPtr;
    NvU32 dataU32;
    uint64_t tick;
    bool isRefPtr;
    bool cancel;
};

void *handleTimer(void *arg) {
    struct nvkmsTimer *timer = (struct nvkmsTimer *)arg;

    while (nanoTime() < timer->tick) {
        arch_yield();
    }

    if (timer->cancel)
        task_exit(0);

    if (timer->isRefPtr) {
        timer->proc(nvkms_dec_ref((struct nvkms_ref_ptr *)(timer->dataPtr)),
                    timer->dataU32);
    } else {
        timer->proc(timer->dataPtr, timer->dataU32);
    }

    task_exit(0);
}

void workqueueTimerHandler(void *arg) {
    struct nvkmsTimer *timer = (struct nvkmsTimer *)arg;

    if (timer->isRefPtr) {
        timer->proc(nvkms_dec_ref((struct nvkms_ref_ptr *)(timer->dataPtr)),
                    timer->dataU32);
    } else {
        timer->proc(timer->dataPtr, timer->dataU32);
    }
}

nvkms_timer_handle_t *nvkms_alloc_timer(nvkms_timer_proc_t *proc, void *dataPtr,
                                        NvU32 dataU32, NvU64 usec) {
    struct nvkmsTimer *timer = malloc(sizeof(struct nvkmsTimer));
    memset(timer, 0, sizeof(struct nvkmsTimer));
    timer->proc = proc;
    timer->dataPtr = dataPtr;
    timer->dataU32 = dataU32;
    timer->tick = nanoTime() + usec * 1000;
    timer->isRefPtr = false;
    timer->cancel = false;

    if (usec) {
        task_create("NV_TIMER_HANDLER", (void (*)(uint64_t))handleTimer,
                    (uint64_t)timer, KTHREAD_PRIORITY);
    } else {
        workqueueTimerHandler(timer);
    }

    return (nvkms_timer_handle_t *)timer;
}

NvBool nvkms_alloc_timer_with_ref_ptr(nvkms_timer_proc_t *proc,
                                      struct nvkms_ref_ptr *ref_ptr,
                                      NvU32 dataU32, NvU64 usec) {
    nvkms_inc_ref(ref_ptr);
    struct nvkmsTimer *timer = malloc(sizeof(struct nvkmsTimer));
    memset(timer, 0, sizeof(struct nvkmsTimer));
    timer->proc = proc;
    timer->dataPtr = ref_ptr;
    timer->dataU32 = dataU32;
    timer->tick = nanoTime() + usec * 1000;
    timer->isRefPtr = false;
    timer->cancel = false;

    if (usec) {
        task_create("NV_TIMER_HANDLER", (void (*)(uint64_t))handleTimer,
                    (uint64_t)timer, KTHREAD_PRIORITY);
    } else {
        workqueueTimerHandler(timer);
    }

    return true;
}

void nvkms_free_timer(nvkms_timer_handle_t *handle) {
    struct nvkmsTimer *timer = (struct nvkmsTimer *)handle;
    if (timer)
        timer->cancel = true;
}

void nvkms_event_queue_changed(nvkms_per_open_handle_t *pOpenKernel,
                               NvBool eventsAvailable) {
    // auto popen = reinterpret_cast<nvkms_per_open *>(pOpenKernel);

    // switch (popen->type) {
    // case NVKMS_CLIENT_USER_SPACE:
    //     assert(!"unimplemented");
    // case NVKMS_CLIENT_KERNEL_SPACE: {
    //     if (eventsAvailable)
    //         workqueueAdd(workqueue_func_t(nvKmsKapiHandleEventQueueChange),
    //                      popen->device);

    //     break;
    // }
    // }
}

void *nvkms_get_per_open_data(int fd) STUBBED;

NvBool nvkms_open_gpu(NvU32 gpuId) { return NV_TRUE; }

void nvkms_close_gpu(NvU32 gpuId) STUBBED;
NvU32 nvkms_enumerate_gpus(nv_gpu_info_t *gpu_info) STUBBED;

NvBool nvkms_allow_write_combining(void) { return NV_FALSE; }

NvBool nvkms_kernel_supports_syncpts(void) { return NV_FALSE; }

NvBool nvkms_fd_is_nvidia_chardev(int fd) STUBBED;

spinlock_t pmRwLock = {0};

void nvkms_read_lock_pm_lock() { spin_lock(&pmRwLock); }

void nvkms_read_unlock_pm_lock() { spin_unlock(&pmRwLock); }

bool nvkms_read_trylock_pm_lock() { return pmRwLock.lock != 0; }

struct nvkms_per_open *nvkms_open_common(enum NvKmsClientType type,
                                         struct NvKmsKapiDevice *device,
                                         int *status) {
    struct nvkms_per_open *popen = (struct nvkms_per_open *)(nvkms_alloc(
        sizeof(struct nvkms_per_open), NV_TRUE));

    if (popen == NULL) {
        *status = -ENOMEM;
        goto failed;
    }

    popen->type = type;
    popen->device = device;

    spin_lock(&nvKmsLock);

    popen->data = nvKmsOpen(current_task->pid, type, popen);

    spin_unlock(&nvKmsLock);

    if (popen->data == NULL) {
        *status = -EPERM;
        goto failed;
    }

    *status = 0;

    return popen;

failed:
    nvkms_free(popen, sizeof(*popen));

    return NULL;
}

int nvkms_ioctl_common(struct nvkms_per_open *popen, NvU32 cmd, NvU64 address,
                       const size_t size) {
    NvBool ret = NV_FALSE;

    spin_lock(&nvKmsLock);

    if (popen->data != NULL)
        ret = nvKmsIoctl(popen->data, cmd, address, size);

    spin_unlock(&nvKmsLock);

    return ret ? 0 : -EPERM;
}

struct nvkms_per_open *nvkms_open_from_kapi(struct NvKmsKapiDevice *device) {
    int status = 0;

    nvkms_read_lock_pm_lock();
    struct nvkms_per_open *ret =
        nvkms_open_common(NVKMS_CLIENT_KERNEL_SPACE, device, &status);
    nvkms_read_unlock_pm_lock();

    return ret;
}

void nvkms_close_from_kapi(struct nvkms_per_open *popen) STUBBED;

NvBool nvkms_ioctl_from_kapi(struct nvkms_per_open *popen, NvU32 cmd,
                             void *params_address, const size_t param_size) {
    nvkms_read_lock_pm_lock();
    NvBool ret = nvkms_ioctl_common(popen, cmd, (NvU64)(NvUPtr)params_address,
                                    param_size) == 0;
    nvkms_read_unlock_pm_lock();

    return ret;
}

NvBool nvkms_ioctl_from_kapi_try_pmlock(struct nvkms_per_open *popen, NvU32 cmd,
                                        void *params_address,
                                        const size_t param_size) {
    if (nvkms_read_trylock_pm_lock())
        return NV_FALSE;

    NvBool ret = nvkms_ioctl_common(popen, cmd, (NvU64)(NvUPtr)params_address,
                                    param_size) == 0;
    nvkms_read_unlock_pm_lock();

    return ret;
}

nvkms_sema_handle_t *nvkms_sema_alloc(void) {
    spinlock_t *sem = malloc(sizeof(spinlock_t));
    sem->lock = 0;
    return (nvkms_sema_handle_t *)sem;
}

void nvkms_sema_free(nvkms_sema_handle_t *s) {
    spin_unlock((spinlock_t *)s);
    free(s);
}

void nvkms_sema_down(nvkms_sema_handle_t *s) {
    spin_lock((spinlock_t *)s);
    spin_unlock((spinlock_t *)s);
}

void nvkms_sema_up(nvkms_sema_handle_t *s) {
    spin_lock((spinlock_t *)s);
    spin_unlock((spinlock_t *)s);
}

struct nvkms_backlight_device *
nvkms_register_backlight(NvU32 gpu_id, NvU32 display_id, void *drv_priv,
                         NvU32 current_brightness) STUBBED;

void nvkms_unregister_backlight(struct nvkms_backlight_device *nvkms_bd) {}

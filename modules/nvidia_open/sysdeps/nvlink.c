#include <nvlink_os.h>
#include <libs/klibc.h>
#include <libs/aether/stdio.h>
#include <libs/aether/mm.h>

#define STUBBED                                                                \
    {                                                                          \
        ASSERT(!"unimplemented");                                              \
    }

void nvlink_assert(int expression) { ASSERT(expression); }

static void delay(uint64_t ns) {
    uint64_t start = nanoTime();
    while (nanoTime() - start < ns) {
        arch_yield();
    }
}

void nvlink_sleep(unsigned int ms) { delay(ms * 1000000); }

void *nvlink_malloc(NvLength s) { return malloc(s); }
void nvlink_free(void *ptr) { return free(ptr); }

void *nvlink_memset(void *dest, int c, NvLength len) {
    return memset(dest, c, len);
}

void *nvlink_memcpy(void *dest, const void *src, NvLength l) {
    return memcpy(dest, src, l);
}

int nvlink_memcmp(const void *a, const void *b, NvLength l) {
    return memcmp(a, b, l);
}

NvU32 nvlink_memRd32(const volatile void *address) {
    return (*(const volatile NvU32 *)(address));
}

void nvlink_memWr32(volatile void *address, NvU32 data) {
    (*(volatile NvU32 *)(address)) = data;
}

NvU64 nvlink_memRd64(const volatile void *address) {
    return (*(const volatile NvU64 *)(address));
}

void nvlink_memWr64(volatile void *address, NvU64 data) {
    (*(volatile NvU64 *)(address)) = data;
}

// String management functions
char *nvlink_strcpy(char *dest, const char *src) {
    strcpy(dest, src);
    return dest;
}

NvLength nvlink_strlen(const char *s) { return strlen(s); }

int nvlink_strcmp(const char *a, const char *b) { return strcmp(a, b); }

int nvlink_snprintf(char *buf, NvLength len, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = vsprintf(buf, fmt, args);
    va_end(args);

    return ret;
}

void nvlink_print(const char *file, int line, const char *func, int level,
                  const char *fmt, ...) {
    printk("nvidia_open [%d %s:%d (%s)]: ", level, file, line, func);

    char buf[2048];

    va_list args;
    va_start(args, fmt);
    sprintf(buf, fmt, args);
    va_end(args);

    printk(buf);
}

// Locking support functions
void *nvlink_allocLock(void) {
    spinlock_t *sem = (spinlock_t *)malloc(sizeof(spinlock_t));
    sem->lock = 0;
    return sem;
}

void nvlink_acquireLock(void *s) {
    spinlock_t *spin = s;
    spin_lock(spin);
}

NvBool nvlink_isLockOwner(void *) { return NV_TRUE; }

void nvlink_releaseLock(void *s) {
    spinlock_t *spin = s;
    spin_unlock(spin);
}

void nvlink_freeLock(void *s) {
    spin_unlock(s);
    free(s);
}

int nvlink_is_admin(void) { return NV_TRUE; }

NvU64 nvlink_get_platform_time(void) { return (NvU64)nanoTime(); }

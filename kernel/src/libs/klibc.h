#pragma once

#include "settings.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limine.h>

#include <libs/errno.h>

#include <libs/endian.h>

typedef int clockid_t;
typedef void *timer_t;

#define _IOC(a, b, c, d) (((a) << 30) | ((b) << 8) | (c) | ((d) << 16))
#define _IOC_NONE 0U
#define _IOC_WRITE 1U
#define _IOC_READ 2U

#define _IO(a, b) _IOC(_IOC_NONE, (a), (b), 0)
#define _IOW(a, b, c) _IOC(_IOC_WRITE, (a), (b), sizeof(c))
#define _IOR(a, b, c) _IOC(_IOC_READ, (a), (b), sizeof(c))
#define _IOWR(a, b, c) _IOC(_IOC_READ | _IOC_WRITE, (a), (b), sizeof(c))

#define ABS(x) ((x) > 0 ? (x) : -(x)) // 绝对值
// 最大最小值
#define MAX(x, y) ((x > y) ? (x) : (y))
#define MIN(x, y) ((x < y) ? (x) : (y))

#define PADDING_UP(a, align) (typeof(a))((((uint64_t)(a)) + ((uint64_t)(align)) - 1) & ~(((uint64_t)(align)) - 1))

// 四舍五入成整数
static inline uint64_t round(double x)
{
    return (uint64_t)(x + 0.5);
}

static inline void *memcpy(void *dest, const void *src, size_t n)
{
    uint8_t *pdest = (uint8_t *)dest;
    const uint8_t *psrc = (const uint8_t *)src;

    for (size_t i = 0; i < n; i++)
    {
        pdest[i] = psrc[i];
    }

    return dest;
}

#if defined(__x86_64__)

/**
 * Copy 16 bytes from one location to another using optimised SSE
 * instructions. The locations should not overlap.
 *
 * @param s1
 *   Pointer to the destination of the data.
 * @param s2
 *   Pointer to the source data.
 */
static inline void mov16(uint8_t *dst, const uint8_t *src)
{
    asm volatile("movdqu (%[src]), %%xmm0\n\t"
                 "movdqu %%xmm0, (%[dst])\n\t"
                 :
                 : [src] "r"(src),
                   [dst] "r"(dst)
                 : "xmm0", "memory");
}

/**
 * Copy 32 bytes from one location to another using optimised SSE
 * instructions. The locations should not overlap.
 *
 * @param s1
 *   Pointer to the destination of the data.
 * @param s2
 *   Pointer to the source data.
 */
static inline void mov32(uint8_t *dst, const uint8_t *src)
{
    asm volatile("movdqu (%[src]), %%xmm0\n\t"
                 "movdqu 16(%[src]), %%xmm1\n\t"
                 "movdqu %%xmm0, (%[dst])\n\t"
                 "movdqu %%xmm1, 16(%[dst])"
                 :
                 : [src] "r"(src),
                   [dst] "r"(dst)
                 : "xmm0", "xmm1", "memory");
}

/**
 * Copy 48 bytes from one location to another using optimised SSE
 * instructions. The locations should not overlap.
 *
 * @param s1
 *   Pointer to the destination of the data.
 * @param s2
 *   Pointer to the source data.
 */
static inline void mov48(uint8_t *dst, const uint8_t *src)
{
    asm volatile("movdqu (%[src]), %%xmm0\n\t"
                 "movdqu 16(%[src]), %%xmm1\n\t"
                 "movdqu 32(%[src]), %%xmm2\n\t"
                 "movdqu %%xmm0, (%[dst])\n\t"
                 "movdqu %%xmm1, 16(%[dst])"
                 "movdqu %%xmm2, 32(%[dst])"
                 :
                 : [src] "r"(src),
                   [dst] "r"(dst)
                 : "xmm0", "xmm1", "memory");
}

/**
 * Copy 64 bytes from one location to another using optimised SSE
 * instructions. The locations should not overlap.
 *
 * @param s1
 *   Pointer to the destination of the data.
 * @param s2
 *   Pointer to the source data.
 */
static inline void mov64(uint8_t *dst, const uint8_t *src)
{
    asm volatile("movdqu (%[src]), %%xmm0\n\t"
                 "movdqu 16(%[src]), %%xmm1\n\t"
                 "movdqu 32(%[src]), %%xmm2\n\t"
                 "movdqu 48(%[src]), %%xmm3\n\t"
                 "movdqu %%xmm0, (%[dst])\n\t"
                 "movdqu %%xmm1, 16(%[dst])\n\t"
                 "movdqu %%xmm2, 32(%[dst])\n\t"
                 "movdqu %%xmm3, 48(%[dst])"
                 :
                 : [src] "r"(src),
                   [dst] "r"(dst)
                 : "xmm0", "xmm1", "xmm2", "xmm3", "memory");
}

/**
 * Copy 128 bytes from one location to another using optimised SSE
 * instructions. The locations should not overlap.
 *
 * @param s1
 *   Pointer to the destination of the data.
 * @param s2
 *   Pointer to the source data.
 */
static inline void mov128(uint8_t *dst, const uint8_t *src)
{
    asm volatile("movdqu (%[src]), %%xmm0\n\t"
                 "movdqu 16(%[src]), %%xmm1\n\t"
                 "movdqu 32(%[src]), %%xmm2\n\t"
                 "movdqu 48(%[src]), %%xmm3\n\t"
                 "movdqu 64(%[src]), %%xmm4\n\t"
                 "movdqu 80(%[src]), %%xmm5\n\t"
                 "movdqu 96(%[src]), %%xmm6\n\t"
                 "movdqu 112(%[src]), %%xmm7\n\t"
                 "movdqu %%xmm0, (%[dst])\n\t"
                 "movdqu %%xmm1, 16(%[dst])\n\t"
                 "movdqu %%xmm2, 32(%[dst])\n\t"
                 "movdqu %%xmm3, 48(%[dst])\n\t"
                 "movdqu %%xmm4, 64(%[dst])\n\t"
                 "movdqu %%xmm5, 80(%[dst])\n\t"
                 "movdqu %%xmm6, 96(%[dst])\n\t"
                 "movdqu %%xmm7, 112(%[dst])"
                 :
                 : [src] "r"(src),
                   [dst] "r"(dst)
                 : "xmm0", "xmm1", "xmm2", "xmm3",
                   "xmm4", "xmm5", "xmm6", "xmm7", "memory");
}

/**
 * Copy 256 bytes from one location to another using optimised SSE
 * instructions. The locations should not overlap.
 *
 * @param s1
 *   Pointer to the destination of the data.
 * @param s2
 *   Pointer to the source data.
 */
static inline void mov256(uint8_t *dst, const uint8_t *src)
{
    /*
     * There are 16XMM registers, but this function does not use
     * them all so that it can still be compiled as 32bit
     * code. The performance increase was neglible if all 16
     * registers were used.
     */
    mov128(dst, src);
    mov128(dst + 128, src + 128);
}

/**
 * Copy bytes from one location to another. The locations should not overlap.
 *
 * @param s1
 *   Pointer to the destination of the data.
 * @param s2
 *   Pointer to the source data.
 * @param n
 *   Number of bytes to copy.
 * @return
 *   s1
 */
static inline void *fast_memcpy(void *s1, const void *s2, size_t n)
{
    uint8_t *dst = (uint8_t *)s1;
    const uint8_t *src = (const uint8_t *)s2;

    /* We can't copy < 16 bytes using XMM registers so do it manually. */
    if (n < 16)
    {
        if (n & 0x01)
        {
            *dst = *src;
            dst += 1;
            src += 1;
        }
        if (n & 0x02)
        {
            *(uint16_t *)dst = *(const uint16_t *)src;
            dst += 2;
            src += 2;
        }
        if (n & 0x04)
        {
            *(uint32_t *)dst = *(const uint32_t *)src;
            dst += 4;
            src += 4;
        }
        if (n & 0x08)
        {
            *(uint64_t *)dst = *(const uint64_t *)src;
        }
        return dst;
    }

    /* Special fast cases for <= 128 bytes */
    if (n <= 32)
    {
        mov16(dst, src);
        mov16(dst - 16 + n, src - 16 + n);
        return s1;
    }
    if (n <= 64)
    {
        mov32(dst, src);
        mov32(dst - 32 + n, src - 32 + n);
        return s1;
    }
    if (n <= 128)
    {
        mov64(dst, src);
        mov64(dst - 64 + n, src - 64 + n);
        return s1;
    }

    /*
     * For large copies > 128 bytes. This combination of 256, 64 and 16 byte
     * copies was found to be faster than doing 128 and 32 byte copies as
     * well.
     */
    for (; n >= 256; n -= 256, dst += 256, src += 256)
    {
        mov256(dst, src);
    }

    /*
     * We split the remaining bytes (which will be less than 256) into
     * 64byte (2^6) chunks.
     * Using incrementing integers in the case labels of a switch statement
     * enourages the compiler to use a jump table. To get incrementing
     * integers, we shift the 2 relevant bits to the LSB position to first
     * get decrementing integers, and then subtract.
     */
    switch (3 - (n >> 6))
    {
    case 0x00:
        mov64(dst, src);
        n -= 64;
        dst += 64;
        src += 64; /* fallthrough */
    case 0x01:
        mov64(dst, src);
        n -= 64;
        dst += 64;
        src += 64; /* fallthrough */
    case 0x02:
        mov64(dst, src);
        n -= 64;
        dst += 64;
        src += 64; /* fallthrough */
    default:;
    }

    /*
     * We split the remaining bytes (which will be less than 64) into
     * 16byte (2^4) chunks, using the same switch structure as above.
     */
    switch (3 - (n >> 4))
    {
    case 0x00:
        mov16(dst, src);
        n -= 16;
        dst += 16;
        src += 16; /* fallthrough */
    case 0x01:
        mov16(dst, src);
        n -= 16;
        dst += 16;
        src += 16; /* fallthrough */
    case 0x02:
        mov16(dst, src);
        n -= 16;
        dst += 16;
        src += 16; /* fallthrough */
    default:;
    }

    /* Copy any remaining bytes, without going beyond end of buffers */
    if (n != 0)
    {
        mov16(dst - 16 + n, src - 16 + n);
    }
    return s1;
}
#else
static inline void *fast_memcpy(void *s1, const void *s2, size_t n)
{
    return memcpy(s1, s2, n);
}
#endif

static inline void *memset(void *s, int c, size_t n)
{
    uint8_t *p = (uint8_t *)s;
    uint8_t val = (uint8_t)c;

    if (n >= 8)
    {
        uint64_t word = val;
        word |= word << 8;
        word |= word << 16;
        word |= word << 32;

        uint64_t *p64 = (uint64_t *)p;
        while (n >= 8)
        {
            *p64++ = word;
            n -= 8;
        }
        p = (uint8_t *)p64;
    }

    while (n--)
    {
        *p++ = val;
    }

    return s;
}

static inline void *memmove(void *dest, const void *src, size_t n)
{
    uint8_t *pdest = (uint8_t *)dest;
    const uint8_t *psrc = (const uint8_t *)src;

    if (src > dest)
    {
        for (size_t i = 0; i < n; i++)
        {
            pdest[i] = psrc[i];
        }
    }
    else if (src < dest)
    {
        for (size_t i = n; i > 0; i--)
        {
            pdest[i - 1] = psrc[i - 1];
        }
    }

    return dest;
}

static inline int memcmp(const void *s1, const void *s2, size_t n)
{
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;

    for (size_t i = 0; i < n; i++)
    {
        if (p1[i] != p2[i])
        {
            return p1[i] < p2[i] ? -1 : 1;
        }
    }

    return 0;
}

static inline void strcpy(char *dest, const char *src)
{
    if (!dest || !src)
    {
        return;
    }

    while (*src)
    {
        *dest++ = *src++;
    }
    *dest = '\0';
}

static inline void strncpy(char *dest, const char *src, int size)
{
    if (!dest || !src || !size)
    {
        return;
    }

    char *d = dest;
    const char *s = src;

    while ((size-- > 0) && (*s))
    {
        *d++ = *s++;
    }
    if (size == 0)
    {
        *(d - 1) = '\0';
    }
    else
    {
        *d = '\0';
    }
}

static inline int strlen(const char *str)
{
    if (str == (const char *)0)
    {
        return 0;
    }

    const char *c = str;

    int len = 0;
    while (*c++)
    {
        len++;
    }

    return len;
}

static inline size_t strnlen(const char *str, size_t maxlen)
{
    if (str == NULL)
    {
        return 0;
    }

    const char *p = str;
    while (maxlen-- > 0 && *p)
    {
        p++;
    }

    return (size_t)(p - str);
}

static inline int strncmp(const char *s1, const char *s2, int size)
{
    if (!s1 || !s2)
    {
        return -1;
    }

    while (*s1 && *s2 && (*s1 == *s2) && size)
    {
        s1++;
        s2++;
    }

    return !((*s1 == '\0') || (*s2 == '\0') || (*s1 == *s2));
}

static inline int strcmp(const char *str1, const char *str2)
{
    int ret = 0;
    while (!(ret = *(unsigned char *)str1 - *(unsigned char *)str2) && *str1)
    {
        str1++;
        str2++;
    }
    if (ret < 0)
    {
        return -1;
    }
    else if (ret > 0)
    {
        return 1;
    }
    return 0;
}

static inline char *strcat(char *dest, const char *src)
{
    size_t dest_len = 0;

    while (dest[dest_len] != '\0')
    {
        dest_len++;
    }

    size_t i = 0;

    while (src[i] != '\0')
    {
        dest[dest_len + i] = src[i];

        i++;
    }

    dest[dest_len + i] = '\0';

    return dest;
}

static inline const char *strstr(const char *haystack, const char *needle)
{
    if (!*needle)
        return (const char *)haystack;

    size_t needle_len = strlen(needle);
    size_t haystack_len = strlen(haystack);

    for (size_t i = 0; i + needle_len <= haystack_len; i++)
    {
        if (haystack[i] != *needle)
            continue;

        size_t j;
        for (j = 0; j < needle_len; j++)
        {
            if (haystack[i + j] != needle[j])
                break;
        }

        if (j == needle_len)
            return (const char *)(haystack + i);
    }

    return NULL;
}

char *strdup(const char *s);

#if defined(__x86_64__)

typedef struct
{
    volatile uint32_t lock;
    uint64_t rflags;
} spinlock_t;

static inline void spin_lock(spinlock_t *lock)
{
    asm volatile(
        "1: lock btsl $0, %0\n" // 测试并设置
        "   jc 1b\n"            // 如果已锁定则重试s
        : "+m"(lock->lock)
        :
        : "memory", "cc");
}

static inline void spin_unlock(spinlock_t *lock)
{
    asm volatile(
        "lock btrl $0, %0\n" // 清除锁标志
        : "+m"(lock->lock)
        :
        : "memory", "cc");
}

static inline void spin_lock_irqsave(spinlock_t *lock)
{
    uint64_t flags;
    asm volatile(
        "pushfq\n\t" // 保存RFLAGS
        "pop %0\n\t" // 存储到flags变量
        "cli\n\t"    // 禁用中断
        : "=r"(flags)
        :
        : "memory");

    asm volatile(
        "1: lock btsl $0, %0\n\t" // 测试并设置
        "   jc 1b\n\t"            // 如果已锁定则重试
        : "+m"(lock->lock)
        :
        : "memory", "cc");

    lock->rflags = flags; // 保存原始中断状态
}

static inline void spin_unlock_irqrestore(spinlock_t *lock)
{
    asm volatile(
        "lock btrl $0, %0\n\t" // 清除锁标志
        : "+m"(lock->lock)
        :
        : "memory", "cc");

    uint64_t flags = lock->rflags;
    asm volatile(
        "push %0\n\t" // 恢复原始RFLAGS
        "popfq"
        :
        : "r"(flags)
        : "memory");
}

#elif defined(__aarch64__)

typedef struct
{
    volatile uint32_t lock;
    uint64_t daif;
} spinlock_t;

static inline void spin_lock(spinlock_t *lock)
{
    uint32_t tmp;
    asm volatile(
        "1: ldaxr %w0, [%1]\n"     // 加载独占
        "   cbnz %w0, 1b\n"        // 检查是否已锁定
        "   mov %w0, #1\n"         // 准备锁定值
        "   stxr %w0, %w0, [%1]\n" // 尝试存储
        "   cbnz %w0, 1b\n"        // 检查是否成功
        : "=&r"(tmp)
        : "r"(&lock->lock)
        : "memory");
}

static inline void spin_unlock(spinlock_t *lock)
{
    asm volatile(
        "stlr wzr, [%0]\n" // 释放锁
        :
        : "r"(&lock->lock)
        : "memory");
}

static inline void spin_lock_irqsave(spinlock_t *lock)
{
    uint32_t tmp, daif;

    // 保存并禁用中断
    asm volatile(
        "mrs %0, daif\n\t"
        "msr daifset, #2\n\t"
        : "=r"(daif)
        :
        : "memory");

    // 获取锁
    asm volatile(
        "1: ldaxr %w0, [%1]\n\t"
        "   cbnz %w0, 1b\n\t"
        "   mov %w0, #1\n\t"
        "   stxr %w0, %w0, [%1]\n\t"
        "   cbnz %w0, 1b\n\t"
        : "=&r"(tmp)
        : "r"(&lock->lock)
        : "memory");

    lock->daif = daif; // 保存原始DAIF状态
}

static inline void spin_unlock_irqrestore(spinlock_t *lock)
{
    uint32_t daif = lock->daif;

    // 释放锁
    asm volatile(
        "stlr wzr, [%0]\n\t"
        :
        : "r"(&lock->lock)
        : "memory");

    // 恢复中断状态
    asm volatile(
        "msr daif, %0\n\t"
        :
        : "r"(daif)
        : "memory");
}

#endif

typedef struct semaphore
{
    spinlock_t lock;
    uint32_t cnt;
    uint8_t invalid;
} semaphore_t;

extern uint64_t nanoTime();

static inline bool semaphore_wait(semaphore_t *sem, uint32_t timeout)
{
    uint64_t timerStart = nanoTime();
    bool ret = false;

    while (true)
    {
        if (timeout > 0 && nanoTime() > (timerStart + timeout * 1000))
            goto just_return;
        if (sem->cnt > 0)
        {
            sem->cnt--;
            ret = true;
            goto cleanup;
        }
    }

cleanup:
    spin_unlock(&sem->lock);
just_return:
    return ret;
}

static inline void semaphore_post(semaphore_t *sem)
{
    spin_lock(&sem->lock);
    sem->cnt++;
    spin_unlock(&sem->lock);
}

extern uint64_t get_physical_memory_offset();

static inline bool check_user_overflow(uint64_t addr, uint64_t size)
{
    if ((addr + size) > get_physical_memory_offset())
    {
        return true;
    }
    return false;
}

static inline void qsort_swap(void *a, void *b, size_t size)
{
    char tmp[size];
    memcpy(tmp, a, size);
    memcpy(a, b, size);
    memcpy(b, tmp, size);
}

static inline void *qsort_partition(void *base, size_t size, void *low, void *high, int (*cmp)(const void *, const void *))
{
    void *pivot = high;
    void *i = low - size;
    for (void *j = low; j != high; j += size)
    {
        if (cmp(j, pivot) <= 0)
        {
            i += size;
            qsort_swap(i, j, size);
        }
    }
    qsort_swap(i + size, high, size);
    return (i + size);
}

static inline void qsort_quicksort(void *base, size_t size, void *low, void *high, int (*cmp)(const void *, const void *))
{
    if (low < high)
    {
        void *pi = qsort_partition(base, size, low, high, cmp);
        qsort_quicksort(base, size, low, pi - size, cmp);
        qsort_quicksort(base, size, pi + size, high, cmp);
    }
}

static inline void qsort(void *base, size_t nitems, size_t size, int (*cmp)(const void *, const void *))
{
    qsort_quicksort(base, size, base, (char *)base + size * (nitems - 1), cmp);
}

static inline int qsort_compare(const void *a, const void *b)
{
    return (*(int *)a - *(int *)b);
}
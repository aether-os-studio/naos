#pragma once

#include "settings.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limine.h>

#include <libs/errno.h>

#include <libs/endian.h>

typedef long ssize_t;
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

#define wait_until(cond) \
    ({                   \
        while (!(cond))  \
            ;            \
    })

#define wait_until_expire(cond, max)          \
    ({                                        \
        uint64_t __wcounter__ = (max);        \
        while (!(cond) && __wcounter__-- > 1) \
            ;                                 \
        __wcounter__;                         \
    })

#define ABS(x) ((x) > 0 ? (x) : -(x)) // 绝对值
// 最大最小值
#define MAX(x, y) ((x > y) ? (x) : (y))
#define MIN(x, y) ((x < y) ? (x) : (y))

#define PADDING_DOWN(size, to) ((size_t)(size) / (size_t)(to) * (size_t)(to))
#define PADDING_UP(size, to) PADDING_DOWN((size_t)(size) + (size_t)(to) - (size_t)1, to)

#define container_of(ptr, type, member) ({                      \
        uint64_t __mptr = ((uint64_t)(ptr));    \
        (type *)( (char *)__mptr - offsetof(type,member) ); })
#define container_of_or_null(ptr, type, member) ({                      \
        uint64_t __mptr = ((uint64_t)(ptr));    \
        (type *)( (char *)__mptr - offsetof(type,member) ) : NULL; })

// 四舍五入成整数
static inline uint64_t round(double x)
{
    return (uint64_t)(x + 0.5);
}

extern void *memcpy(void *s1, void *s2, size_t n);

static inline void *fast_memcpy(void *s1, const void *s2, size_t n)
{
    return __builtin_memcpy(s1, s2, n);
}

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
        size--;
    }

    return !((*s1 == '\0') || (*s2 == '\0') || size == 0 || *s1 == *s2);
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

static inline char *strrchr(const char *s, int c)
{
    const char *last = NULL;
    if (!s)
        return NULL;

    do
    {
        if (*s == (char)c)
            last = s;
    } while (*s++);

    return (char *)last;
}

char *strdup(const char *s);

#if defined(__x86_64__)

typedef struct spinlock
{
    volatile long lock;
    long rflags;
} spinlock_t;

static inline void spin_lock(spinlock_t *lock)
{
    long flags;
    asm volatile(
        "pushfq\n\t" // 保存RFLAGS
        "pop %0\n\t" // 存储到flags变量
        "cli\n\t"    // 禁用中断
        : "=r"(flags)
        :
        : "memory");

    asm volatile(
        "1:\n\t"
        "lock btsq $0, %0\n\t" // 测试并设置
        "   jc 1b\n\t"         // 如果已锁定则重试
        : "+m"(lock->lock)
        :
        : "memory", "cc");

    asm volatile("mfence" ::: "memory");

    lock->rflags = flags; // 保存原始中断状态
}

static inline void spin_unlock(spinlock_t *lock)
{
    asm volatile(
        "lock btrq $0, %0\n\t" // 清除锁标志
        : "+m"(lock->lock)
        :
        : "memory", "cc");

    long flags = lock->rflags;
    asm volatile(
        "push %0\n\t" // 恢复原始RFLAGS
        "popfq"
        :
        : "r"(flags)
        : "memory");

    asm volatile("sfence" ::: "memory");
}

#elif defined(__aarch64__)

typedef struct spinlock
{
    volatile long lock;
    long daif;
} spinlock_t;

static inline void spin_lock(spinlock_t *lock)
{
    long tmp, daif;

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

static inline void spin_unlock(spinlock_t *lock)
{
    long daif = lock->daif;

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

#elif defined(__loongarch64)

typedef struct spinlock
{
    volatile long lock;
    uint64_t crmd;
} spinlock_t;

static inline void spin_lock(spinlock_t *lock)
{
    uint32_t tmp;

    uint64_t __crmd;
    __asm__ __volatile__(
        "csrrd %0, 0x1\n\t"
        : "=r"(__crmd));
    lock->crmd = __crmd;
    __crmd &= ~0x4UL;
    __asm__ __volatile__(
        "csrwr %0, 0x1"
        : : "r"(__crmd));

    /* 自旋等待 */
    while (__sync_lock_test_and_set(&lock->lock, 1))
    {
        while (lock->lock)
            ;
    }
}

static inline void spin_unlock(spinlock_t *lock)
{
    __sync_lock_release(&lock->lock);
    __asm__ __volatile__(
        "csrwr %0, 0x1"
        : : "r"(lock->crmd));
}

#endif

extern uint64_t nanoTime();

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

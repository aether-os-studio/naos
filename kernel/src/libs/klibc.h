#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limine.h>

typedef int8_t NA_int8;
typedef int16_t NA_int16;
typedef int32_t NA_int32;
typedef int64_t NA_int64;

typedef uint8_t NA_uint8;
typedef uint16_t NA_uint16;
typedef uint32_t NA_uint32;
typedef uint64_t NA_uint64;

#define ABS(x) ((x) > 0 ? (x) : -(x)) // 绝对值
// 最大最小值
#define max(x, y) ((x > y) ? (x) : (y))
#define min(x, y) ((x < y) ? (x) : (y))

// 四舍五入成整数
static inline uint64_t NA_round(double x)
{
    return (uint64_t)(x + 0.5);
}

static inline void *NA_memcpy(void *dest, const void *src, size_t n)
{
    uint8_t *pdest = (uint8_t *)dest;
    const uint8_t *psrc = (const uint8_t *)src;

    for (size_t i = 0; i < n; i++)
    {
        pdest[i] = psrc[i];
    }

    return dest;
}

static inline void *NA_memset(void *s, int c, size_t n)
{
    uint8_t *p = (uint8_t *)s;

    for (size_t i = 0; i < n; i++)
    {
        p[i] = (uint8_t)c;
    }

    return s;
}

static inline void *NA_memmove(void *dest, const void *src, size_t n)
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

static inline int NA_memcmp(const void *s1, const void *s2, size_t n)
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

static inline void NA_strcpy(char *dest, const char *src)
{
    if (!dest || !src)
    {
        return;
    }

    while (*dest && *src)
    {
        *dest++ = *src++;
    }
    *dest = '\0';
}

static inline void NA_strncpy(char *dest, const char *src, int size)
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

static inline int NA_strlen(const char *str)
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

/**
 * 比较两个字符串，最多比较size个字符
 * 如果某一字符串提前比较完成，也算相同
 */
static inline int NA_strncmp(const char *s1, const char *s2, int size)
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

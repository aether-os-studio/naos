#pragma once

#include "settings.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limine.h>

#include <libs/errno.h>

typedef int64_t err_t;

#define ABS(x) ((x) > 0 ? (x) : -(x)) // 绝对值
// 最大最小值
#define MAX(x, y) ((x > y) ? (x) : (y))
#define MIN(x, y) ((x < y) ? (x) : (y))

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

static inline void *memset(void *s, int c, size_t n)
{
    uint8_t *p = (uint8_t *)s;

    for (size_t i = 0; i < n; i++)
    {
        p[i] = (uint8_t)c;
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

/**
 * 比较两个字符串，最多比较size个字符
 * 如果某一字符串提前比较完成，也算相同
 */
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

extern void *malloc(size_t size);

static inline char *strdup(const char *s)
{
    size_t len = strlen((char *)s);
    char *ptr = (char *)malloc(len + 1);
    if (ptr == NULL)
        return NULL;
    memcpy(ptr, (void *)s, len + 1);
    return ptr;
}

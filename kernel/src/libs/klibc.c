#include <libs/klibc.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>

void *memcpy(void *restrict dest, const void *restrict src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;

#define LS >>
#define RS <<

    typedef uint32_t __attribute__((__may_alias__)) u32;
    uint32_t w, x;

    for (; (uintptr_t)s % 4 && n; n--)
        *d++ = *s++;

    if ((uintptr_t)d % 4 == 0) {
        for (; n >= 16; s += 16, d += 16, n -= 16) {
            *(u32 *)(d + 0) = *(u32 *)(s + 0);
            *(u32 *)(d + 4) = *(u32 *)(s + 4);
            *(u32 *)(d + 8) = *(u32 *)(s + 8);
            *(u32 *)(d + 12) = *(u32 *)(s + 12);
        }
        if (n & 8) {
            *(u32 *)(d + 0) = *(u32 *)(s + 0);
            *(u32 *)(d + 4) = *(u32 *)(s + 4);
            d += 8;
            s += 8;
        }
        if (n & 4) {
            *(u32 *)(d + 0) = *(u32 *)(s + 0);
            d += 4;
            s += 4;
        }
        if (n & 2) {
            *d++ = *s++;
            *d++ = *s++;
        }
        if (n & 1) {
            *d = *s;
        }
        return dest;
    }

    if (n >= 32)
        switch ((uintptr_t)d % 4) {
        case 1:
            w = *(u32 *)s;
            *d++ = *s++;
            *d++ = *s++;
            *d++ = *s++;
            n -= 3;
            for (; n >= 17; s += 16, d += 16, n -= 16) {
                x = *(u32 *)(s + 1);
                *(u32 *)(d + 0) = (w LS 24) | (x RS 8);
                w = *(u32 *)(s + 5);
                *(u32 *)(d + 4) = (x LS 24) | (w RS 8);
                x = *(u32 *)(s + 9);
                *(u32 *)(d + 8) = (w LS 24) | (x RS 8);
                w = *(u32 *)(s + 13);
                *(u32 *)(d + 12) = (x LS 24) | (w RS 8);
            }
            break;
        case 2:
            w = *(u32 *)s;
            *d++ = *s++;
            *d++ = *s++;
            n -= 2;
            for (; n >= 18; s += 16, d += 16, n -= 16) {
                x = *(u32 *)(s + 2);
                *(u32 *)(d + 0) = (w LS 16) | (x RS 16);
                w = *(u32 *)(s + 6);
                *(u32 *)(d + 4) = (x LS 16) | (w RS 16);
                x = *(u32 *)(s + 10);
                *(u32 *)(d + 8) = (w LS 16) | (x RS 16);
                w = *(u32 *)(s + 14);
                *(u32 *)(d + 12) = (x LS 16) | (w RS 16);
            }
            break;
        case 3:
            w = *(u32 *)s;
            *d++ = *s++;
            n -= 1;
            for (; n >= 19; s += 16, d += 16, n -= 16) {
                x = *(u32 *)(s + 3);
                *(u32 *)(d + 0) = (w LS 8) | (x RS 24);
                w = *(u32 *)(s + 7);
                *(u32 *)(d + 4) = (x LS 8) | (w RS 24);
                x = *(u32 *)(s + 11);
                *(u32 *)(d + 8) = (w LS 8) | (x RS 24);
                w = *(u32 *)(s + 15);
                *(u32 *)(d + 12) = (x LS 8) | (w RS 24);
            }
            break;
        }
    if (n & 16) {
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
    }
    if (n & 8) {
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
    }
    if (n & 4) {
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
    }
    if (n & 2) {
        *d++ = *s++;
        *d++ = *s++;
    }
    if (n & 1) {
        *d = *s;
    }
    return dest;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    uint8_t val = (uint8_t)c;

    while (n > 0 && ((uintptr_t)p & 7)) {
        *p++ = val;
        n--;
    }

    if (n >= 8) {
        uint64_t word = val;
        word |= word << 8;
        word |= word << 16;
        word |= word << 32;

        uint64_t *p64 = (uint64_t *)p;
        while (n >= 8) {
            *p64++ = word;
            n -= 8;
        }
        p = (uint8_t *)p64;
    }

    while (n--) {
        *p++ = val;
    }

    return s;
}

void *memmove(void *dest, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    // 特殊情况处理
    if (d == s || n == 0) {
        return dest;
    }

    if (d < s) {
        // 前向复制：dest在src前面，从前往后复制

        // 小块数据直接逐字节复制
        if (n < 16) {
            while (n--) {
                *d++ = *s++;
            }
            return dest;
        }

        // 对齐优化：先处理未对齐的前导字节
        size_t align = (uintptr_t)d & (sizeof(size_t) - 1);
        if (align) {
            align = sizeof(size_t) - align;
            n -= align;
            while (align--) {
                *d++ = *s++;
            }
        }

        // 按字（word）复制 - 提升效率
        while (n >= sizeof(size_t) * 4) {
            ((size_t *)d)[0] = ((const size_t *)s)[0];
            ((size_t *)d)[1] = ((const size_t *)s)[1];
            ((size_t *)d)[2] = ((const size_t *)s)[2];
            ((size_t *)d)[3] = ((const size_t *)s)[3];
            d += sizeof(size_t) * 4;
            s += sizeof(size_t) * 4;
            n -= sizeof(size_t) * 4;
        }

        while (n >= sizeof(size_t)) {
            *(size_t *)d = *(const size_t *)s;
            d += sizeof(size_t);
            s += sizeof(size_t);
            n -= sizeof(size_t);
        }

        // 复制剩余字节
        while (n--) {
            *d++ = *s++;
        }
    } else {
        // 后向复制：dest在src后面，从后往前复制（处理重叠）
        d += n;
        s += n;

        // 小块数据直接逐字节复制
        if (n < 16) {
            while (n--) {
                *--d = *--s;
            }
            return dest;
        }

        // 对齐优化：先处理未对齐的后导字节
        size_t align = (uintptr_t)d & (sizeof(size_t) - 1);
        if (align) {
            n -= align;
            while (align--) {
                *--d = *--s;
            }
        }

        // 按字（word）复制
        while (n >= sizeof(size_t) * 4) {
            d -= sizeof(size_t) * 4;
            s -= sizeof(size_t) * 4;
            ((size_t *)d)[3] = ((const size_t *)s)[3];
            ((size_t *)d)[2] = ((const size_t *)s)[2];
            ((size_t *)d)[1] = ((const size_t *)s)[1];
            ((size_t *)d)[0] = ((const size_t *)s)[0];
            n -= sizeof(size_t) * 4;
        }

        while (n >= sizeof(size_t)) {
            d -= sizeof(size_t);
            s -= sizeof(size_t);
            *(size_t *)d = *(const size_t *)s;
            n -= sizeof(size_t);
        }

        // 复制剩余字节
        while (n--) {
            *--d = *--s;
        }
    }

    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;

    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] < p2[i] ? -1 : 1;
        }
    }

    return 0;
}

#ifdef ALIGN
#undef ALIGN
#endif

#define ONES ((size_t)-1 / UCHAR_MAX)
#define HIGHS (ONES * (UCHAR_MAX / 2 + 1))
#define HASZERO(x) ((x) - ONES & ~(x) & HIGHS)

void *memchr(const void *src, int c, size_t n) {
    const unsigned char *s = src;
    c = (unsigned char)c;
    for (; ((uintptr_t)s & sizeof(size_t)) && n && *s != c; s++, n--)
        ;
    if (n && *s != c) {
        size_t *w = 0;
        size_t k = ONES * c;
        for (w = (void *)s; n >= sizeof(size_t) && !HASZERO(*w ^ k);
             w++, n -= sizeof(size_t))
            ;
        for (s = (const void *)w; n && *s != c; s++, n--)
            ;
    }
    return n ? (void *)s : 0;
}

#define TOLOWER(x) ((x) | 0x20)
#define isxdigit(c)                                                            \
    (('0' <= (c) && (c) <= '9') || ('a' <= (c) && (c) <= 'f') ||               \
     ('A' <= (c) && (c) <= 'F'))
#define isdigit(c) (('0' <= (c) && (c) <= '9'))

uint64_t strtoul(const char *restrict cp, char **restrict endp, int base) {
    uint64_t result = 0, value;

    if (!base) {
        base = 10;
        if (*cp == '0') {
            base = 8;
            cp++;
            if ((TOLOWER(*cp) == 'x') && isxdigit(cp[1])) {
                cp++;
                base = 16;
            }
        }
    } else if (base == 16) {
        if (cp[0] == '0' && TOLOWER(cp[1]) == 'x')
            cp += 2;
    }
    while (isxdigit(*cp) &&
           (value = isdigit(*cp) ? *cp - '0' : TOLOWER(*cp) - 'a' + 10) <
               base) {
        result = result * base + value;
        cp++;
    }
    if (endp)
        *endp = (char *)cp;
    return result;
}

void panic(const char *file, int line, const char *func, const char *cond) {
    printk("assert failed! %s\n", cond);
    printk("file: %s\nline %d\nfunc: %s\n", file, line, func);

    while (1) {
        arch_pause();
    }
}

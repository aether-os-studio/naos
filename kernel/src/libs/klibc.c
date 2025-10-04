#include <libs/klibc.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>

void *memcpy(void *dest, const void *src, size_t n) {
    if (n == 0 || dest == src)
        return dest;

    uint64_t *d64 = (uint64_t *)dest;
    const uint64_t *s64 = (const uint64_t *)src;
    size_t num_quads = n / 8;
    size_t remainder = n % 8;

    for (size_t i = 0; i < num_quads; i++) {
        d64[i] = s64[i];
    }

    if (remainder > 0) {
        uint8_t *d8 = (uint8_t *)(d64 + num_quads);
        const uint8_t *s8 = (const uint8_t *)(s64 + num_quads);
        for (size_t i = 0; i < remainder; i++) {
            d8[i] = s8[i];
        }
    }

    return dest;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    uint8_t val = (uint8_t)c;

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

void panic(const char *file, int line, const char *func, const char *cond) {
    printk("assert failed! %s\n", cond);
    printk("file: %s\nline %d\nfunc: %s\n", file, line, func);

    while (1) {
        arch_pause();
    }
}

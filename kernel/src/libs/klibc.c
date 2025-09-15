#include <libs/klibc.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>

void *memcpy(void *dest, const void *src, size_t n)
{
    if (n == 0 || dest == src)
        return dest;

    uint64_t *d64 = (uint64_t *)dest;
    const uint64_t *s64 = (const uint64_t *)src;
    size_t num_quads = n / 8;
    size_t remainder = n % 8;

    for (size_t i = 0; i < num_quads; i++)
    {
        d64[i] = s64[i];
    }

    if (remainder > 0)
    {
        uint8_t *d8 = (uint8_t *)(d64 + num_quads);
        const uint8_t *s8 = (const uint8_t *)(s64 + num_quads);
        for (size_t i = 0; i < remainder; i++)
        {
            d8[i] = s8[i];
        }
    }

    return dest;
}

void *memset(void *s, int c, size_t n)
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

void panic(const char *file, int line, const char *func, const char *cond)
{
    printk("assert failed! %s", cond);
    printk("file: %s\nline %d\nfunc: %s\n", file, line, func);

    arch_make_trap();
}

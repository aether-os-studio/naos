#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

// strcmp
int strcmp(const char *s1, const char *s2)
{
    while (*s1 == *s2)
    {
        if (*s1 == '\0')
            return 0;
        s1++;
        s2++;
    }
    return *s1 - *s2;
}
char *strdup(const char *s)
{
    size_t l = strlen(s);
    char *d = malloc(l + 1);
    if (!d)
        return NULL;
    return memcpy(d, s, l + 1);
}
// strcpy
char *strcpy(char *dest, const char *src)
{
    char *tmp = dest;
    while ((*dest++ = *src++) != '\0')
        ;
    return tmp;
}
// strncpy
char *strncpy(char *dest, const char *src, size_t n)
{
    char *tmp = dest;
    while (n-- > 0 && (*dest++ = *src++) != '\0')
        ;
    return tmp;
}

// memset
void *memset(void *dest, int c, size_t n)
{
    unsigned char *s = dest;
    size_t k;

    /* Fill head and tail with minimal branching. Each
     * conditional ensures that all the subsequently used
     * offsets are well-defined and in the dest region. */

    if (!n)
        return dest;
    s[0] = c;
    s[n - 1] = c;
    if (n <= 2)
        return dest;
    s[1] = c;
    s[2] = c;
    s[n - 2] = c;
    s[n - 3] = c;
    if (n <= 6)
        return dest;
    s[3] = c;
    s[n - 4] = c;
    if (n <= 8)
        return dest;

    /* Advance pointer to align it at a 4-byte boundary,
     * and truncate n to a multiple of 4. The previous code
     * already took care of any head/tail that get cut off
     * by the alignment. */

    k = -(uintptr_t)s & 3;
    s += k;
    n -= k;
    n &= -4;

#ifdef __GNUC__
    typedef uint32_t __attribute__((__may_alias__)) u32;
    typedef uint64_t __attribute__((__may_alias__)) u64;

    uint32_t c32 = ((u32)-1) / 255 * (unsigned char)c;

    /* In preparation to copy 32 bytes at a time, aligned on
     * an 8-byte bounary, fill head/tail up to 28 bytes each.
     * As in the initial byte-based head/tail fill, each
     * conditional below ensures that the subsequent offsets
     * are valid (e.g. !(n<=24) implies n>=28). */

    *(uint32_t *)(s + 0) = c32;
    *(uint32_t *)(s + n - 4) = c32;
    if (n <= 8)
        return dest;
    *(uint32_t *)(s + 4) = c32;
    *(uint32_t *)(s + 8) = c32;
    *(uint32_t *)(s + n - 12) = c32;
    *(uint32_t *)(s + n - 8) = c32;
    if (n <= 24)
        return dest;
    *(uint32_t *)(s + 12) = c32;
    *(uint32_t *)(s + 16) = c32;
    *(uint32_t *)(s + 20) = c32;
    *(uint32_t *)(s + 24) = c32;
    *(uint32_t *)(s + n - 28) = c32;
    *(uint32_t *)(s + n - 24) = c32;
    *(uint32_t *)(s + n - 20) = c32;
    *(uint32_t *)(s + n - 16) = c32;

    /* Align to a multiple of 8 so we can fill 64 bits at a time,
     * and avoid writing the same bytes twice as much as is
     * practical without introducing additional branching. */

    k = 24 + ((uintptr_t)s & 4);
    s += k;
    n -= k;

    /* If this loop is reached, 28 tail bytes have already been
     * filled, so any remainder when n drops below 32 can be
     * safely ignored. */

    u64 c64 = c32 | ((u64)c32 << 32);
    for (; n >= 32; n -= 32, s += 32)
    {
        *(u64 *)(s + 0) = c64;
        *(u64 *)(s + 8) = c64;
        *(u64 *)(s + 16) = c64;
        *(u64 *)(s + 24) = c64;
    }
#else
    /* Pure C fallback with no aliasing violations. */
    for (; n; n--, s++)
        *s = c;
#endif

    return dest;
}
// memcmp
int memcmp(const void *vl, const void *vr, size_t n)
{
    const unsigned char *l = vl, *r = vr;
    for (; n && *l == *r; n--, l++, r++)
        ;
    return n ? *l - *r : 0;
}
// memcpy
void *memcpy(void *dest, const void *src, size_t n)
{
    unsigned char *d = dest;
    const unsigned char *s = src;

#ifdef __GNUC__

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define LS >>
#define RS <<
#else
#define LS <<
#define RS >>
#endif

    typedef uint32_t __attribute__((__may_alias__)) u32;
    uint32_t w, x;

    for (; (uintptr_t)s % 4 && n; n--)
        *d++ = *s++;

    if ((uintptr_t)d % 4 == 0)
    {
        for (; n >= 16; s += 16, d += 16, n -= 16)
        {
            *(uint32_t *)(d + 0) = *(uint32_t *)(s + 0);
            *(uint32_t *)(d + 4) = *(uint32_t *)(s + 4);
            *(uint32_t *)(d + 8) = *(uint32_t *)(s + 8);
            *(uint32_t *)(d + 12) = *(uint32_t *)(s + 12);
        }
        if (n & 8)
        {
            *(uint32_t *)(d + 0) = *(uint32_t *)(s + 0);
            *(uint32_t *)(d + 4) = *(uint32_t *)(s + 4);
            d += 8;
            s += 8;
        }
        if (n & 4)
        {
            *(uint32_t *)(d + 0) = *(uint32_t *)(s + 0);
            d += 4;
            s += 4;
        }
        if (n & 2)
        {
            *d++ = *s++;
            *d++ = *s++;
        }
        if (n & 1)
        {
            *d = *s;
        }
        return dest;
    }

    if (n >= 32)
        switch ((uintptr_t)d % 4)
        {
        case 1:
            w = *(uint32_t *)s;
            *d++ = *s++;
            *d++ = *s++;
            *d++ = *s++;
            n -= 3;
            for (; n >= 17; s += 16, d += 16, n -= 16)
            {
                x = *(uint32_t *)(s + 1);
                *(uint32_t *)(d + 0) = (w LS 24) | (x RS 8);
                w = *(uint32_t *)(s + 5);
                *(uint32_t *)(d + 4) = (x LS 24) | (w RS 8);
                x = *(uint32_t *)(s + 9);
                *(uint32_t *)(d + 8) = (w LS 24) | (x RS 8);
                w = *(uint32_t *)(s + 13);
                *(uint32_t *)(d + 12) = (x LS 24) | (w RS 8);
            }
            break;
        case 2:
            w = *(uint32_t *)s;
            *d++ = *s++;
            *d++ = *s++;
            n -= 2;
            for (; n >= 18; s += 16, d += 16, n -= 16)
            {
                x = *(uint32_t *)(s + 2);
                *(uint32_t *)(d + 0) = (w LS 16) | (x RS 16);
                w = *(uint32_t *)(s + 6);
                *(uint32_t *)(d + 4) = (x LS 16) | (w RS 16);
                x = *(uint32_t *)(s + 10);
                *(uint32_t *)(d + 8) = (w LS 16) | (x RS 16);
                w = *(uint32_t *)(s + 14);
                *(uint32_t *)(d + 12) = (x LS 16) | (w RS 16);
            }
            break;
        case 3:
            w = *(uint32_t *)s;
            *d++ = *s++;
            n -= 1;
            for (; n >= 19; s += 16, d += 16, n -= 16)
            {
                x = *(uint32_t *)(s + 3);
                *(uint32_t *)(d + 0) = (w LS 8) | (x RS 24);
                w = *(uint32_t *)(s + 7);
                *(uint32_t *)(d + 4) = (x LS 8) | (w RS 24);
                x = *(uint32_t *)(s + 11);
                *(uint32_t *)(d + 8) = (w LS 8) | (x RS 24);
                w = *(uint32_t *)(s + 15);
                *(uint32_t *)(d + 12) = (x LS 8) | (w RS 24);
            }
            break;
        }
    if (n & 16)
    {
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
    if (n & 8)
    {
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
    }
    if (n & 4)
    {
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
        *d++ = *s++;
    }
    if (n & 2)
    {
        *d++ = *s++;
        *d++ = *s++;
    }
    if (n & 1)
    {
        *d = *s;
    }
    return dest;
#endif

    for (; n; n--)
        *d++ = *s++;
    return dest;
}

long long strtoll(const char *nptr, char **endptr, int base)
{
    const char *s;
    long long acc, cutoff;
    int c;
    int neg, any, cutlim;

    /*
     * Skip white space and pick up leading +/- sign if any.
     * If base is 0, allow 0x for hex and 0 for octal, else
     * assume decimal; if base is already 16, allow 0x.
     */
    s = nptr;
    do
    {
        c = (unsigned char)*s++;
    } while (isspace(c));

    if (c == '-')
    {
        neg = 1;
        c = *s++;
    }
    else
    {
        neg = 0;
        if (c == '+')
            c = *s++;
    }

    if ((base == 0 || base == 16) && c == '0' && (*s == 'x' || *s == 'X'))
    {
        c = s[1];
        s += 2;
        base = 16;
    }

    if (base == 0)
        base = c == '0' ? 8 : 10;

    /*
     * Compute the cutoff value between legal numbers and illegal
     * numbers.  That is the largest legal value, divided by the
     * base.  An input number that is greater than this value, if
     * followed by a legal input character, is too big.  One that
     * is equal to this value may be valid or not; the limit
     * between valid and invalid numbers is then based on the last
     * digit.  For instance, if the range for long long is
     * [-9223372036854775808..9223372036854775807] and the input base
     * is 10, cutoff will be set to 922337203685477580 and cutlim to
     * either 7 (neg==0) or 8 (neg==1), meaning that if we have
     * accumulated a value > 922337203685477580, or equal but the
     * next digit is > 7 (or 8), the number is too big, and we will
     * return a range error.
     *
     * Set any if any 'digits' consumed; make it negative to indicate
     * overflow.
     */

    switch (base)
    {
    case 4:
        if (neg)
        {
            cutlim = LLONG_MIN % 4;
            cutoff = LLONG_MIN / 4;
        }
        else
        {
            cutlim = LLONG_MAX % 4;
            cutoff = LLONG_MAX / 4;
        }
        break;

    case 8:
        if (neg)
        {
            cutlim = LLONG_MIN % 8;
            cutoff = LLONG_MIN / 8;
        }
        else
        {
            cutlim = LLONG_MAX % 8;
            cutoff = LLONG_MAX / 8;
        }
        break;

    case 10:
        if (neg)
        {
            cutlim = LLONG_MIN % 10;
            cutoff = LLONG_MIN / 10;
        }
        else
        {
            cutlim = LLONG_MAX % 10;
            cutoff = LLONG_MAX / 10;
        }
        break;

    case 16:
        if (neg)
        {
            cutlim = LLONG_MIN % 16;
            cutoff = LLONG_MIN / 16;
        }
        else
        {
            cutlim = LLONG_MAX % 16;
            cutoff = LLONG_MAX / 16;
        }
        break;

    default:
        cutoff = neg ? LLONG_MIN : LLONG_MAX;
        cutlim = cutoff % base;
        cutoff /= base;
        break;
    }

    if (neg)
    {
        if (cutlim > 0)
        {
            cutlim -= base;
            cutoff += 1;
        }
        cutlim = -cutlim;
    }

    for (acc = 0, any = 0;; c = (unsigned char)*s++)
    {
        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;

        if (c >= base)
            break;

        if (any < 0)
            continue;

        if (neg)
        {
            if (acc < cutoff || (acc == cutoff && c > cutlim))
            {
                any = -1;
                acc = LLONG_MIN;
                errno = ERANGE;
            }
            else
            {
                any = 1;
                acc *= base;
                acc -= c;
            }
        }
        else
        {
            if (acc > cutoff || (acc == cutoff && c > cutlim))
            {
                any = -1;
                acc = LLONG_MAX;
                errno = ERANGE;
            }
            else
            {
                any = 1;
                acc *= base;
                acc += c;
            }
        }
    }

    if (endptr != 0)
        *endptr = (char *)(any ? s - 1 : nptr);

    return (acc);
}
unsigned long long strtoull(const char *nptr, char **endptr, int base)
{
    const char *s;
    unsigned long long acc, cutoff;
    int c;
    int neg, any, cutlim;

    s = nptr;
    do
    {
        c = (unsigned char)*s++;
    } while (isspace(c));

    if (c == '-')
    {
        neg = 1;
        c = *s++;
    }
    else
    {
        neg = 0;
        if (c == '+')
            c = *s++;
    }

    if ((base == 0 || base == 16) && c == '0' && (*s == 'x' || *s == 'X'))
    {
        c = s[1];
        s += 2;
        base = 16;
    }

    if (base == 0)
        base = c == '0' ? 8 : 10;

    switch (base)
    {
    case 4:
        cutoff = ULLONG_MAX / 4;
        cutlim = ULLONG_MAX % 4;
        break;

    case 8:
        cutoff = ULLONG_MAX / 8;
        cutlim = ULLONG_MAX % 8;
        break;

    case 10:
        cutoff = ULLONG_MAX / 10;
        cutlim = ULLONG_MAX % 10;
        break;

    case 16:
        cutoff = ULLONG_MAX / 16;
        cutlim = ULLONG_MAX % 16;
        break;

    default:
        cutoff = ULLONG_MAX / base;
        cutlim = ULLONG_MAX % base;
        break;
    }

    for (acc = 0, any = 0;; c = (unsigned char)*s++)
    {
        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;

        if (c >= base)
            break;

        if (any < 0)
            continue;

        if (acc > cutoff || (acc == cutoff && c > cutlim))
        {
            any = -1;
            acc = ULLONG_MAX;
            errno = ERANGE;
        }
        else
        {
            any = 1;
            acc *= (unsigned long long)base;
            acc += c;
        }
    }

    if (neg && any > 0)
        acc = -acc;

    if (endptr != 0)
        *endptr = (char *)(any ? s - 1 : nptr);

    return (acc);
}

int atoi(const char *nptr) { return (int)strtol(nptr, NULL, 10); }

void F2S(double d, char *str, int l) {}

char *strchr(const char *s, int c)
{
    const char *p = s;
    while (*p && *p != c)
    {
        p++;
    }
    if (*p == c)
    {
        return (char *)p;
    }
    return NULL;
}
char *strrchr(const char *s1, int ch)
{
    char *s2;
    char *s3;
    s2 = strchr(s1, ch);
    while (s2 != NULL)
    {
        s3 = strchr(s2 + 1, ch);
        if (s3 != NULL)
        {
            s2 = s3;
        }
        else
        {
            return s2;
        }
    }
    return NULL;
}

void *memmove(void *dest, const void *src, int n)
{
    char *d = dest;
    const char *s = src;

    if (d == s)
    {
        return d; // 源和目标相同，无需复制
    }

    // 检查是否有重叠
    if (s < d && s + n > d)
    {
        // 有重叠且源地址在目标地址之前，需要从后向前复制
        for (int i = n; i != 0; i--)
        {
            d[i - 1] = s[i - 1];
        }
    }
    else
    {
        // 无重叠或源地址在目标地址之后，可以从前向后复制
        for (int i = 0; i < n; i++)
        {
            d[i] = s[i];
        }
    }

    return dest;
}

/////////////////////////////////////////

// strlen
size_t strlen(const char *s)
{
    size_t len = 0;
    while (s[len])
        len++;
    return len;
}

void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = s;

    while (n-- != 0)
    {
        if ((unsigned char)c == *p++)
        {
            return (void *)(p - 1);
        }
    }

    return NULL;
}

size_t strnlen(const char *s, size_t n)
{
    const char *p = memchr(s, 0, n);
    return p ? p - s : n;
}

// strcat
char *strcat(char *dest, const char *src)
{
    char *tmp = dest;
    while (*dest)
        dest++;
    while ((*dest++ = *src++) != '\0')
        ;
    return tmp;
}
// strncat
char *strncat(char *dest, const char *src, size_t n)
{
    char *tmp = dest;
    while (*dest)
        dest++;
    while (n-- > 0 && (*dest++ = *src++) != '\0')
        ;
    return tmp;
}

// strtol
long strtol(const char *nptr, char **endptr, int base)
{
    long acc = 0;
    int c;
    unsigned long cutoff;
    int neg = 0, any, cutlim;

    /*
     * Skip white space and pick up leading +/- sign if any.
     * If base is 0, allow 0x for hex and 0 for octal, else
     * assume decimal; if base is already 16, allow 0x.
     */
    do
    {
        c = *nptr++;
    } while (isspace(c));
    if (c == '-')
    {
        neg = 1;
        c = *nptr++;
    }
    else if (c == '+')
        c = *nptr++;
    if ((base == 0 || base == 16) && c == '0' && (*nptr == 'x' || *nptr == 'X'))
    {
        c = nptr[1];
        nptr += 2;
        base = 16;
    }
    else if ((base == 0 || base == 2) && c == '0' &&
             (*nptr == 'b' || *nptr == 'B'))
    {
        c = nptr[1];
        nptr += 2;
        base = 2;
    }
    else if (base == 0)
        base = c == '0' ? 8 : 10;

    /*
     * Compute the cutoff value between legal numbers and illegal
     * numbers.  That is the largest legal value, divided by the
     * base.  An input number that is greater than this value, if
     * followed by a legal input character, is too big.  One that
     * is equal to this value may be valid or not; the limit
     * between valid and invalid numbers is then based on the last
     * digit.  For instance, if the range for longs is
     * [-2147483648..2147483647] and the input base is 10,
     * cutoff will be set to 214748364 and cutlim to either
     * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
     * a value > 214748364, or equal but the next digit is > 7 (or 8),
     * the number is too big, and we will return a range error.
     */
    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff % (unsigned long)base;
    cutoff /= (unsigned long)base;
    for (acc = 0, any = 0;; c = *nptr++)
    {
        if (isdigit(c))
            c -= '0';
        else if (isalpha(c))
            c -= isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
            any = -1;
        else
        {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0)
    {
        acc = neg ? LONG_MIN : LONG_MAX;
        // errno = ERANGE;
        write(2, "panic: strtol: overflow\n", 25);
    }
    else if (neg)
        acc = -acc;
    if (endptr != 0)
        *endptr = (char *)(any ? nptr : (char *)nptr - 1);
    return (acc);
}

// isspace
int isspace(int c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
            c == '\v');
}

// isdigit
int isdigit(int c) { return (c >= '0' && c <= '9'); }

// isalpha
int isalpha(int c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

// isupper
int isupper(int c) { return (c >= 'A' && c <= 'Z'); }

// strncmp
int strncmp(const char *s1, const char *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)s1,
                        *p2 = (const unsigned char *)s2;
    while (n-- > 0)
    {
        if (*p1 != *p2)
            return *p1 - *p2;
        if (*p1 == '\0')
            return 0;
        p1++, p2++;
    }
    return 0;
}

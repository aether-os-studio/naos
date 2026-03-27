#include <libs/klibc.h>
#include <task/task.h>
#include <drivers/kernel_logger.h>
#include <arch/arch.h>
#include <mm/fault.h>
#include <mm/page_table.h>

void spin_init(spinlock_t *lock) { memset(lock, 0, sizeof(spinlock_t)); }

void raw_spin_lock(spinlock_t *sl) {
    while (__sync_lock_test_and_set(&sl->lock, 1)) {
        arch_pause();
    }

    __sync_synchronize();
}

void raw_spin_unlock(spinlock_t *sl) { __sync_lock_release(&sl->lock); }

void spin_lock(spinlock_t *sl) {
    bool irq_state = arch_interrupt_enabled();

    arch_disable_interrupt();

    if (current_task)
        current_task->preempt_count++;

    raw_spin_lock(sl);

    sl->irq_state = irq_state;
}

void spin_unlock(spinlock_t *sl) {
    raw_spin_unlock(sl);

    if (current_task)
        current_task->preempt_count--;

    if (sl->irq_state) {
        arch_enable_interrupt();
    }
}

void kref_ref(kref_t *ref);
void kref_unref(kref_t *ref);

void kref_ref(kref_t *ref) {
    spin_lock(&ref->lock);
    ref->ref_count++;
    spin_unlock(&ref->lock);
}

void kref_unref(kref_t *ref) {
    spin_lock(&ref->lock);
    ref->ref_count--;
    spin_unlock(&ref->lock);
}

int kref_get(kref_t *ref) {
    spin_lock(&ref->lock);
    int value = ref->ref_count;
    spin_unlock(&ref->lock);
    return value;
}

void kref_set(kref_t *ref, int value) {
    spin_lock(&ref->lock);
    ref->ref_count = value;
    spin_unlock(&ref->lock);
}

bool check_user_overflow(uint64_t addr, uint64_t size) {
    uint64_t hhdm = get_physical_memory_offset();
    if (addr >= (UINT64_MAX - size) || (addr + size) >= hhdm) {
        return true;
    }
    if (size > 0 && (addr + size - 1) >= hhdm) {
        return true;
    }
    return false;
}

bool check_unmapped(uint64_t addr, uint64_t len) {
    if (len == 0) {
        return false;
    }
    if (!current_task || !current_task->mm) {
        return true;
    }

    uint64_t end = addr + len;
    uint64_t *pgdir =
        (uint64_t *)phys_to_virt(current_task->mm->page_table_addr);
    vma_manager_t *mgr = &current_task->mm->task_vma_mgr;
    uint64_t cursor = addr;

    spin_lock(&mgr->lock);
    while (cursor < end) {
        uint64_t chunk_end = MIN(end, PADDING_UP(cursor + 1, PAGE_SIZE));
        if (translate_address(pgdir, cursor)) {
            cursor = chunk_end;
            continue;
        }

        vma_t *vma = vma_find(mgr, cursor);
        if (!vma) {
            spin_unlock(&mgr->lock);
            return true;
        }

        cursor = MIN(end, vma->vm_end);
    }
    spin_unlock(&mgr->lock);

    return false;
}

static uint64_t user_translate_access(uint64_t *pgdir, uint64_t uaddr,
                                      bool write) {
    if (!pgdir || !uaddr)
        return 0;

    uint64_t indexs[ARCH_MAX_PT_LEVEL];
    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL; i++) {
        indexs[i] = PAGE_CALC_PAGE_TABLE_INDEX(uaddr, i + 1);
    }

    for (uint64_t i = 0; i < ARCH_MAX_PT_LEVEL - 1; i++) {
        uint64_t entry = pgdir[indexs[i]];
        if (ARCH_PT_IS_LARGE(entry)) {
            uint64_t flags = ARCH_READ_PTE_FLAG(entry);
            if (!(flags & ARCH_PT_FLAG_USER))
                return 0;
#if defined(__aarch64__)
            if (write && (flags & ARCH_PT_FLAG_READONLY))
                return 0;
#else
            if (write && !(flags & ARCH_PT_FLAG_WRITEABLE))
                return 0;
#endif
            return (ARCH_READ_PTE(entry) & ~PAGE_CALC_PAGE_TABLE_MASK(i + 1)) +
                   (uaddr & PAGE_CALC_PAGE_TABLE_MASK(i + 1));
        }
        if (!ARCH_PT_IS_TABLE(entry))
            return 0;
        pgdir = (uint64_t *)phys_to_virt(ARCH_READ_PTE(entry));
    }

    uint64_t pte = pgdir[indexs[ARCH_MAX_PT_LEVEL - 1]];
    if (!(pte & ARCH_PT_FLAG_VALID))
        return 0;

    uint64_t flags = ARCH_READ_PTE_FLAG(pte);
    if (!(flags & ARCH_PT_FLAG_USER))
        return 0;
#if defined(__aarch64__)
    if (write && (flags & ARCH_PT_FLAG_READONLY))
        return 0;
#else
    if (write && !(flags & ARCH_PT_FLAG_WRITEABLE))
        return 0;
#endif

    return ARCH_READ_PTE(pte) +
           (uaddr & PAGE_CALC_PAGE_TABLE_MASK(ARCH_MAX_PT_LEVEL));
}

uint64_t user_translate_or_fault(uint64_t *pgdir, uint64_t uaddr, bool write) {
    uint64_t pa = user_translate_access(pgdir, uaddr, write);
    if (pa)
        return pa;

    task_t *task = arch_get_current();
    if (!task)
        return 0;
    if (handle_page_fault_flags(task, uaddr,
                                write ? PF_ACCESS_WRITE : PF_ACCESS_READ) != 0)
        return 0;

    return user_translate_access(pgdir, uaddr, write);
}

void *memcpy(void *restrict dest, const void *restrict src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;

    typedef uint64_t __attribute__((__may_alias__)) u64;

    for (; (uintptr_t)s % 8 && n; n--)
        *d++ = *s++;

    if ((uintptr_t)d % 8 == 0) {
        for (; n >= 32; s += 32, d += 32, n -= 32) {
            *(u64 *)(d + 0) = *(u64 *)(s + 0);
            *(u64 *)(d + 8) = *(u64 *)(s + 8);
            *(u64 *)(d + 16) = *(u64 *)(s + 16);
            *(u64 *)(d + 24) = *(u64 *)(s + 24);
        }
        if (n & 16) {
            *(u64 *)(d + 0) = *(u64 *)(s + 0);
            *(u64 *)(d + 8) = *(u64 *)(s + 8);
            d += 16;
            s += 16;
        }
        if (n & 8) {
            *(u64 *)(d + 0) = *(u64 *)(s + 0);
            d += 8;
            s += 8;
        }
        if (n & 4) {
            *(uint32_t *)(d + 0) = *(uint32_t *)(s + 0);
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

    while (n--)
        *d++ = *s++;
    return dest;
}

void *memset(void *dest, int c, size_t n) {
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

    typedef uint32_t __attribute__((__may_alias__)) u32;
    typedef uint64_t __attribute__((__may_alias__)) u64;

    u32 c32 = ((u32)-1) / 255 * (unsigned char)c;

    /* In preparation to copy 32 bytes at a time, aligned on
     * an 8-byte bounary, fill head/tail up to 28 bytes each.
     * As in the initial byte-based head/tail fill, each
     * conditional below ensures that the subsequent offsets
     * are valid (e.g. !(n<=24) implies n>=28). */

    *(u32 *)(s + 0) = c32;
    *(u32 *)(s + n - 4) = c32;
    if (n <= 8)
        return dest;
    *(u32 *)(s + 4) = c32;
    *(u32 *)(s + 8) = c32;
    *(u32 *)(s + n - 12) = c32;
    *(u32 *)(s + n - 8) = c32;
    if (n <= 24)
        return dest;
    *(u32 *)(s + 12) = c32;
    *(u32 *)(s + 16) = c32;
    *(u32 *)(s + 20) = c32;
    *(u32 *)(s + 24) = c32;
    *(u32 *)(s + n - 28) = c32;
    *(u32 *)(s + n - 24) = c32;
    *(u32 *)(s + n - 20) = c32;
    *(u32 *)(s + n - 16) = c32;

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
    for (; n >= 32; n -= 32, s += 32) {
        *(u64 *)(s + 0) = c64;
        *(u64 *)(s + 8) = c64;
        *(u64 *)(s + 16) = c64;
        *(u64 *)(s + 24) = c64;
    }

    return dest;
}

void *memmove(void *dest, const void *src, size_t n) {
    typedef __attribute__((__may_alias__)) size_t WT;
#define WS (sizeof(WT))

    char *d = dest;
    const char *s = src;

    if (d == s)
        return d;
    if ((uintptr_t)s - (uintptr_t)d - n <= -2 * n)
        return memcpy(d, s, n);

    if (d < s) {
        if ((uintptr_t)s % WS == (uintptr_t)d % WS) {
            while ((uintptr_t)d % WS) {
                if (!n--)
                    return dest;
                *d++ = *s++;
            }
            for (; n >= WS; n -= WS, d += WS, s += WS)
                *(WT *)d = *(WT *)s;
        }
        for (; n; n--)
            *d++ = *s++;
    } else {
        if ((uintptr_t)s % WS == (uintptr_t)d % WS) {
            while ((uintptr_t)(d + n) % WS) {
                if (!n--)
                    return dest;
                d[n] = s[n];
            }
            while (n >= WS)
                n -= WS, *(WT *)(d + n) = *(WT *)(s + n);
        }
        while (n)
            n--, d[n] = s[n];
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

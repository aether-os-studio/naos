#include "heap.h"
#include <libs/klibc.h>

#ifndef HEAP_ALIGN
#define HEAP_ALIGN (sizeof(void *))
#endif

#define HEAP_MAGIC 0xDEADBEEF
#define BLOCK_USED ((size_t)1)
#define BLOCK_MASK (~(size_t)0x7)

static inline size_t align_up(size_t v, size_t a) {
    return (v + (a - 1)) & ~(a - 1);
}

static inline uintptr_t align_up_ptr(uintptr_t v, size_t a) {
    return (v + (uintptr_t)(a - 1)) & ~((uintptr_t)a - 1);
}

static inline bool is_power_of_two(size_t x) {
    return x && ((x & (x - 1)) == 0);
}

typedef struct BlockHeader {
    size_t size_and_flags;
    size_t req_size;
    uint32_t magic;
    uint32_t reserved;
} BlockHeader;

typedef struct BlockFooter {
    size_t size_and_flags;
} BlockFooter;

typedef struct FreeBlock {
    BlockHeader hdr;
    struct FreeBlock *prev;
    struct FreeBlock *next;
} FreeBlock;

static spinlock_t heap_lock;
static bool heap_initialized = false;
static uint8_t *heap_start = NULL;
static uint8_t *heap_end = NULL;
static FreeBlock *free_list = NULL;
static ErrorHandler error_handler = NULL;
static OomCallback oom_handler = NULL;

#define HEADER_SIZE ((size_t)sizeof(BlockHeader))
#define FOOTER_SIZE ((size_t)sizeof(BlockFooter))
#define BACKPTR_SIZE ((size_t)sizeof(void *))
#define MIN_BLOCK_SIZE                                                         \
    PADDING_UP(sizeof(FreeBlock) + sizeof(BlockFooter), HEAP_ALIGN)

static inline size_t block_size(const BlockHeader *h) {
    return h->size_and_flags & BLOCK_MASK;
}

static inline bool block_is_used(const BlockHeader *h) {
    return (h->size_and_flags & BLOCK_USED) != 0;
}

static inline void block_set(BlockHeader *h, size_t total, bool used) {
    h->size_and_flags = (total & BLOCK_MASK) | (used ? BLOCK_USED : 0);
}

static inline BlockFooter *block_footer(BlockHeader *h) {
    return (BlockFooter *)((uint8_t *)h + block_size(h) - FOOTER_SIZE);
}

static inline void block_write_footer(BlockHeader *h) {
    block_footer(h)->size_and_flags = h->size_and_flags;
}

static inline BlockHeader *block_next(BlockHeader *h) {
    uint8_t *p = (uint8_t *)h + block_size(h);
    if (p >= heap_end)
        return NULL;
    return (BlockHeader *)p;
}

static inline BlockHeader *block_prev(BlockHeader *h) {
    if ((uint8_t *)h <= heap_start + FOOTER_SIZE)
        return NULL;
    BlockFooter *pf = (BlockFooter *)((uint8_t *)h - FOOTER_SIZE);
    size_t psz = pf->size_and_flags & BLOCK_MASK;
    if (psz == 0)
        return NULL;
    uint8_t *p = (uint8_t *)h - psz;
    if (p < heap_start)
        return NULL;
    return (BlockHeader *)p;
}

static inline bool ptr_in_heap(const void *p) {
    return (const uint8_t *)p >= heap_start && (const uint8_t *)p < heap_end;
}

static inline bool block_valid(BlockHeader *h) {
    if (!h || !ptr_in_heap(h))
        return false;
    if (h->magic != HEAP_MAGIC)
        return false;

    size_t sz = block_size(h);
    if (sz < MIN_BLOCK_SIZE)
        return false;
    if ((uint8_t *)h + sz > heap_end)
        return false;

    BlockFooter *f = block_footer(h);
    if (!ptr_in_heap(f))
        return false;
    if ((f->size_and_flags & BLOCK_MASK) != sz)
        return false;
    return true;
}

static inline void **user_backptr_slot(void *user_ptr) {
    return (void **)((uint8_t *)user_ptr - BACKPTR_SIZE);
}

static inline BlockHeader *ptr_to_header(void *ptr) {
    if (!ptr)
        return NULL;
    if (!ptr_in_heap(ptr))
        return NULL;
    BlockHeader *h = (BlockHeader *)(*user_backptr_slot(ptr));
    if (!block_valid(h))
        return NULL;
    return h;
}

static void heap_report_error(enum HeapError err, void *ptr) {
    if (error_handler) {
        error_handler(err, ptr);
    }
}

static void free_list_insert(FreeBlock *fb) {
    fb->prev = NULL;
    fb->next = free_list;
    if (free_list)
        free_list->prev = fb;
    free_list = fb;
}

static void free_list_remove(FreeBlock *fb) {
    if (fb->prev)
        fb->prev->next = fb->next;
    else
        free_list = fb->next;
    if (fb->next)
        fb->next->prev = fb->prev;
    fb->prev = fb->next = NULL;
}

static FreeBlock *coalesce(FreeBlock *fb) {
    BlockHeader *h = &fb->hdr;

    BlockHeader *prev = block_prev(h);
    if (prev && block_valid(prev) && !block_is_used(prev)) {
        FreeBlock *pf = (FreeBlock *)prev;
        free_list_remove(pf);

        size_t ns = block_size(prev) + block_size(h);
        block_set(prev, ns, false);
        prev->req_size = 0;
        prev->magic = HEAP_MAGIC;
        block_write_footer(prev);

        h = prev;
        fb = (FreeBlock *)h;
    }

    BlockHeader *next = block_next(h);
    if (next && block_valid(next) && !block_is_used(next)) {
        FreeBlock *nf = (FreeBlock *)next;
        free_list_remove(nf);

        size_t ns = block_size(h) + block_size(next);
        block_set(h, ns, false);
        h->req_size = 0;
        h->magic = HEAP_MAGIC;
        block_write_footer(h);

        fb = (FreeBlock *)h;
    }

    return fb;
}

static bool add_region_locked(uint8_t *address, size_t size) {
    if (!address || size < MIN_BLOCK_SIZE)
        return false;

    uintptr_t start = align_up_ptr((uintptr_t)address, HEAP_ALIGN);
    if (start >= (uintptr_t)address + size)
        return false;

    size_t adjusted = size - (size_t)(start - (uintptr_t)address);
    adjusted &= ~(HEAP_ALIGN - 1);
    if (adjusted < MIN_BLOCK_SIZE)
        return false;

    uint8_t *region_start = (uint8_t *)start;
    uint8_t *region_end = region_start + adjusted;

    if (!heap_initialized) {
        heap_start = region_start;
        heap_end = region_end;
    } else {
        if (region_start != heap_end) {
            return false;
        }
        heap_end = region_end;
    }

    BlockHeader *h = (BlockHeader *)region_start;
    block_set(h, adjusted, false);
    h->req_size = 0;
    h->magic = HEAP_MAGIC;
    block_write_footer(h);

    FreeBlock *fb = (FreeBlock *)h;
    fb->prev = fb->next = NULL;

    if (region_start > heap_start) {
        BlockHeader *prev = block_prev(h);
        if (prev && block_valid(prev) && !block_is_used(prev)) {
            FreeBlock *pf = (FreeBlock *)prev;
            free_list_remove(pf);

            size_t ns = block_size(prev) + block_size(h);
            block_set(prev, ns, false);
            prev->req_size = 0;
            prev->magic = HEAP_MAGIC;
            block_write_footer(prev);

            free_list_insert((FreeBlock *)prev);
            return true;
        }
    }

    free_list_insert(fb);
    return true;
}

static FreeBlock *find_fit(size_t alignment, size_t req_size,
                           size_t *need_total, void **user_ptr_out) {
    for (FreeBlock *fb = free_list; fb; fb = fb->next) {
        BlockHeader *h = &fb->hdr;
        size_t total = block_size(h);

        uintptr_t base = (uintptr_t)h;
        uintptr_t raw = base + HEADER_SIZE;
        uintptr_t user = align_up_ptr(raw + BACKPTR_SIZE, alignment);
        uintptr_t back = user - BACKPTR_SIZE;

        size_t need = align_up(
            (size_t)((back + BACKPTR_SIZE + req_size + FOOTER_SIZE) - base),
            HEAP_ALIGN);
        if (need < MIN_BLOCK_SIZE)
            need = MIN_BLOCK_SIZE;

        if (total >= need) {
            *need_total = need;
            *user_ptr_out = (void *)user;
            return fb;
        }
    }
    return NULL;
}

static void allocate_from_block(FreeBlock *fb, size_t need_total,
                                size_t req_size, void *user_ptr) {
    BlockHeader *h = &fb->hdr;
    size_t old = block_size(h);

    free_list_remove(fb);

    if (old >= need_total + MIN_BLOCK_SIZE) {
        size_t remain = old - need_total;

        block_set(h, need_total, true);
        h->req_size = req_size;
        h->magic = HEAP_MAGIC;
        block_write_footer(h);

        BlockHeader *nh = (BlockHeader *)((uint8_t *)h + need_total);
        block_set(nh, remain, false);
        nh->req_size = 0;
        nh->magic = HEAP_MAGIC;
        block_write_footer(nh);
        free_list_insert((FreeBlock *)nh);
    } else {
        block_set(h, old, true);
        h->req_size = req_size;
        h->magic = HEAP_MAGIC;
        block_write_footer(h);
    }

    *user_backptr_slot(user_ptr) = h;
}

bool heap_init(uint8_t *address, size_t size) {
    spin_lock(&heap_lock);

    heap_initialized = false;
    heap_start = NULL;
    heap_end = NULL;
    free_list = NULL;

    bool ok = add_region_locked(address, size);
    heap_initialized = ok;

    spin_unlock(&heap_lock);
    return ok;
}

bool heap_extend(uint8_t *address, size_t size) {
    spin_lock(&heap_lock);
    if (!heap_initialized) {
        spin_unlock(&heap_lock);
        return false;
    }
    bool ok = add_region_locked(address, size);
    spin_unlock(&heap_lock);
    return ok;
}

void heap_onerror(ErrorHandler handler) {
    spin_lock(&heap_lock);
    error_handler = handler;
    spin_unlock(&heap_lock);
}

void heap_set_oom_handler(OomCallback callback) {
    spin_lock(&heap_lock);
    oom_handler = callback;
    spin_unlock(&heap_lock);
}

size_t usable_size(void *ptr) {
    if (!ptr)
        return 0;

    spin_lock(&heap_lock);
    BlockHeader *h = ptr_to_header(ptr);
    if (!h || !block_is_used(h)) {
        spin_unlock(&heap_lock);
        return 0;
    }
    size_t r = h->req_size;
    spin_unlock(&heap_lock);
    return r;
}

void *aligned_alloc(size_t alignment, size_t size) {
    if (size == 0)
        return NULL;
    if (!is_power_of_two(alignment))
        return NULL;
    if (alignment < sizeof(void *))
        alignment = sizeof(void *);

retry:
    spin_lock(&heap_lock);

    if (!heap_initialized) {
        spin_unlock(&heap_lock);
        return NULL;
    }

    size_t need_total = 0;
    void *user_ptr = NULL;
    FreeBlock *fb = find_fit(alignment, size, &need_total, &user_ptr);

    if (fb) {
        allocate_from_block(fb, need_total, size, user_ptr);
        spin_unlock(&heap_lock);
        return user_ptr;
    }

    OomCallback oom = oom_handler;
    spin_unlock(&heap_lock);

    if (oom) {
        MemorySpan span = oom(size);
        if (span.ptr && span.size) {
            if (heap_extend(span.ptr, span.size)) {
                goto retry;
            }
        }
    }

    return NULL;
}

void *malloc(size_t size) { return aligned_alloc(HEAP_ALIGN, size); }

void *calloc(size_t nmemb, size_t size) {
    if (nmemb == 0 || size == 0) {
        return malloc(0);
    }

    if (nmemb > ((size_t)-1) / size) {
        return NULL;
    }

    size_t total = nmemb * size;
    void *p = malloc(total);
    if (p) {
        memset(p, 0, total);
    }
    return p;
}

void free(void *ptr) {
    if (!ptr)
        return;

    spin_lock(&heap_lock);

    BlockHeader *h = ptr_to_header(ptr);
    if (!h || !block_is_used(h)) {
        heap_report_error(InvalidFree, ptr);
        spin_unlock(&heap_lock);
        return;
    }

    block_set(h, block_size(h), false);
    h->req_size = 0;
    h->magic = HEAP_MAGIC;
    block_write_footer(h);

    FreeBlock *fb = (FreeBlock *)h;
    fb->prev = fb->next = NULL;
    fb = coalesce(fb);
    free_list_insert(fb);

    spin_unlock(&heap_lock);
}

void *realloc(void *ptr, size_t size) {
    if (!ptr)
        return malloc(size);
    if (size == 0) {
        free(ptr);
        return NULL;
    }

    spin_lock(&heap_lock);

    BlockHeader *h = ptr_to_header(ptr);
    if (!h || !block_is_used(h)) {
        heap_report_error(InvalidFree, ptr);
        spin_unlock(&heap_lock);
        return NULL;
    }

    size_t old_req = h->req_size;

    if (size <= old_req) {
        h->req_size = size;
        spin_unlock(&heap_lock);
        return ptr;
    }

    BlockHeader *next = block_next(h);
    if (next && block_valid(next) && !block_is_used(next)) {
        uintptr_t user = (uintptr_t)ptr;
        uintptr_t back = user - BACKPTR_SIZE;
        uintptr_t base = (uintptr_t)h;
        size_t needed = align_up(
            (size_t)((back + BACKPTR_SIZE + size + FOOTER_SIZE) - base),
            HEAP_ALIGN);

        size_t combined = block_size(h) + block_size(next);
        if (combined >= needed) {
            FreeBlock *nf = (FreeBlock *)next;
            free_list_remove(nf);

            size_t remain = combined - needed;
            if (remain >= MIN_BLOCK_SIZE) {
                block_set(h, needed, true);
                h->req_size = size;
                h->magic = HEAP_MAGIC;
                block_write_footer(h);

                BlockHeader *nh = (BlockHeader *)((uint8_t *)h + needed);
                block_set(nh, remain, false);
                nh->req_size = 0;
                nh->magic = HEAP_MAGIC;
                block_write_footer(nh);
                free_list_insert((FreeBlock *)nh);
            } else {
                block_set(h, combined, true);
                h->req_size = size;
                h->magic = HEAP_MAGIC;
                block_write_footer(h);
            }

            spin_unlock(&heap_lock);
            return ptr;
        }
    }

    spin_unlock(&heap_lock);

    void *np = malloc(size);
    if (!np)
        return NULL;

    memcpy(np, ptr, old_req < size ? old_req : size);
    free(ptr);
    return np;
}

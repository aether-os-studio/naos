#include <mm/alloc.h>
#include <mm/mm.h>

#define ALLOC_HEADER_MAGIC 0x4E414F53414C4C4FULL
#define ALLOC_HEADER_FREED 0x4E414F5346524545ULL
#define SLAB_PAGE_MAGIC 0x534C4142U
#define LARGE_CLASS_INDEX 0xFFFFU

#define HEAP_DEFAULT_ALIGNMENT (sizeof(uintptr_t) * 2)
#define HEAP_MIN_ALIGNMENT (sizeof(uintptr_t))

#define SLAB_REFILL_BYTES (DEFAULT_PAGE_SIZE * 32)
#define SLAB_KEEP_EMPTY_PAGES 2
#define MAX_HEAP_SPANS 256

typedef enum alloc_kind {
    ALLOC_KIND_SLAB = 1,
    ALLOC_KIND_LARGE = 2,
} alloc_kind_t;

typedef struct alloc_header {
    uint64_t magic;
    uintptr_t base;
    uint64_t backend_size;
    size_t requested_size;
    size_t alignment;
    uint16_t class_index;
    uint8_t kind;
    uint8_t reserved;
} alloc_header_t;

typedef struct free_page_node {
    struct free_page_node *next;
} free_page_node_t;

typedef struct slab_free_obj {
    struct slab_free_obj *next;
} slab_free_obj_t;

typedef struct slab_page {
    uint32_t magic;
    uint16_t class_index;
    uint16_t capacity;
    uint16_t inuse;
    uint8_t source;
    uint8_t reserved[5];
    struct slab_page *next;
    slab_free_obj_t *free_list;
} slab_page_t;

typedef struct slab_class {
    uint16_t obj_size;
    uint16_t partial_count;
    slab_page_t *partial;
} slab_class_t;

typedef struct heap_span {
    uintptr_t start;
    uintptr_t end;
} heap_span_t;

enum {
    SLAB_PAGE_SOURCE_POOL = 0,
    SLAB_PAGE_SOURCE_FRAME = 1,
};

static const uint16_t slab_class_sizes[] = {
    64, 80, 96, 128, 160, 192, 256, 320, 384, 512, 768, 1024, 1536, 2048,
};

#define SLAB_CLASS_COUNT                                                       \
    (sizeof(slab_class_sizes) / sizeof(slab_class_sizes[0]))

static spinlock_t allocator_lock = SPIN_INIT;
static bool allocator_initialized = false;
static bool allocator_oom_inflight = false;

static ErrorHandler allocator_error_handler = NULL;
static OomCallback allocator_oom_handler = NULL;

static slab_class_t slab_classes[SLAB_CLASS_COUNT];

static free_page_node_t *pool_free_pages = NULL;
static size_t pool_free_count = 0;

static heap_span_t heap_spans[MAX_HEAP_SPANS];
static size_t heap_span_count = 0;

static inline bool add_overflow_size(size_t lhs, size_t rhs, size_t *out) {
    if (!out || lhs > SIZE_MAX - rhs)
        return true;
    *out = lhs + rhs;
    return false;
}

static inline bool is_power_of_two(size_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

static inline uintptr_t align_up_uintptr(uintptr_t value, size_t alignment) {
    return (uintptr_t)PADDING_UP(value, alignment);
}

static inline slab_page_t *slab_page_from_obj(uintptr_t obj_base) {
    return (slab_page_t *)(obj_base & ~(uintptr_t)(DEFAULT_PAGE_SIZE - 1));
}

static void report_error(enum HeapError error, void *ptr) {
    ErrorHandler handler = NULL;

    spin_lock(&allocator_lock);
    handler = allocator_error_handler;
    spin_unlock(&allocator_lock);

    if (handler)
        handler(error, ptr);
}

static void reset_allocator_locked(void) {
    allocator_initialized = false;
    allocator_oom_inflight = false;
    allocator_error_handler = NULL;
    allocator_oom_handler = NULL;

    pool_free_pages = NULL;
    pool_free_count = 0;

    heap_span_count = 0;

    for (size_t idx = 0; idx < SLAB_CLASS_COUNT; idx++) {
        slab_classes[idx].obj_size = slab_class_sizes[idx];
        slab_classes[idx].partial_count = 0;
        slab_classes[idx].partial = NULL;
    }
}

static bool spans_overlap(uintptr_t start_a, uintptr_t end_a, uintptr_t start_b,
                          uintptr_t end_b) {
    return !(end_a <= start_b || end_b <= start_a);
}

static void pool_push_page_locked(void *page) {
    free_page_node_t *node = (free_page_node_t *)page;
    node->next = pool_free_pages;
    pool_free_pages = node;
    pool_free_count++;
}

static void *pool_pop_page_locked(void) {
    if (!pool_free_pages)
        return NULL;

    free_page_node_t *node = pool_free_pages;
    pool_free_pages = node->next;
    pool_free_count--;
    return (void *)node;
}

static bool heap_extend_locked(uint8_t *address, size_t size) {
    if (!address || size == 0)
        return false;

    uintptr_t raw_start = (uintptr_t)address;
    uintptr_t raw_end = raw_start + size;
    if (raw_end < raw_start)
        return false;

    uintptr_t start = align_up_uintptr(raw_start, DEFAULT_PAGE_SIZE);
    uintptr_t end = (uintptr_t)PADDING_DOWN(raw_end, DEFAULT_PAGE_SIZE);
    if (start >= end)
        return false;

    for (size_t idx = 0; idx < heap_span_count; idx++) {
        if (spans_overlap(start, end, heap_spans[idx].start,
                          heap_spans[idx].end))
            return false;
    }

    if (heap_span_count >= MAX_HEAP_SPANS)
        return false;

    heap_spans[heap_span_count].start = start;
    heap_spans[heap_span_count].end = end;
    heap_span_count++;

    for (uintptr_t page = start; page < end; page += DEFAULT_PAGE_SIZE) {
        pool_push_page_locked((void *)page);
    }

    return true;
}

static bool refill_pool_locked(size_t request_bytes) {
    if (!allocator_oom_handler || allocator_oom_inflight)
        return false;

    allocator_oom_inflight = true;
    OomCallback callback = allocator_oom_handler;

    spin_unlock(&allocator_lock);
    MemorySpan span = callback(request_bytes);
    spin_lock(&allocator_lock);

    allocator_oom_inflight = false;

    if (!span.ptr || span.size == 0)
        return false;

    return heap_extend_locked(span.ptr, span.size);
}

static bool slab_partial_remove_locked(slab_class_t *klass,
                                       slab_page_t *target) {
    slab_page_t *prev = NULL;
    slab_page_t *curr = klass->partial;

    while (curr) {
        if (curr == target) {
            if (prev)
                prev->next = curr->next;
            else
                klass->partial = curr->next;
            curr->next = NULL;
            if (klass->partial_count > 0)
                klass->partial_count--;
            return true;
        }
        prev = curr;
        curr = curr->next;
    }

    return false;
}

static void slab_partial_push_locked(slab_class_t *klass, slab_page_t *page) {
    page->next = klass->partial;
    klass->partial = page;
    klass->partial_count++;
}

static bool slab_release_page_locked(slab_class_t *klass, slab_page_t *page) {
    bool removed = slab_partial_remove_locked(klass, page);
    if (!removed)
        return false;

    page->magic = 0;
    page->class_index = 0;
    page->capacity = 0;
    page->inuse = 0;
    page->free_list = NULL;
    page->next = NULL;

    if (page->source == SLAB_PAGE_SOURCE_POOL) {
        pool_push_page_locked(page);
        return true;
    }

    spin_unlock(&allocator_lock);
    free_frames_bytes(page, DEFAULT_PAGE_SIZE);
    spin_lock(&allocator_lock);
    return true;
}

static slab_page_t *slab_create_page_locked(uint16_t class_index) {
    if (class_index >= SLAB_CLASS_COUNT)
        return NULL;

    slab_class_t *klass = &slab_classes[class_index];
    void *page_mem = pool_pop_page_locked();
    uint8_t source = SLAB_PAGE_SOURCE_POOL;

    if (!page_mem) {
        refill_pool_locked(SLAB_REFILL_BYTES);
        page_mem = pool_pop_page_locked();
    }

    if (!page_mem) {
        spin_unlock(&allocator_lock);
        page_mem = alloc_frames_bytes(DEFAULT_PAGE_SIZE);
        spin_lock(&allocator_lock);
        source = SLAB_PAGE_SOURCE_FRAME;
    }

    if (!page_mem)
        return NULL;

    slab_page_t *page = (slab_page_t *)page_mem;
    memset(page, 0, sizeof(*page));

    page->magic = SLAB_PAGE_MAGIC;
    page->class_index = class_index;
    page->source = source;

    uintptr_t page_start = (uintptr_t)page_mem;
    uintptr_t obj_start =
        align_up_uintptr(page_start + sizeof(slab_page_t), sizeof(uintptr_t));
    if (obj_start < page_start || obj_start >= page_start + DEFAULT_PAGE_SIZE) {
        if (source == SLAB_PAGE_SOURCE_POOL) {
            pool_push_page_locked(page_mem);
        } else {
            spin_unlock(&allocator_lock);
            free_frames_bytes(page_mem, DEFAULT_PAGE_SIZE);
            spin_lock(&allocator_lock);
        }
        return NULL;
    }

    size_t available = page_start + DEFAULT_PAGE_SIZE - obj_start;
    size_t obj_size = klass->obj_size;
    size_t capacity = available / obj_size;

    if (capacity == 0 || capacity > UINT16_MAX) {
        if (source == SLAB_PAGE_SOURCE_POOL) {
            pool_push_page_locked(page_mem);
        } else {
            spin_unlock(&allocator_lock);
            free_frames_bytes(page_mem, DEFAULT_PAGE_SIZE);
            spin_lock(&allocator_lock);
        }
        return NULL;
    }

    page->capacity = (uint16_t)capacity;

    for (size_t idx = 0; idx < capacity; idx++) {
        slab_free_obj_t *obj = (slab_free_obj_t *)(obj_start + idx * obj_size);
        obj->next = page->free_list;
        page->free_list = obj;
    }

    slab_partial_push_locked(klass, page);
    return page;
}

static int slab_class_for_request(size_t request_size, size_t alignment) {
    size_t required = 0;
    if (add_overflow_size(request_size, sizeof(alloc_header_t), &required))
        return -1;

    if (alignment > 1) {
        size_t pad = alignment - 1;
        if (add_overflow_size(required, pad, &required))
            return -1;
    }

    for (size_t idx = 0; idx < SLAB_CLASS_COUNT; idx++) {
        if (slab_class_sizes[idx] >= required)
            return (int)idx;
    }

    return -1;
}

static void *slab_alloc_locked(size_t size, size_t alignment,
                               uint16_t class_index) {
    if (class_index >= SLAB_CLASS_COUNT)
        return NULL;

    slab_class_t *klass = &slab_classes[class_index];
    slab_page_t *page = klass->partial;

    if (!page)
        page = slab_create_page_locked(class_index);
    if (!page)
        return NULL;

    slab_free_obj_t *obj = page->free_list;
    if (!obj)
        return NULL;

    page->free_list = obj->next;
    page->inuse++;
    bool became_full = (page->free_list == NULL);
    if (became_full)
        slab_partial_remove_locked(klass, page);

    uintptr_t obj_base = (uintptr_t)obj;
    uintptr_t obj_end = obj_base + klass->obj_size;
    uintptr_t user =
        align_up_uintptr(obj_base + sizeof(alloc_header_t), alignment);

    if (user < obj_base + sizeof(alloc_header_t) || user + size < user ||
        user + size > obj_end) {
        obj->next = page->free_list;
        page->free_list = obj;
        if (page->inuse > 0)
            page->inuse--;
        if (became_full)
            slab_partial_push_locked(klass, page);
        return NULL;
    }

    alloc_header_t *header = (alloc_header_t *)(user - sizeof(alloc_header_t));
    header->magic = ALLOC_HEADER_MAGIC;
    header->base = obj_base;
    header->backend_size = klass->obj_size;
    header->requested_size = size;
    header->alignment = alignment;
    header->class_index = class_index;
    header->kind = ALLOC_KIND_SLAB;
    header->reserved = 0;

    return (void *)user;
}

static void *large_alloc(size_t size, size_t alignment) {
    size_t needed = 0;
    if (add_overflow_size(size, sizeof(alloc_header_t), &needed))
        return NULL;

    if (alignment > 1) {
        if (add_overflow_size(needed, alignment - 1, &needed))
            return NULL;
    }

    size_t alloc_bytes = PADDING_UP(needed, DEFAULT_PAGE_SIZE);
    if (alloc_bytes < needed)
        return NULL;

    void *base = alloc_frames_bytes(alloc_bytes);
    if (!base)
        return NULL;

    uintptr_t base_addr = (uintptr_t)base;
    uintptr_t user =
        align_up_uintptr(base_addr + sizeof(alloc_header_t), alignment);
    if (user < base_addr + sizeof(alloc_header_t) || user + size < user ||
        user + size > base_addr + alloc_bytes) {
        free_frames_bytes(base, alloc_bytes);
        return NULL;
    }

    alloc_header_t *header = (alloc_header_t *)(user - sizeof(alloc_header_t));
    header->magic = ALLOC_HEADER_MAGIC;
    header->base = base_addr;
    header->backend_size = alloc_bytes;
    header->requested_size = size;
    header->alignment = alignment;
    header->class_index = LARGE_CLASS_INDEX;
    header->kind = ALLOC_KIND_LARGE;
    header->reserved = 0;

    return (void *)user;
}

static void *alloc_with_alignment(size_t size, size_t alignment) {
    if (size == 0)
        size = 1;

    if (alignment < HEAP_MIN_ALIGNMENT)
        alignment = HEAP_MIN_ALIGNMENT;
    if (!is_power_of_two(alignment))
        return NULL;

    int class_index = slab_class_for_request(size, alignment);
    if (class_index >= 0) {
        spin_lock(&allocator_lock);
        void *ptr = slab_alloc_locked(size, alignment, (uint16_t)class_index);
        spin_unlock(&allocator_lock);
        if (ptr)
            return ptr;
    }

    return large_alloc(size, alignment);
}

bool heap_init(uint8_t *address, size_t size) {
    spin_lock(&allocator_lock);
    reset_allocator_locked();

    bool ok = heap_extend_locked(address, size);
    allocator_initialized = ok;

    spin_unlock(&allocator_lock);
    return ok;
}

bool heap_extend(uint8_t *address, size_t size) {
    spin_lock(&allocator_lock);
    bool ok = heap_extend_locked(address, size);
    if (ok)
        allocator_initialized = true;
    spin_unlock(&allocator_lock);
    return ok;
}

void heap_onerror(ErrorHandler handler) {
    spin_lock(&allocator_lock);
    allocator_error_handler = handler;
    spin_unlock(&allocator_lock);
}

void heap_set_oom_handler(OomCallback callback) {
    spin_lock(&allocator_lock);
    allocator_oom_handler = callback;
    spin_unlock(&allocator_lock);
}

size_t usable_size(void *ptr) {
    if (!ptr)
        return 0;

    alloc_header_t *header =
        (alloc_header_t *)((uintptr_t)ptr - sizeof(alloc_header_t));
    if (header->magic != ALLOC_HEADER_MAGIC)
        return 0;

    return header->requested_size;
}

void *malloc(size_t size) {
    return alloc_with_alignment(size, HEAP_DEFAULT_ALIGNMENT);
}

void *calloc(size_t nmemb, size_t size) {
    if (nmemb == 0 || size == 0)
        return malloc(1);

    if (nmemb > SIZE_MAX / size)
        return NULL;

    size_t total = nmemb * size;
    void *ptr = malloc(total);
    if (!ptr)
        return NULL;

    memset(ptr, 0, total);
    return ptr;
}

void *aligned_alloc(size_t alignment, size_t size) {
    if (!is_power_of_two(alignment) || alignment < HEAP_MIN_ALIGNMENT ||
        size == 0 || (size % alignment) != 0) {
        report_error(LayoutError, NULL);
        return NULL;
    }

    return alloc_with_alignment(size, alignment);
}

void free(void *ptr) {
    if (!ptr)
        return;

    alloc_header_t *header =
        (alloc_header_t *)((uintptr_t)ptr - sizeof(alloc_header_t));

    spin_lock(&allocator_lock);
    if (header->magic != ALLOC_HEADER_MAGIC) {
        spin_unlock(&allocator_lock);
        report_error(InvalidFree, ptr);
        return;
    }

    if (header->kind == ALLOC_KIND_SLAB) {
        uint16_t class_index = header->class_index;
        uintptr_t obj_base = header->base;
        if (class_index >= SLAB_CLASS_COUNT) {
            header->magic = ALLOC_HEADER_FREED;
            spin_unlock(&allocator_lock);
            report_error(InvalidFree, ptr);
            return;
        }

        slab_class_t *klass = &slab_classes[class_index];
        slab_page_t *page = slab_page_from_obj(obj_base);
        if (page->magic != SLAB_PAGE_MAGIC ||
            page->class_index != class_index || page->inuse == 0) {
            header->magic = ALLOC_HEADER_FREED;
            spin_unlock(&allocator_lock);
            report_error(InvalidFree, ptr);
            return;
        }

        bool was_full = (page->inuse == page->capacity);
        header->magic = ALLOC_HEADER_FREED;
        page->inuse--;

        slab_free_obj_t *obj = (slab_free_obj_t *)obj_base;
        obj->next = page->free_list;
        page->free_list = obj;

        if (was_full) {
            slab_partial_push_locked(klass, page);
        } else if (page->inuse == 0 &&
                   klass->partial_count > SLAB_KEEP_EMPTY_PAGES) {
            slab_release_page_locked(klass, page);
        }

        spin_unlock(&allocator_lock);
        return;
    }

    if (header->kind == ALLOC_KIND_LARGE) {
        void *base = (void *)header->base;
        uint64_t backend_size = header->backend_size;
        header->magic = ALLOC_HEADER_FREED;
        spin_unlock(&allocator_lock);
        free_frames_bytes(base, backend_size);
        return;
    }

    header->magic = ALLOC_HEADER_FREED;
    spin_unlock(&allocator_lock);
    report_error(InvalidFree, ptr);
}

void *realloc(void *ptr, size_t size) {
    if (!ptr)
        return malloc(size);

    if (size == 0) {
        free(ptr);
        return NULL;
    }

    alloc_header_t *header =
        (alloc_header_t *)((uintptr_t)ptr - sizeof(alloc_header_t));

    spin_lock(&allocator_lock);
    if (header->magic != ALLOC_HEADER_MAGIC) {
        spin_unlock(&allocator_lock);
        report_error(InvalidFree, ptr);
        return NULL;
    }

    size_t old_size = header->requested_size;
    size_t old_alignment = header->alignment;
    if (size <= old_size) {
        header->requested_size = size;
        spin_unlock(&allocator_lock);
        return ptr;
    }
    spin_unlock(&allocator_lock);

    void *new_ptr = alloc_with_alignment(size, old_alignment);
    if (!new_ptr)
        return NULL;

    memcpy(new_ptr, ptr, old_size);
    free(ptr);
    return new_ptr;
}

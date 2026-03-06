#pragma once

#include <libs/klibc.h>

typedef enum HeapError {
    InvalidFree,
    LayoutError,
} HeapError;

typedef void (*ErrorHandler)(enum HeapError error, void *ptr);

typedef struct MemorySpan {
    uint8_t *ptr;
    size_t size;
} MemorySpan;

typedef struct MemorySpan (*OomCallback)(size_t);

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

bool heap_init(uint8_t *address, size_t size);
bool heap_extend(uint8_t *address, size_t size);
void heap_onerror(ErrorHandler handler);
void heap_set_oom_handler(OomCallback callback);
size_t usable_size(void *ptr);
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *aligned_alloc(size_t alignment, size_t size);
void free(void *ptr);
void *realloc(void *ptr, size_t size);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

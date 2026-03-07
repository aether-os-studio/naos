#pragma once

#include <libs/klibc.h>

typedef struct hashmap_entry {
    uint64_t key;
    void *value;
    uint8_t state;
} hashmap_entry_t;

typedef struct hashmap {
    hashmap_entry_t *buckets;
    size_t bucket_count;
    size_t size;
    size_t used;
} hashmap_t;

#define HASHMAP_ENTRY_EMPTY 0
#define HASHMAP_ENTRY_OCCUPIED 1
#define HASHMAP_ENTRY_TOMBSTONE 2

#define HASHMAP_INIT                                                           \
    (hashmap_t){.buckets = NULL, .bucket_count = 0, .size = 0, .used = 0}

int hashmap_init(hashmap_t *map, size_t initial_capacity);
void hashmap_clear(hashmap_t *map);
void hashmap_deinit(hashmap_t *map);

void *hashmap_get(const hashmap_t *map, uint64_t key);
int hashmap_put(hashmap_t *map, uint64_t key, void *value);
void *hashmap_remove(hashmap_t *map, uint64_t key);

static inline size_t hashmap_size(const hashmap_t *map) {
    return map ? map->size : 0;
}

static inline bool hashmap_entry_is_occupied(const hashmap_entry_t *entry) {
    return entry && entry->state == HASHMAP_ENTRY_OCCUPIED;
}

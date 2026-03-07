#include <libs/hashmap.h>
#include <mm/mm.h>

#define HASHMAP_MIN_CAPACITY 16
#define HASHMAP_MAX_LOAD_NUM 8
#define HASHMAP_MAX_LOAD_DEN 10
#define HASHMAP_TOMBSTONE_REBUILD_MIN 16

static inline uint64_t hashmap_hash_u64(uint64_t key) {
    key += 0x9e3779b97f4a7c15ULL;
    key = (key ^ (key >> 30)) * 0xbf58476d1ce4e5b9ULL;
    key = (key ^ (key >> 27)) * 0x94d049bb133111ebULL;
    return key ^ (key >> 31);
}

static size_t hashmap_next_capacity(size_t capacity) {
    size_t next = HASHMAP_MIN_CAPACITY;
    while (next < capacity) {
        next <<= 1;
    }
    return next;
}

static inline size_t hashmap_bucket_index(uint64_t hash, size_t bucket_count) {
    return hash & (bucket_count - 1);
}

static inline bool hashmap_should_grow(const hashmap_t *map) {
    return (map->used + 1) * HASHMAP_MAX_LOAD_DEN >=
           map->bucket_count * HASHMAP_MAX_LOAD_NUM;
}

static inline bool hashmap_should_rebuild(const hashmap_t *map) {
    return (map->used - map->size) >= HASHMAP_TOMBSTONE_REBUILD_MIN &&
           map->size <= (map->used >> 1);
}

static void hashmap_insert_rehashed(hashmap_entry_t *buckets,
                                    size_t bucket_count, uint64_t key,
                                    void *value) {
    size_t bucket = hashmap_bucket_index(hashmap_hash_u64(key), bucket_count);

    while (hashmap_entry_is_occupied(&buckets[bucket])) {
        bucket = (bucket + 1) & (bucket_count - 1);
    }

    buckets[bucket].key = key;
    buckets[bucket].value = value;
    buckets[bucket].state = HASHMAP_ENTRY_OCCUPIED;
}

static int hashmap_rehash(hashmap_t *map, size_t target_capacity) {
    size_t bucket_count = hashmap_next_capacity(target_capacity);
    hashmap_entry_t *new_buckets =
        calloc(bucket_count, sizeof(hashmap_entry_t));
    if (!new_buckets) {
        return -ENOMEM;
    }

    for (size_t i = 0; i < map->bucket_count; i++) {
        hashmap_entry_t *entry = &map->buckets[i];
        if (!hashmap_entry_is_occupied(entry)) {
            continue;
        }

        hashmap_insert_rehashed(new_buckets, bucket_count, entry->key,
                                entry->value);
    }

    free(map->buckets);
    map->buckets = new_buckets;
    map->bucket_count = bucket_count;
    map->used = map->size;
    return 0;
}

int hashmap_init(hashmap_t *map, size_t initial_capacity) {
    if (!map) {
        return -EINVAL;
    }

    map->buckets = NULL;
    map->bucket_count = 0;
    map->size = 0;
    map->used = 0;

    return hashmap_rehash(map, initial_capacity ? initial_capacity
                                                : HASHMAP_MIN_CAPACITY);
}

void hashmap_clear(hashmap_t *map) {
    if (!map || !map->buckets) {
        return;
    }

    memset(map->buckets, 0, map->bucket_count * sizeof(hashmap_entry_t));
    map->size = 0;
    map->used = 0;
}

void hashmap_deinit(hashmap_t *map) {
    if (!map) {
        return;
    }

    free(map->buckets);
    map->buckets = NULL;
    map->bucket_count = 0;
    map->size = 0;
    map->used = 0;
}

void *hashmap_get(const hashmap_t *map, uint64_t key) {
    if (!map || !map->buckets || map->bucket_count == 0) {
        return NULL;
    }

    size_t bucket =
        hashmap_bucket_index(hashmap_hash_u64(key), map->bucket_count);
    while (true) {
        const hashmap_entry_t *entry = &map->buckets[bucket];
        if (entry->state == HASHMAP_ENTRY_EMPTY) {
            return NULL;
        }
        if (entry->state == HASHMAP_ENTRY_OCCUPIED && entry->key == key) {
            return entry->value;
        }

        bucket = (bucket + 1) & (map->bucket_count - 1);
    }
}

int hashmap_put(hashmap_t *map, uint64_t key, void *value) {
    if (!map) {
        return -EINVAL;
    }

    if (!map->buckets || map->bucket_count == 0) {
        int rc = hashmap_init(map, HASHMAP_MIN_CAPACITY);
        if (rc < 0) {
            return rc;
        }
    }

    if (hashmap_should_grow(map)) {
        int rc = hashmap_rehash(map, map->bucket_count << 1);
        if (rc < 0) {
            return rc;
        }
    } else if (hashmap_should_rebuild(map)) {
        int rc = hashmap_rehash(map, map->bucket_count);
        if (rc < 0) {
            return rc;
        }
    }

    size_t bucket =
        hashmap_bucket_index(hashmap_hash_u64(key), map->bucket_count);
    hashmap_entry_t *first_tombstone = NULL;

    while (true) {
        hashmap_entry_t *entry = &map->buckets[bucket];
        if (entry->state == HASHMAP_ENTRY_EMPTY) {
            hashmap_entry_t *target = first_tombstone ? first_tombstone : entry;
            if (target == entry) {
                map->used++;
            }
            target->key = key;
            target->value = value;
            target->state = HASHMAP_ENTRY_OCCUPIED;
            map->size++;
            return 0;
        }

        if (entry->state == HASHMAP_ENTRY_OCCUPIED && entry->key == key) {
            entry->value = value;
            return 0;
        }

        if (entry->state == HASHMAP_ENTRY_TOMBSTONE && !first_tombstone) {
            first_tombstone = entry;
        }

        bucket = (bucket + 1) & (map->bucket_count - 1);
    }
}

void *hashmap_remove(hashmap_t *map, uint64_t key) {
    if (!map || !map->buckets || map->bucket_count == 0) {
        return NULL;
    }

    size_t bucket =
        hashmap_bucket_index(hashmap_hash_u64(key), map->bucket_count);
    while (true) {
        hashmap_entry_t *entry = &map->buckets[bucket];
        if (entry->state == HASHMAP_ENTRY_EMPTY) {
            return NULL;
        }
        if (entry->state == HASHMAP_ENTRY_OCCUPIED && entry->key == key) {
            void *value = entry->value;
            entry->value = NULL;
            entry->state = HASHMAP_ENTRY_TOMBSTONE;
            map->size--;

            if (map->size == 0) {
                memset(map->buckets, 0,
                       map->bucket_count * sizeof(hashmap_entry_t));
                map->used = 0;
            }

            return value;
        }

        bucket = (bucket + 1) & (map->bucket_count - 1);
    }
}

#include <arch/arch.h>
#include <fs/vfs/vfs.h>
#include <libs/llist.h>
#include <mm/mm.h>
#include <mm/page.h>
#include <mm/cache.h>

#define CACHE_BUCKET_COUNT 8192

typedef enum cache_kind {
    CACHE_KIND_BLOCK = 1,
    CACHE_KIND_PAGE = 2,
} cache_kind_t;

struct cache_entry {
    cache_kind_t kind;
    uint64_t key0;
    uint64_t key1;
    uintptr_t page_phys;
    void *data;
    size_t valid_bytes;
    size_t refs;
    bool loading;
    bool detached;
    bool dirty;
    bool writeback;
    uint64_t dirty_seq;
    uint64_t writeback_seq;
    struct hlist_node bucket_node;
    struct llist_header lru_node;
};

static struct hlist_node *cache_buckets[CACHE_BUCKET_COUNT];
static DEFINE_LLIST(cache_lru);
static spinlock_t cache_lock = SPIN_INIT;

static inline uint64_t cache_hash_key(cache_kind_t kind, uint64_t key0,
                                      uint64_t key1) {
    uint64_t hash = 0x9e3779b97f4a7c15ULL ^ ((uint64_t)kind << 32);
    hash ^= key0 + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
    hash ^= key1 + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
    return hash;
}

static inline size_t cache_bucket_index(cache_kind_t kind, uint64_t key0,
                                        uint64_t key1) {
    return (size_t)(cache_hash_key(kind, key0, key1) %
                    (CACHE_BUCKET_COUNT - 1));
}

static cache_entry_t *cache_lookup_locked(cache_kind_t kind, uint64_t key0,
                                          uint64_t key1) {
    size_t bucket = cache_bucket_index(kind, key0, key1);
    struct hlist_node *node = cache_buckets[bucket];

    while (node) {
        cache_entry_t *entry = container_of(node, cache_entry_t, bucket_node);
        if (!entry->detached && entry->kind == kind && entry->key0 == key0 &&
            entry->key1 == key1) {
            return entry;
        }
        node = node->next;
    }

    return NULL;
}

static void cache_touch_locked(cache_entry_t *entry) {
    if (!entry || entry->detached)
        return;

    if (!llist_empty(&entry->lru_node))
        llist_delete(&entry->lru_node);
    llist_prepend(&cache_lru, &entry->lru_node);
}

static void cache_detach_locked(cache_entry_t *entry) {
    if (!entry || entry->detached)
        return;

    hlist_delete(&entry->bucket_node);
    if (!llist_empty(&entry->lru_node))
        llist_delete(&entry->lru_node);
    entry->detached = true;
}

static void cache_entry_destroy(cache_entry_t *entry) {
    if (!entry)
        return;

    if (entry->page_phys)
        address_release(entry->page_phys);
    free(entry);
}

static cache_entry_t *cache_entry_alloc(cache_kind_t kind, uint64_t key0,
                                        uint64_t key1) {
    cache_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry)
        return NULL;

    uintptr_t page_phys = alloc_frames(1);
    if (!page_phys) {
        free(entry);
        return NULL;
    }

    entry->kind = kind;
    entry->key0 = key0;
    entry->key1 = key1;
    entry->page_phys = page_phys;
    entry->data = (void *)phys_to_virt(page_phys);
    llist_init_head(&entry->lru_node);
    memset(entry->data, 0, PAGE_SIZE);
    return entry;
}

static cache_entry_t *cache_get_common(cache_kind_t kind, uint64_t key0,
                                       uint64_t key1, bool create,
                                       bool *created) {
    cache_entry_t *fresh = NULL;

    if (created)
        *created = false;

    while (true) {
        spin_lock(&cache_lock);

        cache_entry_t *entry = cache_lookup_locked(kind, key0, key1);
        if (entry) {
            if (entry->loading) {
                spin_unlock(&cache_lock);
                arch_pause();
                continue;
            }

            entry->refs++;
            cache_touch_locked(entry);
            spin_unlock(&cache_lock);
            if (fresh)
                cache_entry_destroy(fresh);
            return entry;
        }

        spin_unlock(&cache_lock);

        if (!create)
            return NULL;

        if (!fresh) {
            fresh = cache_entry_alloc(kind, key0, key1);
            if (!fresh)
                return NULL;
        }

        spin_lock(&cache_lock);

        entry = cache_lookup_locked(kind, key0, key1);
        if (entry) {
            spin_unlock(&cache_lock);
            continue;
        }

        fresh->loading = true;
        fresh->refs = 1;
        fresh->detached = false;
        hlist_add(&cache_buckets[cache_bucket_index(kind, key0, key1)],
                  &fresh->bucket_node);
        cache_touch_locked(fresh);
        spin_unlock(&cache_lock);

        if (created)
            *created = true;
        return fresh;
    }
}

static void cache_invalidate_exact(cache_kind_t kind, uint64_t key0,
                                   uint64_t key1) {
    cache_entry_t *to_free = NULL;

    spin_lock(&cache_lock);

    cache_entry_t *entry = cache_lookup_locked(kind, key0, key1);
    if (entry) {
        cache_detach_locked(entry);
        if (entry->refs == 0 && !entry->loading)
            to_free = entry;
    }

    spin_unlock(&cache_lock);

    if (to_free)
        cache_entry_destroy(to_free);
}

static int cache_writeback_entry(cache_entry_t *entry) {
    if (!entry || entry->kind != CACHE_KIND_PAGE)
        return -EINVAL;

    vfs_node_t *node = (vfs_node_t *)(uintptr_t)entry->key0;
    if (!node || !node->i_fop || !node->i_fop->write)
        return -EINVAL;

    uint64_t page_base = entry->key1 * PAGE_SIZE;
    size_t write_len = 0;
    uint64_t writeback_seq = 0;
    void *bounce = malloc(PAGE_SIZE);
    if (!bounce)
        return -ENOMEM;

    spin_lock(&cache_lock);
    if (entry->detached || !entry->dirty) {
        spin_unlock(&cache_lock);
        free(bounce);
        return 0;
    }

    entry->writeback = true;
    entry->writeback_seq = entry->dirty_seq;
    writeback_seq = entry->writeback_seq;
    write_len = MIN(entry->valid_bytes, (size_t)PAGE_SIZE);
    if (write_len)
        memcpy(bounce, entry->data, write_len);
    spin_unlock(&cache_lock);

    if (write_len != 0) {
        size_t written = 0;
        fd_t fd = {
            .f_op = node->i_fop,
            .f_inode = node,
            .node = node,
            .f_flags = O_WRONLY,
        };
        loff_t pos = (loff_t)page_base;

        while (written < write_len) {
            ssize_t ret = vfs_write_file(&fd, (uint8_t *)bounce + written,
                                         write_len - written, &pos);
            if (ret <= 0) {
                spin_lock(&cache_lock);
                entry->writeback = false;
                spin_unlock(&cache_lock);
                free(bounce);
                return ret < 0 ? (int)ret : -EIO;
            }
            written += (size_t)ret;
        }
    }

    int sync_ret = vfs_fsync_file(&(fd_t){
        .f_op = node->i_fop,
        .f_inode = node,
        .node = node,
    });

    spin_lock(&cache_lock);
    if (sync_ret < 0) {
        entry->writeback = false;
    } else {
        if (entry->dirty_seq == writeback_seq)
            entry->dirty = false;
        entry->writeback = false;
        if (!entry->detached)
            cache_touch_locked(entry);
    }
    spin_unlock(&cache_lock);
    free(bounce);
    return sync_ret;
}

static void cache_invalidate_range(cache_kind_t kind, uint64_t key0,
                                   uint64_t start_offset, uint64_t len) {
    if (len == 0)
        return;

    uint64_t end_offset = start_offset + len - 1;
    if (end_offset < start_offset)
        end_offset = UINT64_MAX;

    uint64_t first = start_offset / PAGE_SIZE;
    uint64_t last = end_offset / PAGE_SIZE;

    for (uint64_t page = first; page <= last; page++) {
        cache_invalidate_exact(kind, key0, page);
        if (page == UINT64_MAX)
            break;
    }
}

cache_entry_t *cache_block_try_get(uint64_t drive, uint64_t page_index) {
    return cache_get_common(CACHE_KIND_BLOCK, drive, page_index, false, NULL);
}

cache_entry_t *cache_block_get_or_create(uint64_t drive, uint64_t page_index,
                                         bool *created) {
    return cache_get_common(CACHE_KIND_BLOCK, drive, page_index, true, created);
}

void *cache_entry_data(cache_entry_t *entry) {
    return entry ? entry->data : NULL;
}

size_t cache_entry_valid_bytes(const cache_entry_t *entry) {
    return entry ? entry->valid_bytes : 0;
}

void cache_entry_mark_ready(cache_entry_t *entry, size_t valid_bytes) {
    if (!entry)
        return;

    spin_lock(&cache_lock);
    entry->valid_bytes = MIN(valid_bytes, (size_t)PAGE_SIZE);
    entry->loading = false;
    if (!entry->detached)
        cache_touch_locked(entry);
    spin_unlock(&cache_lock);
}

void cache_entry_abort_fill(cache_entry_t *entry) {
    cache_entry_t *to_free = NULL;

    if (!entry)
        return;

    spin_lock(&cache_lock);
    entry->loading = false;
    cache_detach_locked(entry);
    if (entry->refs == 0)
        to_free = entry;
    spin_unlock(&cache_lock);

    if (to_free)
        cache_entry_destroy(to_free);
}

void cache_entry_put(cache_entry_t *entry) {
    cache_entry_t *to_free = NULL;

    if (!entry)
        return;

    spin_lock(&cache_lock);
    if (entry->refs > 0)
        entry->refs--;
    if (entry->refs == 0 && entry->detached && !entry->loading)
        to_free = entry;
    spin_unlock(&cache_lock);

    if (to_free)
        cache_entry_destroy(to_free);
}

void cache_block_invalidate_range(uint64_t drive, uint64_t start_offset,
                                  uint64_t len) {
    cache_invalidate_range(CACHE_KIND_BLOCK, drive, start_offset, len);
}

void cache_block_drop_drive(uint64_t drive) {
    while (true) {
        cache_entry_t *target = NULL;
        bool found = false;

        spin_lock(&cache_lock);

        struct llist_header *pos;
        for (pos = cache_lru.next; pos != &cache_lru; pos = pos->next) {
            cache_entry_t *entry = container_of(pos, cache_entry_t, lru_node);
            if (!entry->detached && entry->kind == CACHE_KIND_BLOCK &&
                entry->key0 == drive) {
                cache_detach_locked(entry);
                if (entry->refs == 0 && !entry->loading)
                    target = entry;
                found = true;
                break;
            }
        }

        spin_unlock(&cache_lock);

        if (target)
            cache_entry_destroy(target);
        if (!found)
            break;
    }
}

static bool cache_buffer_is_userspace(const void *buf, size_t len) {
    return buf && !check_user_overflow((uint64_t)buf, len);
}

static bool cache_copy_to_target(void *dst, const void *src, size_t len,
                                 bool dst_is_userspace) {
    if (len == 0)
        return true;

    if (dst_is_userspace)
        return !copy_to_user(dst, src, len);

    memcpy(dst, src, len);
    return true;
}

static bool cache_copy_from_source(void *dst, const void *src, size_t len,
                                   bool src_is_userspace) {
    if (len == 0)
        return true;

    if (src_is_userspace)
        return !copy_from_user(dst, src, len);

    memcpy(dst, src, len);
    return true;
}

void cache_get_stats(cache_stats_t *stats) {
    if (!stats)
        return;

    memset(stats, 0, sizeof(*stats));

    spin_lock(&cache_lock);

    struct llist_header *pos;
    for (pos = cache_lru.next; pos != &cache_lru; pos = pos->next) {
        cache_entry_t *entry = container_of(pos, cache_entry_t, lru_node);
        if (entry->detached)
            continue;

        if (entry->kind == CACHE_KIND_BLOCK)
            stats->block_pages++;
        else if (entry->kind == CACHE_KIND_PAGE)
            stats->page_pages++;

        if (entry->dirty)
            stats->dirty_pages++;
        if (entry->writeback)
            stats->writeback_pages++;
    }

    spin_unlock(&cache_lock);
}

size_t cache_reclaim_pages(size_t target_pages) {
    size_t reclaimed = 0;

    if (target_pages == 0)
        target_pages = 1;

    while (reclaimed < target_pages) {
        cache_entry_t *victim = NULL;
        int ret = 0;

        spin_lock(&cache_lock);

        struct llist_header *pos;
        for (pos = cache_lru.prev; pos != &cache_lru; pos = pos->prev) {
            cache_entry_t *entry = container_of(pos, cache_entry_t, lru_node);
            if (entry->detached || entry->loading || entry->refs != 0 ||
                entry->writeback)
                continue;

            entry->refs++;
            victim = entry;
            break;
        }

        spin_unlock(&cache_lock);

        if (!victim)
            break;

        if (victim->dirty) {
            ret = cache_writeback_entry(victim);
            if (ret < 0) {
                cache_entry_put(victim);
                break;
            }
        }

        bool destroy = false;

        spin_lock(&cache_lock);
        if (!victim->detached && victim->refs == 1 && !victim->dirty &&
            !victim->writeback) {
            cache_detach_locked(victim);
        }
        if (victim->refs > 0)
            victim->refs--;
        destroy = victim->detached && victim->refs == 0 && !victim->loading;
        spin_unlock(&cache_lock);

        if (!destroy)
            continue;

        cache_entry_destroy(victim);
        reclaimed++;
    }

    return reclaimed;
}

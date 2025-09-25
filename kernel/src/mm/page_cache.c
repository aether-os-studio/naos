#include <mm/page_cache.h>
#include <fs/vfs/vfs.h>

// 哈希函数
static size_t hash_string(const char *str, size_t bucket_count) {
    size_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % bucket_count;
}

// 创建新节点
static cache_node_t *create_node(const char *key) {
    cache_node_t *node = malloc(sizeof(cache_node_t));
    if (!node)
        return NULL;

    node->key = malloc(strlen(key) + 1);
    if (!node->key) {
        free(node);
        return NULL;
    }
    strcpy(node->key, key);

    node->virtual_addr = NULL;
    node->data_size = 0;
    node->dirty = false;
    node->prev = NULL;
    node->next = NULL;

    return node;
}

// 释放节点
static void free_node(cache_node_t *node) {
    if (node) {
        if (node->key)
            free(node->key);
        free(node);
    }
}

// 初始化链表
static void list_init(cache_list_t *list) {
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
}

// 向链表尾部添加节点
static void list_push_back(cache_list_t *list, cache_node_t *node) {
    if (!list->head) {
        list->head = list->tail = node;
        node->prev = node->next = NULL;
    } else {
        list->tail->next = node;
        node->prev = list->tail;
        node->next = NULL;
        list->tail = node;
    }
    list->size++;
}

// 从链表中移除节点
static void list_remove(cache_list_t *list, cache_node_t *node) {
    if (node->prev) {
        node->prev->next = node->next;
    } else {
        list->head = node->next;
    }

    if (node->next) {
        node->next->prev = node->prev;
    } else {
        list->tail = node->prev;
    }

    list->size--;
    node->prev = node->next = NULL;
}

// 移动节点到链表尾部
static void list_move_to_end(cache_list_t *list, cache_node_t *node) {
    if (list->tail == node)
        return;

    list_remove(list, node);
    list_push_back(list, node);
}

// 获取链表头部节点
static cache_node_t *list_front(cache_list_t *list) { return list->head; }

// 弹出链表头部节点
static cache_node_t *list_pop_front(cache_list_t *list) {
    if (!list->head)
        return NULL;

    cache_node_t *node = list->head;
    list_remove(list, node);
    return node;
}

// 创建哈希表
static hash_table_t *hash_table_create(size_t bucket_count) {
    hash_table_t *table = malloc(sizeof(hash_table_t));
    if (!table)
        return NULL;

    table->buckets = calloc(bucket_count, sizeof(hash_entry_t *));
    if (!table->buckets) {
        free(table);
        return NULL;
    }

    table->bucket_count = bucket_count;
    return table;
}

// 哈希表查找
static hash_entry_t *hash_table_find(hash_table_t *table, const char *key) {
    size_t index = hash_string(key, table->bucket_count);
    hash_entry_t *entry = table->buckets[index];

    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

// 哈希表插入/更新
static int hash_table_set(hash_table_t *table, const char *key,
                          cache_node_t *node, int cache_list_type) {
    hash_entry_t *entry = hash_table_find(table, key);

    if (entry) {
        entry->node = node;
        entry->cache_list_type = cache_list_type;
        return 1;
    }

    // 创建新条目
    entry = malloc(sizeof(hash_entry_t));
    if (!entry)
        return 0;

    entry->key = strdup(key);

    entry->node = node;
    entry->cache_list_type = cache_list_type;

    size_t index = hash_string(key, table->bucket_count);
    entry->next = table->buckets[index];
    table->buckets[index] = entry;

    return 1;
}

// 哈希表删除
static void hash_table_remove(hash_table_t *table, const char *key) {
    size_t index = hash_string(key, table->bucket_count);
    hash_entry_t *entry = table->buckets[index];
    hash_entry_t *prev = NULL;

    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            if (prev) {
                prev->next = entry->next;
            } else {
                table->buckets[index] = entry->next;
            }

            free(entry->key);
            free(entry);
            return;
        }
        prev = entry;
        entry = entry->next;
    }
}

// 销毁哈希表
static void hash_table_destroy(hash_table_t *table) {
    if (!table)
        return;

    for (size_t i = 0; i < table->bucket_count; i++) {
        hash_entry_t *entry = table->buckets[i];
        while (entry) {
            hash_entry_t *next = entry->next;
            free(entry->key);
            free(entry);
            entry = next;
        }
    }

    free(table->buckets);
    free(table);
}

void write_back_if_dirty(arc_cache_t *cache, cache_node_t *node) {
    char *path = node->key;
    vfs_node_t file = vfs_open_at(rootdir, (const char *)path);
    if (!file)
        return;
    fd_t fd;
    fd.node = file;
    fd.offset = 0;
    fd.flags = 0;
    fs_callbacks[file->fsid]->write(&fd, node->virtual_addr, 0,
                                    node->data_size);
}

// 创建ARC缓存
arc_cache_t *arc_cache_create(size_t capacity) {
    arc_cache_t *cache = malloc(sizeof(arc_cache_t));
    if (!cache)
        return NULL;

    cache->capacity = capacity;
    cache->p = 0;

    list_init(&cache->T1);
    list_init(&cache->T2);
    list_init(&cache->B1);
    list_init(&cache->B2);

    cache->hash_table = hash_table_create(capacity * 4);
    if (!cache->hash_table) {
        free(cache);
        return NULL;
    }

    return cache;
}

// 替换策略
static void arc_replace(arc_cache_t *cache) {
    cache_node_t *node;

    if (cache->T1.size >= 1 &&
        ((cache->T1.size > cache->p) ||
         (cache->B2.size > 0 && cache->T1.size == cache->p))) {

        // 从T1移除最旧的
        node = list_pop_front(&cache->T1);
        if (node) {
            // 释放实际内存
            if (node->virtual_addr) {
                free_frames_bytes(node->virtual_addr, node->data_size);
            }

            // 移动到B1 (只保留key)
            cache_node_t *ghost_node = create_node(node->key);
            if (ghost_node) {
                list_push_back(&cache->B1, ghost_node);
                hash_table_set(cache->hash_table, node->key, ghost_node,
                               3); // B1
            }

            hash_table_remove(cache->hash_table, node->key);
            free_node(node);
        }
    } else {
        // 从T2移除最旧的
        node = list_pop_front(&cache->T2);
        if (node) {
            // 释放实际内存
            if (node->virtual_addr) {
                free_frames_bytes(node->virtual_addr, node->data_size);
            }

            // 移动到B2 (只保留key)
            cache_node_t *ghost_node = create_node(node->key);
            if (ghost_node) {
                list_push_back(&cache->B2, ghost_node);
                hash_table_set(cache->hash_table, node->key, ghost_node,
                               4); // B2
            }

            hash_table_remove(cache->hash_table, node->key);
            free_node(node);
        }
    }

    // 限制ghost列表大小
    while (cache->B1.size > cache->capacity) {
        node = list_pop_front(&cache->B1);
        if (node) {
            hash_table_remove(cache->hash_table, node->key);
            free_node(node);
        }
    }

    while (cache->B2.size > cache->capacity) {
        node = list_pop_front(&cache->B2);
        if (node) {
            hash_table_remove(cache->hash_table, node->key);
            free_node(node);
        }
    }
}

// 获取缓存项
void *arc_cache_get(arc_cache_t *cache, const char *key, size_t *data_size) {
    if (!cache || !key)
        return NULL;

    hash_entry_t *entry = hash_table_find(cache->hash_table, key);
    if (!entry)
        return NULL;

    // Case I: 在T1中找到
    if (entry->cache_list_type == 1) {
        cache_node_t *node = entry->node;
        // 移动到T2
        list_remove(&cache->T1, node);
        list_push_back(&cache->T2, node);
        hash_table_set(cache->hash_table, key, node, 2); // T2

        if (data_size)
            *data_size = node->data_size;
        return node->virtual_addr;
    }

    // Case II: 在T2中找到
    if (entry->cache_list_type == 2) {
        cache_node_t *node = entry->node;
        // 更新访问顺序
        list_move_to_end(&cache->T2, node);

        if (data_size)
            *data_size = node->data_size;
        return node->virtual_addr;
    }

    return NULL;
}

// 插入缓存项
int arc_cache_put(arc_cache_t *cache, const char *key, const void *data,
                  size_t data_size) {
    if (!cache || !key || !data)
        return 0;

    hash_entry_t *entry = hash_table_find(cache->hash_table, key);

    // Case I: 在T1或T2中找到（更新操作）
    if (entry && (entry->cache_list_type == 1 || entry->cache_list_type == 2)) {
        cache_node_t *node = entry->node;

        // 释放旧内存
        if (node->virtual_addr) {
            free_frames_bytes(node->virtual_addr, node->data_size);
        }

        // 分配新内存
        node->virtual_addr = alloc_frames_bytes(data_size);
        if (!node->virtual_addr)
            return 0;

        // 复制数据（这里假设可以直接memcpy到虚拟地址）
        memcpy(node->virtual_addr, data, data_size);
        node->data_size = data_size;
        node->dirty = true;

        if (entry->cache_list_type == 1) {
            // 从T1移动到T2
            list_remove(&cache->T1, node);
            list_push_back(&cache->T2, node);
            hash_table_set(cache->hash_table, key, node, 2); // T2
        } else {
            // 在T2中更新访问顺序
            list_move_to_end(&cache->T2, node);
        }
        return 1;
    }

    // Case II: 在B1中找到
    if (entry && entry->cache_list_type == 3) {
        // 增加p值
        size_t delta =
            cache->B2.size > 0
                ? (cache->B1.size > 0 ? cache->B2.size / cache->B1.size : 1)
                : 1;
        if (delta < 1)
            delta = 1;
        cache->p = (cache->p + delta < cache->capacity) ? cache->p + delta
                                                        : cache->capacity;

        // 如果需要，进行替换
        if (cache->T1.size + cache->T2.size >= cache->capacity) {
            arc_replace(cache);
        }

        // 从B1移除ghost节点
        list_remove(&cache->B1, entry->node);
        free_node(entry->node);

        // 创建新节点并添加到T2
        cache_node_t *node = create_node(key);
        if (!node)
            return 0;

        node->virtual_addr = alloc_frames_bytes(data_size);
        if (!node->virtual_addr) {
            free_node(node);
            return 0;
        }

        memcpy(node->virtual_addr, data, data_size);
        node->data_size = data_size;
        node->dirty = true;

        list_push_back(&cache->T2, node);
        hash_table_set(cache->hash_table, key, node, 2); // T2
        return 1;
    }

    // Case III: 在B2中找到
    if (entry && entry->cache_list_type == 4) {
        // 减少p值
        size_t delta =
            cache->B1.size > 0
                ? (cache->B2.size > 0 ? cache->B1.size / cache->B2.size : 1)
                : 1;
        if (delta < 1)
            delta = 1;
        cache->p = (cache->p >= delta) ? cache->p - delta : 0;

        // 如果需要，进行替换
        if (cache->T1.size + cache->T2.size >= cache->capacity) {
            arc_replace(cache);
        }

        // 从B2移除ghost节点
        list_remove(&cache->B2, entry->node);
        free_node(entry->node);

        // 创建新节点并添加到T2
        cache_node_t *node = create_node(key);
        if (!node)
            return 0;

        node->virtual_addr = alloc_frames_bytes(data_size);
        if (!node->virtual_addr) {
            free_node(node);
            return 0;
        }

        memcpy(node->virtual_addr, data, data_size);
        node->data_size = data_size;
        node->dirty = true;

        list_push_back(&cache->T2, node);
        hash_table_set(cache->hash_table, key, node, 2); // T2
        return 1;
    }

    // Case IV: 完全新的key
    if (cache->T1.size + cache->T2.size >= cache->capacity) {
        arc_replace(cache);
    }

    cache_node_t *node = create_node(key);
    if (!node)
        return 0;

    node->virtual_addr = alloc_frames_bytes(data_size);
    if (!node->virtual_addr) {
        free_node(node);
        return 0;
    }

    memcpy(node->virtual_addr, data, data_size);
    node->data_size = data_size;
    node->dirty = true;

    list_push_back(&cache->T1, node);
    hash_table_set(cache->hash_table, key, node, 1); // T1
    return 1;
}

// 删除缓存项
int arc_cache_delete(arc_cache_t *cache, const char *key) {
    if (!cache || !key)
        return 0;

    hash_entry_t *entry = hash_table_find(cache->hash_table, key);
    if (!entry)
        return 0;

    cache_node_t *node = entry->node;

    if (entry->cache_list_type == 1 || entry->cache_list_type == 2) {
        write_back_if_dirty(cache, node);
    }

    if (entry->cache_list_type == 1) {
        list_remove(&cache->T1, node);
    } else if (entry->cache_list_type == 2) {
        list_remove(&cache->T2, node);
    } else if (entry->cache_list_type == 3) {
        list_remove(&cache->B1, node);
    } else if (entry->cache_list_type == 4) {
        list_remove(&cache->B2, node);
    }

    if (node->virtual_addr) {
        free_frames_bytes(node->virtual_addr, node->data_size);
    }

    hash_table_remove(cache->hash_table, key);
    free_node(node);
    return 1;
}

// 获取缓存统计信息
typedef struct {
    size_t T1_size;
    size_t T2_size;
    size_t B1_size;
    size_t B2_size;
    size_t target_T1_size;
    size_t capacity;
} arc_cache_stats_t;

void arc_cache_get_stats(arc_cache_t *cache, arc_cache_stats_t *stats) {
    if (!cache || !stats)
        return;

    stats->T1_size = cache->T1.size;
    stats->T2_size = cache->T2.size;
    stats->B1_size = cache->B1.size;
    stats->B2_size = cache->B2.size;
    stats->target_T1_size = cache->p;
    stats->capacity = cache->capacity;
}

// 清空缓存
void arc_cache_clear(arc_cache_t *cache) {
    if (!cache)
        return;

    cache_node_t *node;

    // 清空T1
    while ((node = list_pop_front(&cache->T1))) {
        write_back_if_dirty(cache, node);
        if (node->virtual_addr) {
            free_frames_bytes(node->virtual_addr, node->data_size);
        }
        free_node(node);
    }

    // 清空T2
    while ((node = list_pop_front(&cache->T2))) {
        if (node->virtual_addr) {
            free_frames_bytes(node->virtual_addr, node->data_size);
        }
        free_node(node);
    }

    // 清空B1
    while ((node = list_pop_front(&cache->B1))) {
        free_node(node);
    }

    // 清空B2
    while ((node = list_pop_front(&cache->B2))) {
        free_node(node);
    }

    // 清空哈希表
    hash_table_destroy(cache->hash_table);
    cache->hash_table = hash_table_create(cache->capacity * 4);

    cache->p = 0;
}

void arc_cache_mark_dirty(arc_cache_t *cache, const char *key) {
    if (!cache || !key)
        return;

    hash_entry_t *entry = hash_table_find(cache->hash_table, key);
    if (entry && (entry->cache_list_type == 1 || entry->cache_list_type == 2)) {
        entry->node->dirty = 1;
    }
}

void arc_cache_flush(arc_cache_t *cache, const char *key) {
    if (!cache || !key)
        return;

    hash_entry_t *entry = hash_table_find(cache->hash_table, key);
    if (entry && (entry->cache_list_type == 1 || entry->cache_list_type == 2)) {
        write_back_if_dirty(cache, entry->node);
    }
}

// 销毁缓存
void arc_cache_destroy(arc_cache_t *cache) {
    if (!cache)
        return;

    arc_cache_clear(cache);
    hash_table_destroy(cache->hash_table);
    free(cache);
}

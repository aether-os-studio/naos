#pragma once

#include <libs/klibc.h>
#include <mm/mm.h>

#define ARC_CACHE_CAPABILITY 1024

// 缓存节点结构
typedef struct cache_node {
    char *key;
    void *virtual_addr; // 虚拟地址
    size_t data_size;   // 数据大小
    bool dirty;
    struct cache_node *prev;
    struct cache_node *next;
} cache_node_t;

// 双向链表结构
typedef struct cache_list {
    cache_node_t *head;
    cache_node_t *tail;
    size_t size;
} cache_list_t;

// 哈希表条目
typedef struct hash_entry {
    char *key;
    cache_node_t *node;  // 指向T1或T2中的节点
    int cache_list_type; // 0=none, 1=T1, 2=T2, 3=B1, 4=B2
    struct hash_entry *next;
} hash_entry_t;

// 哈希表
typedef struct hash_table {
    hash_entry_t **buckets;
    size_t bucket_count;
} hash_table_t;

// ARC缓存结构
typedef struct arc_cache {
    size_t capacity;
    size_t p; // T1的目标大小

    cache_list_t T1; // 最近访问过一次的页面
    cache_list_t T2; // 最近访问过至少两次的页面
    cache_list_t B1; // 从T1中被驱逐的页面ID (ghost entries)
    cache_list_t B2; // 从T2中被驱逐的页面ID (ghost entries)

    hash_table_t *hash_table;
} arc_cache_t;

arc_cache_t *arc_cache_create(size_t capacity);
void *arc_cache_get(arc_cache_t *cache, const char *key, size_t *data_size);
int arc_cache_put(arc_cache_t *cache, const char *key, const void *data,
                  size_t data_size);
int arc_cache_delete(arc_cache_t *cache, const char *key);
void arc_cache_flush(arc_cache_t *cache, const char *key);
void arc_cache_mark_dirty(arc_cache_t *cache, const char *key);

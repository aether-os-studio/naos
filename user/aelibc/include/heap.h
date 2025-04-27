#pragma once

#include <stdint.h>

#define MIN_ALLOC_SZ 4

#define MIN_WILDERNESS 0x2000
#define MAX_WILDERNESS 0x1000000

#define HEAP_INIT_SIZE 0x400000

#define BIN_COUNT 64
#define BIN_MAX_IDX (BIN_COUNT - 1)

typedef unsigned int uint;

typedef struct node_t
{
    uint hole;
    uint size;
    struct node_t *next;
    struct node_t *prev;
} node_t;

typedef struct
{
    node_t *header;
} footer_t;

typedef struct
{
    node_t *head;
} bin_t;

typedef struct
{
    uint64_t start;
    uint64_t end;
    bin_t *bins[BIN_COUNT];
} heap_t;

void heap_init();

void init_heap(heap_t *heap, uint64_t start, uint64_t size);

void *heap_alloc(heap_t *heap, size_t size);
void heap_free(heap_t *heap, void *p);
uint expand(heap_t *heap, size_t sz);
void contract(heap_t *heap, size_t sz);

uint get_bin_index(size_t sz);
void create_foot(node_t *head);
footer_t *get_foot(node_t *head);

node_t *get_wilderness(heap_t *heap);

void *malloc(size_t size);
void free(void *ptr);
void *realloc(void *ptr, size_t size);

void add_node(bin_t *bin, node_t *node);

void remove_node(bin_t *bin, node_t *node);

node_t *get_best_fit(bin_t *list, size_t size);
node_t *get_last_node(bin_t *list);
node_t *prev(node_t *current);

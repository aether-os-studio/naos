#include <libsyscall.h>
#include <string.h>
#include <heap.h>

static uint32_t overhead = sizeof(footer_t) + sizeof(node_t);

heap_t uheap;

void *heap_end = NULL;

void *brk(void *addr)
{
    return (void *)enter_syscall((uint64_t)addr, 0, 0, 0, 0, SYS_BRK);
}

void heap_init()
{
    heap_end = brk(heap_end);
    void *new_heap_end = brk(heap_end + HEAP_INIT_SIZE);

    init_heap(&uheap, (uint64_t)heap_end, HEAP_INIT_SIZE);

    heap_end = new_heap_end;
}

uint32_t offset = 8;

void init_heap(heap_t *heap, uint64_t start, uint64_t size)
{
    memset(heap, 0, sizeof(heap_t));

    uint64_t addition_len = 0;
    for (int i = 0; i < BIN_COUNT; i++)
    {
        heap->bins[i] = (bin_t *)start;
        memset(heap->bins[i], 0, sizeof(bin_t));
        start += sizeof(bin_t);
        addition_len += sizeof(bin_t);
    }

    node_t *init_region = (node_t *)start;
    init_region->hole = 1;
    init_region->size = size - addition_len - sizeof(node_t) - sizeof(footer_t);

    create_foot(init_region);

    add_node(heap->bins[get_bin_index(init_region->size)], init_region);

    heap->start = (uint64_t)start;
    heap->end = (uint64_t)(start + size - addition_len);
}

void *heap_alloc(heap_t *heap, size_t size)
{
    uint index = get_bin_index(size);
    bin_t *temp = (bin_t *)heap->bins[index];
    node_t *found = get_best_fit(temp, size);

    while (found == NULL)
    {
        if (index + 1 >= BIN_COUNT)
            return NULL;

        temp = heap->bins[++index];
        found = get_best_fit(temp, size);
    }

    if ((found->size - size) > (overhead + MIN_ALLOC_SZ))
    {
        node_t *split = (node_t *)(((char *)found + sizeof(node_t) + sizeof(footer_t)) + size);
        split->size = found->size - size - sizeof(node_t) - sizeof(footer_t);
        split->hole = 1;

        create_foot(split);

        uint new_idx = get_bin_index(split->size);

        add_node(heap->bins[new_idx], split);

        found->size = size;
        create_foot(found);
    }

    found->hole = 0;
    remove_node(heap->bins[index], found);

    node_t *wild = get_wilderness(heap);
    if (wild->size < MIN_WILDERNESS)
    {
        uint success = expand(heap, 0x8000);
        if (success == 0)
        {
            return NULL;
        }
    }
    else if (wild->size > MAX_WILDERNESS)
    {
        contract(heap, 0x1000);
    }

    found->prev = NULL;
    found->next = NULL;
    return (void *)&found->next;
}

void heap_free(heap_t *heap, void *p)
{
    bin_t *list;
    footer_t *new_foot, *old_foot;

    node_t *head = (node_t *)((char *)p - offset);
    if (head == (node_t *)(uintptr_t)heap->start)
    {
        head->hole = 1;
        add_node(heap->bins[get_bin_index(head->size)], head);
        return;
    }

    node_t *next = (node_t *)((char *)get_foot(head) + sizeof(footer_t));
    footer_t *f = (footer_t *)((char *)head - sizeof(footer_t));
    node_t *prev = f->header;

    if (prev->hole)
    {
        list = heap->bins[get_bin_index(prev->size)];
        remove_node(list, prev);

        prev->size += overhead + head->size;
        new_foot = get_foot(head);
        new_foot->header = prev;

        head = prev;
    }

    if (next->hole)
    {
        list = heap->bins[get_bin_index(next->size)];
        remove_node(list, next);

        head->size += overhead + next->size;

        old_foot = get_foot(next);
        old_foot->header = 0;
        next->size = 0;
        next->hole = 0;

        new_foot = get_foot(head);
        new_foot->header = head;
    }

    head->hole = 1;
    add_node(heap->bins[get_bin_index(head->size)], head);
}

uint expand(heap_t *heap, size_t sz)
{
    void *new_heap = heap_end + sz;
    brk(new_heap);

    return 1;
}

void contract(heap_t *heap, size_t sz)
{
    return;
}

uint get_bin_index(size_t sz)
{
    uint index = 0;
    sz = sz < 4 ? 4 : sz;

    while (sz >>= 1)
        index++;
    index -= 2;

    if (index > BIN_MAX_IDX)
        index = BIN_MAX_IDX;
    return index;
}

void create_foot(node_t *head)
{
    footer_t *foot = get_foot(head);
    foot->header = head;
}

footer_t *get_foot(node_t *node)
{
    return (footer_t *)((uint64_t)node + node->size + sizeof(node_t));
}

node_t *get_wilderness(heap_t *heap)
{
    footer_t *wild_foot = (footer_t *)((char *)heap->end - sizeof(footer_t));
    return wild_foot->header;
}

void *malloc(size_t size)
{
    return heap_alloc(&uheap, size);
}

void free(void *ptr)
{
    heap_free(&uheap, ptr);
}

void *realloc(void *ptr, size_t size)
{
    if (!ptr)
    {
        return malloc(size);
    }
    if (!size)
    {
        free(ptr);
        return 0;
    }

    node_t *node = (node_t *)((char *)ptr - offset);
    size_t len = (size_t)node->size;

    void *new_ptr = malloc(len);
    memcpy(new_ptr, ptr, len);
    free(ptr);

    return new_ptr;
}

void add_node(bin_t *bin, node_t *node);

void remove_node(bin_t *bin, node_t *node);

node_t *get_best_fit(bin_t *list, size_t size);
node_t *get_last_node(bin_t *list);

node_t *next(node_t *current);
node_t *prev(node_t *current);

void add_node(bin_t *bin, node_t *node)
{
    node->next = NULL;
    node->prev = NULL;

    if (bin->head == NULL)
    {
        bin->head = node;
        return;
    }

    // we need to save next and prev while we iterate
    node_t *current = bin->head;
    node_t *previous = NULL;
    // iterate until we get the the end of the list or we find a
    // node whose size is
    while (current != NULL && current->size <= node->size)
    {
        previous = current;
        current = current->next;
    }

    if (current == NULL)
    { // we reached the end of the list
        previous->next = node;
        node->prev = previous;
    }
    else
    {
        if (previous != NULL)
        { // middle of list, connect all links!
            node->next = current;
            previous->next = node;

            node->prev = previous;
            current->prev = node;
        }
        else
        { // head is the only element
            node->next = bin->head;
            bin->head->prev = node;
            bin->head = node;
        }
    }
}

void remove_node(bin_t *bin, node_t *node)
{
    if (bin->head == NULL)
        return;
    if (bin->head == node)
    {
        bin->head = bin->head->next;
        return;
    }

    node_t *temp = bin->head->next;
    while (temp != NULL)
    {
        if (temp == node)
        { // found the node
            if (temp->next == NULL)
            { // last item
                temp->prev->next = NULL;
            }
            else
            { // middle item
                temp->prev->next = temp->next;
                temp->next->prev = temp->prev;
            }
            // we dont worry about deleting the head here because we already checked that
            return;
        }
        temp = temp->next;
    }
}

node_t *get_best_fit(bin_t *bin, size_t size)
{
    if (bin->head == NULL)
        return NULL; // empty list!

    node_t *temp = bin->head;

    while (temp != NULL)
    {
        if (temp->size >= size)
        {
            return temp; // found a fit!
        }
        temp = temp->next;
    }
    return NULL; // no fit!
}

node_t *get_last_node(bin_t *bin)
{
    node_t *temp = bin->head;

    while (temp->next != NULL)
    {
        temp = temp->next;
    }
    return temp;
}

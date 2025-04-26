#include <libsyscall.h>
#include <string.h>

#define ALIGNMENT 8 // 内存对齐单位（通常与 sizeof(void*) 一致）
#define HEADER_SIZE sizeof(struct Block)

// 内存块头部结构
struct Block
{
    size_t size;        // 块大小（包括头部）
    int free;           // 是否空闲
    struct Block *next; // 空闲链表指针
};

static struct Block *free_list = NULL; // 空闲块链表头
static void *heap_start = NULL;        // 堆起始地址
static void *heap_end = NULL;          // 堆结束地址

void *brk(uint64_t addr)
{
    return (void *)enter_syscall(addr, 0, 0, 0, 0, SYS_BRK);
}

// 初始化堆
void init_heap()
{
    if (!heap_start)
    {
        heap_start = brk(0); // 获取当前堆起始地址
        heap_end = heap_start;
    }
}

// 扩展堆
void *extend_heap(size_t size)
{
    void *new_end = brk((uint64_t)heap_end + size);
    heap_end = new_end;
    return heap_end - size; // 返回新分配区域的起始地址
}

// 合并空闲块
static void merge_blocks(struct Block *block)
{
    if (block->next && block->next->free)
    {
        block->size += block->next->size;
        block->next = block->next->next;
    }
}

// 分配内存
void *malloc(size_t size)
{
    // 对齐内存大小
    size = (size + ALIGNMENT - 1) / ALIGNMENT * ALIGNMENT;
    size_t total_size = size + HEADER_SIZE;

    struct Block *prev = NULL;
    struct Block *curr = free_list;

    // 遍历空闲链表寻找合适块
    while (curr)
    {
        if (curr->free && curr->size >= total_size)
        {
            // 分割块（如果剩余空间足够大）
            if (curr->size > total_size + HEADER_SIZE)
            {
                struct Block *new_block = (struct Block *)((char *)curr + total_size);
                new_block->size = curr->size - total_size;
                new_block->free = 1;
                new_block->next = curr->next;

                curr->size = total_size;
                curr->next = new_block;

                if (prev)
                    prev->next = new_block;
                else
                    free_list = new_block;
            }
            else
            {
                if (prev)
                    prev->next = curr->next;
                else
                    free_list = curr->next;
            }

            curr->free = 0;
            return (void *)(curr + 1); // 返回数据区域地址
        }
        prev = curr;
        curr = curr->next;
    }

    // 没有合适块，扩展堆
    void *new_block = extend_heap(total_size);
    struct Block *block = (struct Block *)new_block;
    block->size = total_size;
    block->free = 0;
    block->next = free_list; // 插入链表头部
    free_list = block;

    return (void *)(block + 1);
}

// 释放内存
void free(void *ptr)
{
    if (!ptr)
        return;

    struct Block *block = (struct Block *)ptr - 1;
    block->free = 1;

    // 尝试合并前后空闲块
    if (block->next && block->next->free)
    {
        block->size += block->next->size;
        block->next = block->next->next;
    }

    // 检查前一个块是否可以合并（需要遍历链表）
    struct Block *curr = free_list;
    while (curr && curr->next != block)
        curr = curr->next;
    if (curr && curr->free)
    {
        curr->size += block->size;
        curr->next = block->next;
        block = curr;
    }
}

// 重新分配内存
void *realloc(void *ptr, size_t new_size)
{
    if (!ptr)
        return malloc(new_size);
    if (new_size == 0)
    {
        free(ptr);
        return NULL;
    }

    struct Block *block = (struct Block *)ptr - 1;
    size_t old_size = block->size - HEADER_SIZE;
    size_t total_new_size = (new_size + ALIGNMENT - 1) / ALIGNMENT * ALIGNMENT + HEADER_SIZE;

    // 如果当前块足够大，直接返回
    if (block->size >= total_new_size)
        return ptr;

    // 分配新块并复制数据
    void *new_ptr = malloc(new_size);
    if (new_ptr)
    {
        memcpy(new_ptr, ptr, old_size < new_size ? old_size : new_size);
        free(ptr);
    }
    return new_ptr;
}

#include <arch/arch.h>
#include <mm/mm.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// 链表节点结构
typedef struct linked_list
{
    struct linked_list *next;
    struct linked_list *prev;
    uint64_t data;
} linked_list_t;

// 链表初始化
static inline void list_init(linked_list_t *list)
{
    list->next = list;
    list->prev = list;
    list->data = 0;
}

// 检查链表是否为空
static inline bool list_empty(linked_list_t *list)
{
    return list->next == list;
}

// 在链表尾部添加节点
static inline void list_add_tail(linked_list_t *head, linked_list_t *node)
{
    node->prev = head->prev;
    node->next = head;
    head->prev->next = node;
    head->prev = node;
}

// 从链表中移除节点
static inline void list_remove(linked_list_t *node)
{
    if (node->prev)
        node->prev->next = node->next;
    if (node->next)
        node->next->prev = node->prev;
    node->next = node->prev = NULL;
}

// 遍历链表宏
#define list_foreach(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

// 伙伴系统相关代码保持不变
__attribute__((used, section(".limine_requests"))) static volatile struct limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST,
    .revision = 0,
};

spinlock_t frame_op_lock = {0};

#define MAX_ORDER 31

typedef struct freearea freearea_t;

struct freearea
{
    linked_list_t next; // 链表头
    uint64_t nr;        // 空闲块数量
};

typedef struct buddy_allocator buddy_allocator_t;

struct buddy_allocator
{
    freearea_t areas[MAX_ORDER];
};

// 改进的链表节点管理
#define MAX_LINKED_LISTS_NUM 8192
static linked_list_t linked_lists[MAX_LINKED_LISTS_NUM];
static linked_list_t free_linked_lists; // 空闲链表头

buddy_allocator_t page_allocator;

// 初始化链表节点池
void init_linked_list_pool(void)
{
    list_init(&free_linked_lists);

    // 将所有节点加入空闲链表
    for (size_t i = 0; i < MAX_LINKED_LISTS_NUM; i++)
    {
        list_add_tail(&free_linked_lists, &linked_lists[i]);
    }
}

// 分配链表节点
linked_list_t *alloc_linked_list(void)
{
    if (list_empty(&free_linked_lists))
    {
        return NULL; // 没有可用节点
    }

    linked_list_t *node = free_linked_lists.next;
    list_remove(node);
    list_init(node);
    return node;
}

// 释放链表节点
void free_linked_list(linked_list_t *node)
{
    if (node == NULL)
        return;

    list_remove(node);
    list_add_tail(&free_linked_lists, node);
}

// 计算大于等于count的最小2的幂次对应的order
static uint64_t calculate_min_order(uint64_t count)
{
    if (count == 0)
        return 0;

    uint64_t order = 0;
    while ((1ULL << order) < count)
    {
        order++;
        if (order >= MAX_ORDER)
        {
            return MAX_ORDER - 1;
        }
    }
    return order;
}

// 计算count对应的最大order
static uint64_t calculate_max_order(uint64_t count)
{
    uint64_t order = 0;
    uint64_t c = count;
    while (c > 1)
    {
        c >>= 1;
        order++;
    }
    return (order < MAX_ORDER) ? order : (MAX_ORDER - 1);
}

// 添加物理内存页到伙伴系统
bool frame_addpages(uint64_t addr, uint64_t npages)
{
    uint64_t order = calculate_max_order(npages);
    uint64_t block_size = (1ULL << order); // 块大小（页数）

    // 如果剩余页数小于块大小，则减小order
    while (npages < block_size && order > 0)
    {
        order--;
        block_size = (1ULL << order);
    }

    // 分配链表节点并添加到对应order的空闲链表
    linked_list_t *node = alloc_linked_list();
    if (!node)
        return false;

    node->data = addr;
    list_add_tail(&page_allocator.areas[order].next, node);
    page_allocator.areas[order].nr++;

    // 处理剩余内存
    uint64_t remaining = npages - block_size;
    if (remaining > 0)
    {
        bool res = frame_addpages(addr + block_size * DEFAULT_PAGE_SIZE, remaining);
        if (!res)
            return false;
    }

    return true;
}

// 初始化物理内存管理器
void frame_init()
{
    // 初始化hhdm
    hhdm_init();

    // 初始化链表节点池
    init_linked_list_pool();

    // 初始化伙伴系统
    for (int i = 0; i < MAX_ORDER; i++)
    {
        list_init(&page_allocator.areas[i].next);
        page_allocator.areas[i].nr = 0;
    }

    // 处理内存映射项
    for (uint64_t i = 0; i < memmap_request.response->entry_count; i++)
    {
        if (memmap_request.response->entries[i]->type == LIMINE_MEMMAP_USABLE)
        {
            uint64_t base = memmap_request.response->entries[i]->base;
            uint64_t length = memmap_request.response->entries[i]->length;
            uint64_t npages = length / DEFAULT_PAGE_SIZE;

            if (!frame_addpages(base, npages))
            {
                while (1)
                    arch_pause();
            }
        }
    }
}

// 分配物理页框
uint64_t alloc_frames(uint64_t npages)
{
    spin_lock(&frame_op_lock);

    // 计算所需的最小order
    uint64_t order = calculate_min_order(npages);
    if (order >= MAX_ORDER)
    {
        spin_unlock(&frame_op_lock);
        return (uint64_t)-1; // 请求太大
    }

    // 尝试在所需order及以上找到空闲块
    int found_order = -1;
    for (int i = order; i < MAX_ORDER; i++)
    {
        if (!list_empty(&page_allocator.areas[i].next))
        {
            found_order = i;
            break;
        }
    }

    if (found_order == -1)
    {
        spin_unlock(&frame_op_lock);
        return (uint64_t)-1; // 没有可用内存
    }

    // 取出找到的空闲块
    linked_list_t *node = page_allocator.areas[found_order].next.next;
    list_remove(node);
    page_allocator.areas[found_order].nr--;
    uint64_t addr = node->data;
    free_linked_list(node);

    // 如果找到的块比需要的大，则进行分裂
    while (found_order > order)
    {
        found_order--; // 分裂后块的大小减半，order减1
        uint64_t half_size = (1ULL << found_order) * DEFAULT_PAGE_SIZE;
        uint64_t buddy_addr = addr + half_size;

        // 将分裂出的另一半加入对应order的链表
        linked_list_t *buddy_node = alloc_linked_list();
        if (!buddy_node)
        {
            // 处理链表节点不足的情况
            spin_unlock(&frame_op_lock);
            return (uint64_t)-1;
        }
        buddy_node->data = buddy_addr;
        list_add_tail(&page_allocator.areas[found_order].next, buddy_node);
        page_allocator.areas[found_order].nr++;
    }

    spin_unlock(&frame_op_lock);
    return addr;
}

// 释放物理页框
void free_frames(uint64_t addr, uint64_t npages)
{
    spin_lock(&frame_op_lock);

    // 计算块对应的order
    uint64_t order = calculate_min_order(npages);
    if (order >= MAX_ORDER)
    {
        spin_unlock(&frame_op_lock);
        return;
    }

    // 循环尝试合并伙伴块
    while (order < MAX_ORDER - 1)
    {
        // 计算伙伴块地址
        uint64_t block_size = (1ULL << order) * DEFAULT_PAGE_SIZE;
        uint64_t buddy_addr = addr ^ block_size; // 通过异或切换最高位

        // 在对应order链表中查找伙伴块
        bool found_buddy = false;
        linked_list_t *entry;

        list_foreach(entry, &page_allocator.areas[order].next)
        {
            if (entry->data == buddy_addr)
            {
                // 找到伙伴块，进行合并
                list_remove(entry);
                free_linked_list(entry);
                page_allocator.areas[order].nr--;

                // 合并后形成更大的块（取两个块中较小的地址）
                if (buddy_addr < addr)
                {
                    addr = buddy_addr;
                }

                order++; // 合并后order增加
                found_buddy = true;
                break;
            }
        }

        // 如果没有找到伙伴块，则停止合并
        if (!found_buddy)
            break;
    }

    // 将合并后的块加入对应order的链表
    linked_list_t *node = alloc_linked_list();
    if (!node)
    {
        // 处理链表节点不足的情况
        spin_unlock(&frame_op_lock);
        return;
    }

    node->data = addr;
    list_add_tail(&page_allocator.areas[order].next, node);
    page_allocator.areas[order].nr++;

    spin_unlock(&frame_op_lock);
}

// 内存映射相关函数保持不变
bool mem_map_op_lock = false;

void map_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t paddr, uint64_t size, uint64_t flags)
{
    while (mem_map_op_lock)
    {
        arch_pause();
    }

    mem_map_op_lock = true;

    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE)
    {
        if (paddr == 0)
        {
            uint64_t phys = alloc_frames(1);
            if (phys == (uint64_t)-1)
            {
                printk("Cannot allocate frame\n");
                break;
            }
            map_page(pml4, va, phys, get_arch_page_table_flags(flags));
        }
        else
        {
            map_page(pml4, va, paddr + (va - vaddr), get_arch_page_table_flags(flags));
        }
    }

    mem_map_op_lock = false;
}

void unmap_page_range(uint64_t *pml4, uint64_t vaddr, uint64_t size)
{
    while (mem_map_op_lock)
    {
        arch_pause();
    }

    mem_map_op_lock = true;

    for (uint64_t va = vaddr; va < vaddr + size; va += DEFAULT_PAGE_SIZE)
    {
        unmap_page(pml4, va);
    }

    mem_map_op_lock = false;
}

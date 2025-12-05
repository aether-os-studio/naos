#include <mm/slab.h>

#define MAX_SLAB_MALLOC_SIZE (2UL * 1024 * 1024)
#define MAX_SLAB_MALLOC_MASK ~(MAX_SLAB_MALLOC_SIZE - 1)

// 最大大小必须小于 MAX_SLAB_MALLOC_SIZE
struct slab_cache kmalloc_cache_size[16] = {
    {32, 0, 0, NULL, NULL, NULL, NULL},
    {64, 0, 0, NULL, NULL, NULL, NULL},
    {128, 0, 0, NULL, NULL, NULL, NULL},
    {256, 0, 0, NULL, NULL, NULL, NULL},
    {512, 0, 0, NULL, NULL, NULL, NULL},
    {1024, 0, 0, NULL, NULL, NULL, NULL}, // 1KB
    {2048, 0, 0, NULL, NULL, NULL, NULL},
    {4096, 0, 0, NULL, NULL, NULL, NULL}, // 4KB
    {8192, 0, 0, NULL, NULL, NULL, NULL},
    {16384, 0, 0, NULL, NULL, NULL, NULL},
    {32768, 0, 0, NULL, NULL, NULL, NULL},
    {65536, 0, 0, NULL, NULL, NULL, NULL},  // 64KB
    {131072, 0, 0, NULL, NULL, NULL, NULL}, // 128KB
    {262144, 0, 0, NULL, NULL, NULL, NULL},
    {524288, 0, 0, NULL, NULL, NULL, NULL},
    {1048576, 0, 0, NULL, NULL, NULL, NULL}, // 1MB
};

spinlock_t slab_lock = SPIN_INIT;

struct slab *kmalloc_create(uint64_t size);

void *malloc(size_t size) {
    spin_lock(&slab_lock);

    int i, j;
    struct slab *slab = NULL;
    if (size > kmalloc_cache_size[sizeof(kmalloc_cache_size) /
                                      sizeof(kmalloc_cache_size[0]) -
                                  1]
                   .size) {
        printk("malloc() ERROR: malloc size too long: %08d\n", size);
        spin_unlock(&slab_lock);
        return NULL;
    }
    for (i = 0; i < sizeof(kmalloc_cache_size) / sizeof(kmalloc_cache_size[0]);
         i++)
        if (kmalloc_cache_size[i].size >= size)
            break;
    slab = kmalloc_cache_size[i].cache_pool;

    if (kmalloc_cache_size[i].total_free != 0) {
        do {
            if (slab->free_count == 0)
                slab = container_of(slab->list.next, struct slab, list);
            else
                break;
        } while (slab != kmalloc_cache_size[i].cache_pool);
    } else {
        slab = kmalloc_create(kmalloc_cache_size[i].size);

        ASSERT(slab != NULL);

        kmalloc_cache_size[i].total_free += slab->color_count;

        llist_prepend(&kmalloc_cache_size[i].cache_pool->list, &slab->list);
    }

    for (j = 0; j < slab->color_count; j++) {
        if (*(slab->color_map + (j >> 6)) == 0xffffffffffffffffUL) {
            j += 63;
            continue;
        }

        if ((*(slab->color_map + (j >> 6)) & (1UL << (j % 64))) == 0) {
            *(slab->color_map + (j >> 6)) |= 1UL << (j % 64);
            slab->using_count++;
            slab->free_count--;

            kmalloc_cache_size[i].total_free--;
            kmalloc_cache_size[i].total_using++;

            spin_unlock(&slab_lock);

            return (void *)((char *)slab->v_address +
                            kmalloc_cache_size[i].size * j);
        }
    }

    printk("malloc() ERROR: no memory can alloc\n");

    spin_unlock(&slab_lock);

    return NULL;
}

void *calloc(size_t num, size_t size) {
    void *ptr = malloc(num * size);
    if (ptr)
        memset(ptr, 0, num * size);
    return ptr;
}

struct slab *kmalloc_create(uint64_t size) {
    int i;
    struct slab *slab = NULL;
    uint64_t page = 0;
    uint64_t *vaddresss = NULL;
    long structsize = 0;

    page = alloc_frames(MAX_SLAB_MALLOC_SIZE / DEFAULT_PAGE_SIZE);

    if (!page) {
        printk("kmalloc_create()->alloc_frames() == NULL\n");
        return NULL;
    }

    switch (size) {

        // slab + map in 2M page
    case 32:
    case 64:
    case 128:
    case 256:
    case 512:
        vaddresss = (void *)phys_to_virt(page);
        structsize = sizeof(struct slab) + MAX_SLAB_MALLOC_SIZE / size / 8;

        slab = (struct slab *)((uint8_t *)vaddresss + MAX_SLAB_MALLOC_SIZE -
                               structsize);
        slab->color_map = (uint64_t *)((uint8_t *)slab + sizeof(struct slab));

        slab->free_count =
            (MAX_SLAB_MALLOC_SIZE - (MAX_SLAB_MALLOC_SIZE / size / 8) -
             sizeof(struct slab)) /
            size;
        slab->using_count = 0;
        slab->color_count = slab->free_count;
        slab->v_address = vaddresss;
        slab->page = page;
        llist_init_head(&slab->list);

        slab->color_length =
            ((slab->color_count + sizeof(uint64_t) * 8 - 1) >> 6) << 3;
        memset(slab->color_map, 0xff, slab->color_length);

        for (i = 0; i < slab->color_count; i++)
            *(slab->color_map + (i >> 6)) ^= 1UL << i % 64;

        break;

        // kmalloc slab and map,not in 2M page anymore
    case 1024: // 1KB
    case 2048:
    case 4096: // 4KB
    case 8192:
    case 16384:

        // color_map is a very short buffer.
    case 32768:
    case 65536:
    case 131072: // 128KB
    case 262144:
    case 524288:
    case 1048576: // 1MB
        slab = malloc(sizeof(struct slab));

        slab->free_count = MAX_SLAB_MALLOC_SIZE / size;
        slab->using_count = 0;
        slab->color_count = slab->free_count;

        slab->color_length =
            ((slab->color_count + sizeof(uint64_t) * 8 - 1) >> 6) << 3;

        slab->color_map = (uint64_t *)malloc(slab->color_length);
        memset(slab->color_map, 0xff, slab->color_length);

        slab->v_address = (void *)phys_to_virt(page);
        slab->page = page;
        llist_init_head(&slab->list);

        for (i = 0; i < slab->color_count; i++)
            *(slab->color_map + (i >> 6)) ^= 1UL << i % 64;

        break;

    default:
        printk("kmalloc_create() ERROR: wrong size: %08d\n", size);
        free_frames(page, MAX_SLAB_MALLOC_SIZE / DEFAULT_PAGE_SIZE);

        return NULL;
    }

    return slab;
}

void free(void *address) {
    if (!address)
        return;

    spin_lock(&slab_lock);

    int i;
    int index;
    struct slab *slab = NULL;
    void *page_base_address =
        (void *)((uint64_t)address & MAX_SLAB_MALLOC_MASK);

    for (i = 0; i < sizeof(kmalloc_cache_size) / sizeof(kmalloc_cache_size[0]);
         i++) {
        slab = kmalloc_cache_size[i].cache_pool;
        do {
            if (slab->v_address == page_base_address) {
                index =
                    (address - slab->v_address) / kmalloc_cache_size[i].size;

                *(slab->color_map + (index >> 6)) ^= 1UL << index % 64;

                slab->free_count++;
                slab->using_count--;

                kmalloc_cache_size[i].total_free++;
                kmalloc_cache_size[i].total_using--;

                if ((slab->using_count == 0) &&
                    (kmalloc_cache_size[i].total_free >=
                     slab->color_count * 3 / 2) &&
                    (kmalloc_cache_size[i].cache_pool != slab)) {
                    switch (kmalloc_cache_size[i].size) {
                        ////////////////////slab + map in 2M page

                    case 32:
                    case 64:
                    case 128:
                    case 256:
                    case 512:
                        llist_delete(&slab->list);
                        kmalloc_cache_size[i].total_free -= slab->color_count;

                        free_frames(slab->page,
                                    MAX_SLAB_MALLOC_SIZE / DEFAULT_PAGE_SIZE);
                        break;

                    default:
                        llist_delete(&slab->list);
                        kmalloc_cache_size[i].total_free -= slab->color_count;

                        free(slab->color_map);

                        free_frames(slab->page,
                                    MAX_SLAB_MALLOC_SIZE / DEFAULT_PAGE_SIZE);
                        free(slab);
                        break;
                    }
                }

                spin_unlock(&slab_lock);

                return;
            } else
                slab = container_of(slab->list.next, struct slab, list);

        } while (slab != kmalloc_cache_size[i].cache_pool);
    }

    printk("free() ERROR: can`t free memory\n");

    spin_unlock(&slab_lock);
}

void *realloc(void *ptr, size_t size) {
    if (ptr == NULL)
        return malloc(size);

    if (size == 0) {
        free(ptr);
        return NULL;
    }

    if (size > kmalloc_cache_size[sizeof(kmalloc_cache_size) /
                                      sizeof(kmalloc_cache_size[0]) -
                                  1]
                   .size) {
        printk("realloc() ERROR: size too large: %08d\n", size);
        return NULL;
    }

    spin_lock(&slab_lock);

    int i, old_cache_index = -1;
    struct slab *slab = NULL;
    void *page_base_address = (void *)((uint64_t)ptr & MAX_SLAB_MALLOC_MASK);

    for (i = 0; i < sizeof(kmalloc_cache_size) / sizeof(kmalloc_cache_size[0]);
         i++) {
        slab = kmalloc_cache_size[i].cache_pool;
        do {
            if (slab->v_address == page_base_address) {
                int index =
                    (ptr - slab->v_address) / kmalloc_cache_size[i].size;
                if (index >= 0 && index < slab->color_count &&
                    (*(slab->color_map + (index >> 6)) &
                     (1UL << (index % 64)))) {
                    old_cache_index = i;
                    goto found;
                }
            }
            slab = container_of(slab->list.next, struct slab, list);
        } while (slab != kmalloc_cache_size[i].cache_pool);
    }

found:
    if (old_cache_index == -1) {
        printk("realloc() ERROR: invalid pointer %p\n", ptr);
        spin_unlock(&slab_lock);
        return NULL;
    }

    int new_cache_index;
    for (new_cache_index = 0;
         new_cache_index <
         sizeof(kmalloc_cache_size) / sizeof(kmalloc_cache_size[0]);
         new_cache_index++) {
        if (kmalloc_cache_size[new_cache_index].size >= size)
            break;
    }

    if (old_cache_index == new_cache_index) {
        spin_unlock(&slab_lock);
        return ptr;
    }

    spin_unlock(&slab_lock);
    void *new_ptr = malloc(size);
    spin_lock(&slab_lock);
    if (new_ptr == NULL) {
        spin_unlock(&slab_lock);
        return NULL;
    }

    size_t copy_size = MIN(kmalloc_cache_size[old_cache_index].size, size);
    memcpy(new_ptr, ptr, copy_size);
    spin_unlock(&slab_lock);
    free(ptr);

    return new_ptr;
}

void slab_init() {
    uint64_t page;
    uint64_t *virtual = NULL;
    uint64_t i, j;

    size_t metadata_size = 0;
    size_t color_lengths[sizeof(kmalloc_cache_size) /
                         sizeof(kmalloc_cache_size[0])];
    size_t color_counts[sizeof(kmalloc_cache_size) /
                        sizeof(kmalloc_cache_size[0])];

    for (i = 0; i < sizeof(kmalloc_cache_size) / sizeof(kmalloc_cache_size[0]);
         i++) {
        // 1. Slab 结构体 + 填充
        metadata_size += sizeof(struct slab) + sizeof(long) * 10;

        // 2. 计算 color_map 相关参数
        color_counts[i] = MAX_SLAB_MALLOC_SIZE / kmalloc_cache_size[i].size;
        color_lengths[i] = ((color_counts[i] + sizeof(uint64_t) * 8 - 1) >> 6)
                           << 3;

        // 3. color_map 大小 + 填充 + 对齐
        size_t color_map_total = color_lengths[i] + sizeof(long) * 10;
        color_map_total =
            (color_map_total + sizeof(long) - 1) & (~(sizeof(long) - 1));
        metadata_size += color_map_total;
    }

    uint64_t *metadata_base = (uint64_t *)alloc_frames_bytes(metadata_size);
    if (!metadata_base) {
        // TODO: 错误处理
        return;
    }

    uint64_t *current_ptr = metadata_base;

    for (i = 0; i < sizeof(kmalloc_cache_size) / sizeof(kmalloc_cache_size[0]);
         i++) {
        // 设置 Slab 结构指针
        kmalloc_cache_size[i].cache_pool = (struct slab *)current_ptr;
        current_ptr = (uint64_t *)((uint8_t *)current_ptr +
                                   sizeof(struct slab) + sizeof(long) * 10);

        // 初始化链表
        llist_init_head(&kmalloc_cache_size[i].cache_pool->list);

        // 初始化 Slab 字段
        kmalloc_cache_size[i].cache_pool->using_count = 0;
        kmalloc_cache_size[i].cache_pool->free_count = color_counts[i];
        kmalloc_cache_size[i].cache_pool->color_length = color_lengths[i];
        kmalloc_cache_size[i].cache_pool->color_count = color_counts[i];

        // 设置 color_map 指针
        kmalloc_cache_size[i].cache_pool->color_map = current_ptr;

        // 初始化 color_map
        memset(kmalloc_cache_size[i].cache_pool->color_map, 0xff,
               color_lengths[i]);

        // 清除有效对象的位（标记为可用）
        for (j = 0; j < color_counts[i]; j++) {
            *(kmalloc_cache_size[i].cache_pool->color_map + (j >> 6)) ^=
                1UL << (j % 64);
        }

        // 移动到下一个位置（对齐）
        size_t color_map_total = color_lengths[i] + sizeof(long) * 10;
        color_map_total =
            (color_map_total + sizeof(long) - 1) & (~(sizeof(long) - 1));
        current_ptr = (uint64_t *)((uint8_t *)current_ptr + color_map_total);

        // 初始化统计信息
        kmalloc_cache_size[i].total_free = color_counts[i];
        kmalloc_cache_size[i].total_using = 0;
    }

    for (i = 0; i < sizeof(kmalloc_cache_size) / sizeof(kmalloc_cache_size[0]);
         i++) {
        virtual = (uint64_t *)alloc_frames_bytes(MAX_SLAB_MALLOC_SIZE);
        if (!virtual) {
            // TODO: 错误处理（需要回滚已分配的页面）
            return;
        }

        page = (uint64_t)virt_to_phys(virtual);

        // 关联页面到 slab
        kmalloc_cache_size[i].cache_pool->page = page;
        kmalloc_cache_size[i].cache_pool->v_address = virtual;
    }
}

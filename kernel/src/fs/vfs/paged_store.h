#pragma once

#include <fs/vfs/vfs.h>
#include <mm/mm.h>
#include <mm/page.h>
#include <task/task.h>

typedef struct paged_file_store {
    uint64_t *pages;
    size_t page_slots;
    uint64_t size;
} paged_file_store_t;

static inline size_t paged_file_store_pages_for_size(uint64_t size) {
    return size ? (size_t)(PADDING_UP(size, PAGE_SIZE) / PAGE_SIZE) : 0;
}

static inline int paged_file_store_ensure_slots(paged_file_store_t *store,
                                                size_t slots) {
    if (!store || slots <= store->page_slots)
        return 0;

    size_t new_slots = store->page_slots ? store->page_slots : 1;
    while (new_slots < slots) {
        if (new_slots > SIZE_MAX / 2) {
            new_slots = slots;
            break;
        }
        new_slots *= 2;
    }
    if (new_slots < slots)
        new_slots = slots;

    uint64_t *new_pages = calloc(new_slots, sizeof(uint64_t));
    if (!new_pages)
        return -ENOMEM;

    if (store->pages && store->page_slots) {
        memcpy(new_pages, store->pages, store->page_slots * sizeof(uint64_t));
        free(store->pages);
    }

    store->pages = new_pages;
    store->page_slots = new_slots;
    return 0;
}

static inline int paged_file_store_resolve_page(paged_file_store_t *store,
                                                size_t page_idx, bool create,
                                                uint64_t *out_paddr) {
    if (!store || !out_paddr)
        return -EINVAL;

    *out_paddr = 0;
    if (page_idx >= store->page_slots) {
        if (!create)
            return 0;
        int ret = paged_file_store_ensure_slots(store, page_idx + 1);
        if (ret < 0)
            return ret;
    }

    uint64_t paddr = store->pages[page_idx];
    if (!paddr && create) {
        paddr = alloc_frames(1);
        if (!paddr)
            return -ENOMEM;
        memset((void *)phys_to_virt(paddr), 0, PAGE_SIZE);
        store->pages[page_idx] = paddr;
    }

    *out_paddr = paddr;
    return 0;
}

static inline void paged_file_store_zero_tail(paged_file_store_t *store,
                                              uint64_t size) {
    uint64_t paddr = 0;
    size_t tail_page;

    if (!store || (size & (PAGE_SIZE - 1)) == 0)
        return;

    tail_page = (size_t)(size / PAGE_SIZE);
    if (paged_file_store_resolve_page(store, tail_page, false, &paddr) == 0 &&
        paddr) {
        memset((uint8_t *)phys_to_virt(paddr) + (size % PAGE_SIZE), 0,
               PAGE_SIZE - (size % PAGE_SIZE));
    }
}

static inline ssize_t paged_file_store_read_locked(paged_file_store_t *store,
                                                   void *buf, size_t count,
                                                   loff_t *ppos) {
    size_t copy_len;
    size_t copied = 0;

    if (!store || !buf || !ppos)
        return -EINVAL;
    if ((uint64_t)*ppos >= store->size)
        return 0;

    copy_len = (size_t)MIN((uint64_t)count, store->size - (uint64_t)*ppos);
    while (copied < copy_len) {
        uint64_t file_off = (uint64_t)*ppos + copied;
        size_t page_idx = (size_t)(file_off / PAGE_SIZE);
        size_t in_page = (size_t)(file_off % PAGE_SIZE);
        size_t chunk = MIN(copy_len - copied, PAGE_SIZE - in_page);
        uint64_t paddr = 0;

        paged_file_store_resolve_page(store, page_idx, false, &paddr);
        if (paddr) {
            memcpy((uint8_t *)buf + copied,
                   (uint8_t *)phys_to_virt(paddr) + in_page, chunk);
        } else {
            memset((uint8_t *)buf + copied, 0, chunk);
        }
        copied += chunk;
    }

    *ppos += (loff_t)copy_len;
    return (ssize_t)copy_len;
}

static inline ssize_t paged_file_store_write_locked(paged_file_store_t *store,
                                                    const void *buf,
                                                    size_t count,
                                                    loff_t *ppos) {
    size_t copied = 0;

    if (!store || !buf || !ppos)
        return -EINVAL;

    while (copied < count) {
        uint64_t file_off = (uint64_t)*ppos + copied;
        size_t page_idx = (size_t)(file_off / PAGE_SIZE);
        size_t in_page = (size_t)(file_off % PAGE_SIZE);
        size_t chunk = MIN(count - copied, PAGE_SIZE - in_page);
        uint64_t paddr = 0;
        int ret = paged_file_store_resolve_page(store, page_idx, true, &paddr);
        if (ret < 0)
            return ret;

        memcpy((uint8_t *)phys_to_virt(paddr) + in_page,
               (const uint8_t *)buf + copied, chunk);
        copied += chunk;
    }

    *ppos += (loff_t)count;
    return (ssize_t)count;
}

static inline int
paged_file_store_map_shared_locked(paged_file_store_t *store, uint64_t *pgdir,
                                   uint64_t addr, uint64_t offset,
                                   uint64_t size, uint64_t pt_flags) {
    uint64_t mapped_size;

    if (!store || !pgdir)
        return -EINVAL;
    if (offset > UINT64_MAX - size)
        return -EINVAL;
    if (offset >= store->size)
        return 0;

    mapped_size = MIN(size, store->size - offset);
    for (uint64_t done = 0; done < mapped_size; done += PAGE_SIZE) {
        uint64_t paddr = 0;
        int ret = paged_file_store_resolve_page(
            store, (size_t)((offset + done) / PAGE_SIZE), true, &paddr);
        if (ret < 0)
            return ret;
        if (map_page_range(pgdir, addr + done, paddr, PAGE_SIZE, pt_flags) !=
            0) {
            return -ENOMEM;
        }
    }

    return 0;
}

static inline void paged_file_store_zap_shared_mappings(vfs_node_t *node,
                                                        uint64_t file_start,
                                                        uint64_t file_end) {
    if (!node || file_start >= file_end)
        return;

    spin_lock(&task_queue_lock);
    if (!task_pid_map.buckets) {
        spin_unlock(&task_queue_lock);
        return;
    }

    for (size_t i = 0; i < task_pid_map.bucket_count; i++) {
        hashmap_entry_t *entry = &task_pid_map.buckets[i];
        if (!hashmap_entry_is_occupied(entry))
            continue;

        task_t *task = (task_t *)entry->value;
        if (!task || !task->mm)
            continue;

        task_mm_info_t *mm = task->mm;
        vma_manager_t *mgr = &mm->task_vma_mgr;

        spin_lock(&mgr->lock);
        uint64_t cursor = USER_MMAP_START;
        while (cursor < USER_MMAP_END) {
            vma_t *vma = vma_find_intersection(mgr, cursor, USER_MMAP_END);
            if (!vma)
                break;

            uint64_t next = vma->vm_end;
            if (vma->vm_type == VMA_TYPE_FILE && vma->node == node &&
                (vma->vm_flags & VMA_SHARED) && vma->vm_offset >= 0) {
                uint64_t vma_file_start = (uint64_t)vma->vm_offset;
                uint64_t vma_len = vma->vm_end - vma->vm_start;
                uint64_t vma_file_end = UINT64_MAX;
                if (vma_len <= UINT64_MAX - vma_file_start)
                    vma_file_end = vma_file_start + vma_len;

                uint64_t overlap_start = MAX(file_start, vma_file_start);
                uint64_t overlap_end = MIN(file_end, vma_file_end);
                if (overlap_start < overlap_end) {
                    uint64_t unmap_start =
                        vma->vm_start + (overlap_start - vma_file_start);
                    uint64_t unmap_len = overlap_end - overlap_start;

                    spin_lock(&mm->lock);
                    unmap_page_range_mm(mm, unmap_start, unmap_len);
                    spin_unlock(&mm->lock);
                }
            }

            if (next <= cursor)
                break;
            cursor = next;
        }
        spin_unlock(&mgr->lock);
    }

    spin_unlock(&task_queue_lock);
}

static inline void paged_file_store_destroy(paged_file_store_t *store) {
    if (!store)
        return;

    for (size_t i = 0; i < store->page_slots; i++) {
        if (store->pages[i])
            address_release(store->pages[i]);
    }
    free(store->pages);
    store->pages = NULL;
    store->page_slots = 0;
    store->size = 0;
}

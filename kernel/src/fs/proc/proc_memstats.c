#include <fs/proc/proc.h>
#include <mm/cache.h>
#include <mm/mm.h>
#include <task/task.h>

static uint64_t procfs_pages_for_range(uint64_t start, uint64_t end) {
    if (end <= start)
        return 0;
    return (PADDING_UP(end, PAGE_SIZE) - PADDING_DOWN(start, PAGE_SIZE)) /
           PAGE_SIZE;
}

void procfs_task_mem_stats(task_t *task, procfs_task_mem_stats_t *stats) {
    if (!stats)
        return;

    memset(stats, 0, sizeof(*stats));
    if (!task || !task->mm)
        return;

    task_mm_info_t *mm = task->mm;
    vma_manager_t *mgr = &mm->task_vma_mgr;
    uint64_t shared_size_pages = 0;
    uint64_t file_size_pages = 0;
    page_cache_stats_t cache = {0};

    spin_lock(&mgr->lock);

    rb_node_t *node = rb_first(&mgr->vma_tree);
    while (node) {
        vma_t *vma = rb_entry(node, vma_t, vm_rb);
        uint64_t vma_pages = procfs_pages_for_range(vma->vm_start, vma->vm_end);

        stats->size_pages += vma_pages;
        if (vma->vm_flags & VMA_EXEC)
            stats->text_pages += vma_pages;
        else if (vma->vm_flags & VMA_STACK)
            stats->stack_pages += vma_pages;
        else if (vma->vm_flags & VMA_WRITE)
            stats->data_pages += vma_pages;

        if (vma->vm_type == VMA_TYPE_FILE)
            file_size_pages += vma_pages;
        else if ((vma->vm_flags & VMA_SHARED) || vma->vm_type == VMA_TYPE_SHM)
            shared_size_pages += vma_pages;

        node = rb_next(node);
    }

    spin_unlock(&mgr->lock);

    page_cache_stats_snapshot(&cache);
    stats->resident_pages = task_mm_resident_pages(mm);
    if (file_size_pages > cache.cached_pages)
        file_size_pages = cache.cached_pages;
    if (shared_size_pages > cache.mapped_pages)
        shared_size_pages = cache.mapped_pages;
    stats->shared_pages = MIN(shared_size_pages, stats->resident_pages);
    stats->file_pages = MIN(file_size_pages, stats->resident_pages);
    uint64_t accounted = stats->shared_pages + stats->file_pages;
    uint64_t remaining = stats->resident_pages > accounted
                             ? stats->resident_pages - accounted
                             : 0;
    stats->anon_pages = remaining;
    stats->pte_pages = (stats->size_pages + 511) / 512;
}

#include <fs/proc/proc.h>
#include <libs/string_builder.h>
#include <mm/cache.h>
#include <mm/mm.h>

char *meminfo_origin[] = {
    "MemTotal:\t\t%llu kB\n",       "MemFree:\t\t%llu kB\n",
    "MemAvailable:\t%llu kB\n",     "Buffers:\t\t%llu kB\n",
    "Cached:\t\t%llu kB\n",         "SwapCached:\t\t%llu kB\n",
    "Active:\t\t%llu kB\n",         "Inactive:\t\t%llu kB\n",
    "Active(anon):\t%llu kB\n",     "Inactive(anon):\t%llu kB\n",
    "Active(file):\t%llu kB\n",     "Inactive(file):\t%llu kB\n",
    "Unevictable:\t\t%llu kB\n",    "Mlocked:\t\t%llu kB\n",
    "SwapTotal:\t\t%llu kB\n",      "SwapFree:\t\t%llu kB\n",
    "Zswap:\t\t%llu kB\n",          "Zswapped:\t\t%llu kB\n",
    "Dirty:\t\t%llu kB\n",          "Writeback:\t\t%llu kB\n",
    "AnonPages: \t\t%llu kB\n",     "Mapped:\t\t%llu kB\n",
    "Shmem:\t\t%llu kB\n",          "KReclaimable:\t%llu kB\n",
    "Slab:\t\t%llu kB\n",           "SReclaimable:\t\t%llu kB\n",
    "SUnreclaim:\t\t%llu kB\n",     "KernelStack:\t\t%llu kB\n",
    "PageTables:\t\t%llu kB\n",     "SecPageTables:\t\t%llu kB\n",
    "NFS_Unstable:\t\t%llu kB\n",   "Bounce:\t\t%llu kB\n",
    "WritebackTmp:\t\t%llu kB\n",   "CommitLimit:\t%llu kB\n",
    "Committed_AS:\t%llu kB\n",     "VmallocTotal:\t%llu kB\n",
    "VmallocUsed:\t\t%llu kB\n",    "VmallocChunk:\t\t%llu kB\n",
    "Percpu:\t\t%llu kB\n",         "HardwareCorrupted:\t%llu kB\n",
    "AnonHugePages:\t%llu kB\n",    "ShmemHugePages:\t\t%llu kB\n",
    "ShmemPmdMapped:\t\t%llu kB\n", "FileHugePages:\t\t%llu kB\n",
    "FilePmdMapped:\t\t%llu kB\n",  "Unaccepted:\t\t%llu kB\n",
    "HugePages_Total:\t\t%llu\n",   "HugePages_Free:\t\t%llu\n",
    "HugePages_Rsvd:\t\t%llu\n",    "HugePages_Surp:\t\t%llu\n",
    "Hugepagesize:\t%llu kB\n",     "Hugetlb:\t\t%llu kB\n",
    "DirectMap4k:\t%llu kB\n",      "DirectMap2M:\t%llu kB\n",
    "DirectMap1G:\t%llu kB\n"};

char *proc_gen_meminfo(size_t *context_len) {
    const size_t field_count =
        sizeof(meminfo_origin) / sizeof(meminfo_origin[0]);
    uint64_t values[55] = {0};
    uint64_t managed_pages = 0;
    uint64_t free_pages = 0;
    uint64_t reclaimable_pages = 0;
    cache_stats_t cache_stats = {0};
    const uint64_t page_kb = PAGE_SIZE / 1024;

    for (int i = 0; i < __MAX_NR_ZONES; i++) {
        zone_t *zone = zones[i];
        if (!zone)
            continue;
        managed_pages += zone->managed_pages;
        free_pages += zone->free_pages;
    }

    cache_get_stats(&cache_stats);
    reclaimable_pages = cache_stats.block_pages + cache_stats.page_pages;

    values[0] = managed_pages * page_kb;
    values[1] = free_pages * page_kb;
    values[2] = (free_pages + reclaimable_pages) * page_kb;
    values[3] = cache_stats.block_pages * page_kb;
    values[4] = cache_stats.page_pages * page_kb;
    values[6] =
        (cache_stats.dirty_pages + cache_stats.writeback_pages) * page_kb;
    values[7] = (reclaimable_pages >
                 cache_stats.dirty_pages + cache_stats.writeback_pages)
                    ? (reclaimable_pages - cache_stats.dirty_pages -
                       cache_stats.writeback_pages) *
                          page_kb
                    : 0;
    values[10] = values[6];
    values[11] = (cache_stats.page_pages >
                  cache_stats.dirty_pages + cache_stats.writeback_pages)
                     ? (cache_stats.page_pages - cache_stats.dirty_pages -
                        cache_stats.writeback_pages) *
                           page_kb
                     : 0;
    values[18] = cache_stats.dirty_pages * page_kb;
    values[19] = cache_stats.writeback_pages * page_kb;
    values[21] = cache_stats.page_pages * page_kb;
    values[23] = reclaimable_pages * page_kb;
    values[25] = reclaimable_pages * page_kb;
    values[33] = values[0];
    values[51] = 2048;
    values[53] = values[0];

    string_builder_t *builder = create_string_builder(4096);
    if (builder == NULL)
        return NULL;

    bool status = true;
    for (size_t i = 0; i < field_count; i++) {
        status &= string_builder_append(builder, meminfo_origin[i], values[i]);
    }

    if (!status) {
        free(builder->data);
        free(builder);
        return NULL;
    }

    *context_len = builder->size;
    char *data = builder->data;
    free(builder);
    return data;
}

size_t proc_meminfo_stat(proc_handle_t *handle) {
    size_t content_len = 0;
    char *content = proc_gen_meminfo(&content_len);
    free(content);
    return content_len;
}

size_t proc_meminfo_read(proc_handle_t *handle, void *addr, size_t offset,
                         size_t size) {
    size_t content_len = 0;
    char *content = proc_gen_meminfo(&content_len);

    if (!content || content_len == 0) {
        if (content)
            free(content);
        return 0;
    }

    if (offset >= content_len) {
        free(content);
        return 0;
    }

    content_len = MIN(content_len, offset + size);
    size_t to_copy = MIN(content_len, size);

    memcpy(addr, content + offset, to_copy);
    free(content);

    ((char *)addr)[to_copy] = '\0';
    return to_copy;
}

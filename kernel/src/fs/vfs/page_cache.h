#pragma once

#include <fs/vfs/vfs.h>

bool vfs_page_cache_supported(vfs_node_t node);
int vfs_page_cache_get_page(vfs_node_t node, uint64_t offset,
                            uint64_t *phys_out, size_t *valid_out);
ssize_t vfs_page_cache_read(fd_t *fd, void *addr, size_t offset, size_t size);
void *vfs_page_cache_map(fd_t *fd, uint64_t addr, uint64_t len, uint64_t prot,
                         uint64_t flags, uint64_t offset);
void vfs_page_cache_invalidate(vfs_node_t node, uint64_t offset, uint64_t size);
void vfs_page_cache_invalidate_all(vfs_node_t node);
void vfs_page_cache_resize(vfs_node_t node, uint64_t size);
size_t vfs_page_cache_reclaim_half(void);
size_t vfs_page_cache_count(void);

#include <fs/vfs/page_cache.h>
#include <mm/mm.h>
#include <mm/page.h>
#include <mm/mm_syscall.h>
#include <task/task.h>

typedef struct vfs_page_cache_entry {
    rb_node_t rb_node;
    struct llist_header lru_node;
    vfs_node_t node;
    uint64_t index;
    uint64_t phys;
    size_t valid_bytes;
    bool referenced;
} vfs_page_cache_entry_t;

static DEFINE_LLIST(vfs_page_cache_lru);
static spinlock_t vfs_page_cache_lock = SPIN_INIT;
static size_t vfs_page_cache_pages = 0;

static inline uint64_t page_cache_page_start(uint64_t index) {
    return index * DEFAULT_PAGE_SIZE;
}

static inline const vfs_operations_t *page_cache_ops(vfs_node_t node) {
    if (!node)
        return NULL;

    fs_t *fs = all_fs[node->fsid];
    return fs ? fs->ops : NULL;
}

static inline bool page_cache_regular_file(vfs_node_t node) {
    return node && (node->type & file_none) &&
           !(node->type & (file_dir | file_symlink | file_block | file_stream |
                           file_socket | file_epoll | file_fifo));
}

bool vfs_page_cache_supported(vfs_node_t node) {
    if (!page_cache_regular_file(node))
        return false;

    fs_t *fs = all_fs[node->fsid];
    if (!fs || !fs->ops || !fs->ops->read)
        return false;

    return (fs->flags & FS_FLAGS_VIRTUAL) == 0;
}

static vfs_page_cache_entry_t *page_cache_lookup_locked(vfs_node_t node,
                                                        uint64_t index) {
    rb_node_t *rb = node->page_cache_tree.rb_node;

    while (rb) {
        vfs_page_cache_entry_t *entry =
            rb_entry(rb, vfs_page_cache_entry_t, rb_node);
        if (index < entry->index) {
            rb = rb->rb_left;
        } else if (index > entry->index) {
            rb = rb->rb_right;
        } else {
            return entry;
        }
    }

    return NULL;
}

static void page_cache_insert_locked(vfs_node_t node,
                                     vfs_page_cache_entry_t *entry) {
    rb_node_t **link = &node->page_cache_tree.rb_node;
    rb_node_t *parent = NULL;

    while (*link) {
        vfs_page_cache_entry_t *current =
            rb_entry(*link, vfs_page_cache_entry_t, rb_node);
        parent = *link;

        if (entry->index < current->index) {
            link = &(*link)->rb_left;
        } else {
            link = &(*link)->rb_right;
        }
    }

    entry->rb_node.rb_parent_color = (uint64_t)parent;
    entry->rb_node.rb_left = NULL;
    entry->rb_node.rb_right = NULL;
    *link = &entry->rb_node;
    rb_insert_color(&entry->rb_node, &node->page_cache_tree);
}

static void page_cache_detach_locked(vfs_page_cache_entry_t *entry) {
    if (!entry || !entry->node)
        return;

    rb_erase(&entry->rb_node, &entry->node->page_cache_tree);
    entry->rb_node.rb_parent_color = 0;
    entry->rb_node.rb_left = NULL;
    entry->rb_node.rb_right = NULL;

    if (!llist_empty(&entry->lru_node))
        llist_delete(&entry->lru_node);

    if (vfs_page_cache_pages)
        vfs_page_cache_pages--;
}

static ssize_t page_cache_raw_read(vfs_node_t node, void *addr, size_t offset,
                                   size_t size) {
    const vfs_operations_t *ops = page_cache_ops(node);
    if (!ops || !ops->read)
        return -ENOSYS;

    fd_t fd = {
        .node = node,
        .flags = 0,
        .offset = offset,
        .close_on_exec = false,
    };

    return ops->read(&fd, addr, offset, size);
}

static int page_cache_load_page(vfs_node_t node, uint64_t index,
                                uint64_t *phys_out, size_t *valid_out) {
    if (!node || !phys_out || !valid_out)
        return -EINVAL;

    uint64_t phys = alloc_frames(1);
    if (!phys)
        return -ENOMEM;

    void *page = (void *)phys_to_virt(phys);
    memset(page, 0, DEFAULT_PAGE_SIZE);

    vfs_update(node);

    uint64_t file_off = page_cache_page_start(index);
    uint64_t file_size = node->size;
    size_t want = 0;
    if (file_off < file_size)
        want = MIN((uint64_t)DEFAULT_PAGE_SIZE, file_size - file_off);

    size_t loaded = 0;
    while (loaded < want) {
        ssize_t ret = page_cache_raw_read(node, (uint8_t *)page + loaded,
                                          file_off + loaded, want - loaded);
        if (ret < 0) {
            address_release(phys);
            return (int)ret;
        }
        if (ret == 0)
            break;
        loaded += (size_t)ret;
    }

    *phys_out = phys;
    *valid_out = loaded;
    return 0;
}

static int page_cache_get_page(vfs_node_t node, uint64_t index,
                               uint64_t *phys_out, size_t *valid_out) {
    if (!vfs_page_cache_supported(node))
        return -EOPNOTSUPP;

    spin_lock(&vfs_page_cache_lock);
    vfs_page_cache_entry_t *entry = page_cache_lookup_locked(node, index);
    if (entry) {
        entry->referenced = true;
        address_ref(entry->phys);
        *phys_out = entry->phys;
        *valid_out = entry->valid_bytes;
        spin_unlock(&vfs_page_cache_lock);
        return 0;
    }
    spin_unlock(&vfs_page_cache_lock);

    uint64_t phys = 0;
    size_t valid_bytes = 0;
    int load_ret = page_cache_load_page(node, index, &phys, &valid_bytes);
    if (load_ret < 0)
        return load_ret;

    vfs_page_cache_entry_t *new_entry = malloc(sizeof(*new_entry));
    if (!new_entry) {
        address_release(phys);
        return -ENOMEM;
    }

    memset(new_entry, 0, sizeof(*new_entry));
    new_entry->node = node;
    new_entry->index = index;
    new_entry->phys = phys;
    new_entry->valid_bytes = valid_bytes;
    new_entry->referenced = true;
    llist_init_head(&new_entry->lru_node);

    spin_lock(&vfs_page_cache_lock);
    entry = page_cache_lookup_locked(node, index);
    if (entry) {
        entry->referenced = true;
        address_ref(entry->phys);
        *phys_out = entry->phys;
        *valid_out = entry->valid_bytes;
        spin_unlock(&vfs_page_cache_lock);
        address_release(phys);
        free(new_entry);
        return 0;
    }

    page_cache_insert_locked(node, new_entry);
    llist_append(&vfs_page_cache_lru, &new_entry->lru_node);
    vfs_page_cache_pages++;
    address_ref(phys);
    *phys_out = phys;
    *valid_out = valid_bytes;
    spin_unlock(&vfs_page_cache_lock);

    return 0;
}

static uint64_t page_cache_pt_flags(uint64_t prot) {
    uint64_t pt_flags = PT_FLAG_U;

    if (prot & PROT_READ)
        pt_flags |= PT_FLAG_R;
    if (prot & PROT_WRITE)
        pt_flags |= PT_FLAG_W;
    if (prot & PROT_EXEC)
        pt_flags |= PT_FLAG_X;

    return pt_flags;
}

static uint64_t page_cache_arch_flags(uint64_t prot, bool cow) {
    uint64_t map_prot = cow ? (prot | PROT_READ) : prot;
    uint64_t arch_flags =
        get_arch_page_table_flags(page_cache_pt_flags(map_prot));

    if (!cow)
        return arch_flags;

    arch_flags |= ARCH_PT_FLAG_COW;
#if defined(__aarch64__)
    arch_flags |= ARCH_PT_FLAG_READONLY;
#else
    arch_flags &= ~ARCH_PT_FLAG_WRITEABLE;
#endif

    return arch_flags;
}

int vfs_page_cache_get_page(vfs_node_t node, uint64_t offset,
                            uint64_t *phys_out, size_t *valid_out) {
    if (offset & (DEFAULT_PAGE_SIZE - 1))
        return -EINVAL;

    return page_cache_get_page(node, offset / DEFAULT_PAGE_SIZE, phys_out,
                               valid_out);
}

ssize_t vfs_page_cache_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    if (!fd || !fd->node)
        return -EBADF;
    if (!size)
        return 0;
    if (!vfs_page_cache_supported(fd->node))
        return -EOPNOTSUPP;

    size_t copied = 0;
    while (copied < size) {
        uint64_t current = offset + copied;
        uint64_t index = current / DEFAULT_PAGE_SIZE;
        size_t in_page = current & (DEFAULT_PAGE_SIZE - 1);
        size_t chunk = MIN(size - copied, DEFAULT_PAGE_SIZE - in_page);
        uint64_t phys = 0;
        size_t valid_bytes = 0;

        int ret = page_cache_get_page(fd->node, index, &phys, &valid_bytes);
        if (ret < 0)
            return copied ? (ssize_t)copied : ret;

        if (in_page >= valid_bytes) {
            address_release(phys);
            break;
        }

        size_t available = MIN(chunk, valid_bytes - in_page);
        memcpy((uint8_t *)addr + copied,
               (const void *)(phys_to_virt(phys) + in_page), available);
        address_release(phys);

        copied += available;
        if (available < chunk)
            break;
    }

    return (ssize_t)copied;
}

void *vfs_page_cache_map(fd_t *fd, uint64_t addr, uint64_t len, uint64_t prot,
                         uint64_t flags, uint64_t offset) {
    if (!fd || !fd->node)
        return (void *)(int64_t)-EBADF;
    if (!vfs_page_cache_supported(fd->node))
        return (void *)(int64_t)-EOPNOTSUPP;
    if ((prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) == 0 || len == 0)
        return (void *)addr;
    if ((addr & (DEFAULT_PAGE_SIZE - 1)) || (len & (DEFAULT_PAGE_SIZE - 1)) ||
        (offset & (DEFAULT_PAGE_SIZE - 1))) {
        return (void *)(int64_t)-EINVAL;
    }

    uint64_t map_type = flags & MAP_TYPE;
    if (map_type != MAP_PRIVATE && map_type != MAP_SHARED &&
        map_type != MAP_SHARED_VALIDATE) {
        return (void *)(int64_t)-EINVAL;
    }

    if (map_type != MAP_PRIVATE)
        return (void *)(int64_t)-EOPNOTSUPP;

    bool cow = (prot & PROT_WRITE) != 0;
    uint64_t arch_flags = page_cache_arch_flags(prot, cow);
    task_mm_info_t *mm = current_task ? current_task->mm : NULL;
    if (!mm)
        return (void *)(int64_t)-EFAULT;

    uint64_t mapped = 0;
    for (uint64_t cursor = 0; cursor < len; cursor += DEFAULT_PAGE_SIZE) {
        uint64_t phys = 0;
        size_t valid_bytes = 0;
        int ret =
            page_cache_get_page(fd->node, (offset + cursor) / DEFAULT_PAGE_SIZE,
                                &phys, &valid_bytes);
        if (ret < 0) {
            if (mapped) {
                spin_lock(&mm->lock);
                unmap_page_range((uint64_t *)phys_to_virt(mm->page_table_addr),
                                 addr, mapped);
                spin_unlock(&mm->lock);
            }
            return (void *)(int64_t)ret;
        }

        spin_lock(&mm->lock);
        uint64_t *pgdir = (uint64_t *)phys_to_virt(mm->page_table_addr);
        map_page(pgdir, addr + cursor, phys, arch_flags, false);
        uint64_t mapped_phys = translate_address(pgdir, addr + cursor);
        spin_unlock(&mm->lock);

        address_release(phys);

        if (!mapped_phys) {
            if (mapped) {
                spin_lock(&mm->lock);
                unmap_page_range((uint64_t *)phys_to_virt(mm->page_table_addr),
                                 addr, mapped);
                spin_unlock(&mm->lock);
            }
            return (void *)(int64_t)-ENOMEM;
        }

        mapped += DEFAULT_PAGE_SIZE;
    }

    return (void *)addr;
}

static bool page_cache_range_match(vfs_page_cache_entry_t *entry,
                                   uint64_t start, uint64_t end) {
    uint64_t page_start = page_cache_page_start(entry->index);
    uint64_t page_end = page_start + DEFAULT_PAGE_SIZE;
    return page_start < end && start < page_end;
}

void vfs_page_cache_invalidate(vfs_node_t node, uint64_t offset,
                               uint64_t size) {
    if (!vfs_page_cache_supported(node) || size == 0)
        return;

    uint64_t end = (size > UINT64_MAX - offset) ? UINT64_MAX : (offset + size);

    while (true) {
        vfs_page_cache_entry_t *target = NULL;

        spin_lock(&vfs_page_cache_lock);
        for (rb_node_t *rb = rb_first(&node->page_cache_tree); rb;
             rb = rb_next(rb)) {
            vfs_page_cache_entry_t *entry =
                rb_entry(rb, vfs_page_cache_entry_t, rb_node);
            if (!page_cache_range_match(entry, offset, end))
                continue;
            target = entry;
            page_cache_detach_locked(target);
            break;
        }
        spin_unlock(&vfs_page_cache_lock);

        if (!target)
            break;

        address_release(target->phys);
        free(target);
    }
}

void vfs_page_cache_invalidate_all(vfs_node_t node) {
    if (!vfs_page_cache_supported(node))
        return;

    while (true) {
        vfs_page_cache_entry_t *target = NULL;

        spin_lock(&vfs_page_cache_lock);
        rb_node_t *rb = rb_first(&node->page_cache_tree);
        if (rb) {
            target = rb_entry(rb, vfs_page_cache_entry_t, rb_node);
            page_cache_detach_locked(target);
        }
        spin_unlock(&vfs_page_cache_lock);

        if (!target)
            break;

        address_release(target->phys);
        free(target);
    }
}

void vfs_page_cache_resize(vfs_node_t node, uint64_t size) {
    if (!vfs_page_cache_supported(node))
        return;

    if (size == 0) {
        vfs_page_cache_invalidate_all(node);
        return;
    }

    size_t tail_bytes = size & (DEFAULT_PAGE_SIZE - 1);
    uint64_t drop_from =
        tail_bytes ? PADDING_UP(size, DEFAULT_PAGE_SIZE) : size;
    if (drop_from < UINT64_MAX)
        vfs_page_cache_invalidate(node, drop_from, UINT64_MAX - drop_from);

    uint64_t tail_index = tail_bytes ? (size / DEFAULT_PAGE_SIZE)
                                     : ((size / DEFAULT_PAGE_SIZE) - 1);
    size_t target_bytes = tail_bytes ? tail_bytes : DEFAULT_PAGE_SIZE;
    if (!size)
        return;

    spin_lock(&vfs_page_cache_lock);
    vfs_page_cache_entry_t *entry = page_cache_lookup_locked(node, tail_index);
    if (entry) {
        if (target_bytes > entry->valid_bytes) {
            memset((void *)(phys_to_virt(entry->phys) + entry->valid_bytes), 0,
                   target_bytes - entry->valid_bytes);
        }
        entry->valid_bytes = target_bytes;
        entry->referenced = true;
    }
    spin_unlock(&vfs_page_cache_lock);
}

size_t vfs_page_cache_reclaim_half(void) {
    spin_lock(&vfs_page_cache_lock);

    size_t total = vfs_page_cache_pages;
    size_t target = total / 2;
    size_t reclaimed = 0;
    size_t scanned = 0;
    size_t limit = total ? total * 4 : 0;
    struct llist_header *cursor = vfs_page_cache_lru.next;

    while (reclaimed < target && scanned < limit &&
           !llist_empty(&vfs_page_cache_lru)) {
        if (cursor == &vfs_page_cache_lru)
            cursor = cursor->next;
        if (cursor == &vfs_page_cache_lru)
            break;

        vfs_page_cache_entry_t *entry =
            list_entry(cursor, vfs_page_cache_entry_t, lru_node);
        cursor = cursor->next;
        scanned++;

        if (entry->referenced) {
            entry->referenced = false;
            llist_delete(&entry->lru_node);
            llist_append(&vfs_page_cache_lru, &entry->lru_node);
            continue;
        }

        page_t *page = get_page(entry->phys);
        if (!page || page->refcount != 1)
            continue;

        page_cache_detach_locked(entry);
        spin_unlock(&vfs_page_cache_lock);
        address_release(entry->phys);
        free(entry);
        reclaimed++;
        spin_lock(&vfs_page_cache_lock);
        cursor = vfs_page_cache_lru.next;
    }

    spin_unlock(&vfs_page_cache_lock);
    return reclaimed;
}

size_t vfs_page_cache_count(void) {
    size_t count = 0;

    spin_lock(&vfs_page_cache_lock);
    count = vfs_page_cache_pages;
    spin_unlock(&vfs_page_cache_lock);

    return count;
}

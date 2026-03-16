#include <ext.h>
#include <ext_disk.h>

#include <boot/boot.h>

#include <dev/device.h>
#include <mm/mm_syscall.h>

#include <mm/mm.h>
#include <arch/arch.h>

static int ext_fsid = 0;
static spinlock_t rwlock = SPIN_INIT;
DEFINE_LLIST(ext_mounts);

#define EXT_MAP_CACHE_TARGET_BYTES (128u * 1024u)
#define EXT_MAP_CACHE_MIN_ENTRIES 16u
#define EXT_MAP_CACHE_MAX_ENTRIES 128u

typedef struct ext_map_cache_entry {
    uint32_t block;
    uint8_t *data;
    bool valid;
} ext_map_cache_entry_t;

typedef struct ext_mount_ctx {
    struct llist_header node;
    vfs_node_t root;
    uint64_t dev;
    ext_super_block_t sb;
    ext_group_desc_t *groups;
    uint32_t group_count;
    uint32_t block_size;
    uint32_t inode_size;
    uint32_t desc_size;
    uint32_t ptrs_per_block;
    uint64_t blocks_count;
    uint64_t inodes_count;
    ext_map_cache_entry_t *map_cache_entries;
    uint32_t map_cache_entry_count;
} ext_mount_ctx_t;

typedef struct ext_dir_lookup {
    bool found;
    uint32_t inode;
    uint8_t file_type;
    uint32_t lblock;
    uint16_t offset;
    uint16_t rec_len;
    bool has_prev;
    uint16_t prev_offset;
    uint16_t prev_rec_len;
} ext_dir_lookup_t;

static void ext_hide_node(vfs_node_t node);
static int ext_dev_read(ext_mount_ctx_t *fs, uint64_t offset, void *buf,
                        size_t size);
static int ext_dev_write(ext_mount_ctx_t *fs, uint64_t offset, const void *buf,
                         size_t size);
static void ext_sync_node_from_inode(vfs_node_t node, ext_mount_ctx_t *fs,
                                     const ext_inode_disk_t *inode);

static uint64_t ext_now(void) {
    return boot_get_boottime() + nano_time() / 1000000000;
}

static uint16_t ext_dir_rec_len(size_t name_len) {
    return (uint16_t)PADDING_UP(8 + name_len, 4);
}

static uint64_t ext_inode_size_get(const ext_inode_disk_t *inode) {
    return (uint64_t)inode->i_size_lo | ((uint64_t)inode->i_size_high << 32);
}

static void ext_inode_size_set(ext_inode_disk_t *inode, uint64_t size) {
    inode->i_size_lo = (uint32_t)size;
    inode->i_size_high = (uint32_t)(size >> 32);
}

static uint64_t ext_inode_blocks_get(const ext_inode_disk_t *inode) {
    return (uint64_t)inode->i_blocks_lo |
           ((uint64_t)inode->i_blocks_high << 32);
}

static void ext_inode_blocks_set(ext_inode_disk_t *inode, uint64_t blocks) {
    inode->i_blocks_lo = (uint32_t)blocks;
    inode->i_blocks_high = (uint16_t)(blocks >> 32);
}

static void ext_inode_add_fs_blocks(ext_mount_ctx_t *fs,
                                    ext_inode_disk_t *inode,
                                    uint32_t fs_blocks) {
    uint64_t sectors_per_block = fs->block_size / 512;
    ext_inode_blocks_set(inode, ext_inode_blocks_get(inode) +
                                    (uint64_t)fs_blocks * sectors_per_block);
}

static void ext_inode_sub_fs_blocks(ext_mount_ctx_t *fs,
                                    ext_inode_disk_t *inode,
                                    uint32_t fs_blocks) {
    uint64_t sectors_per_block = fs->block_size / 512;
    uint64_t cur = ext_inode_blocks_get(inode);
    uint64_t delta = (uint64_t)fs_blocks * sectors_per_block;
    ext_inode_blocks_set(inode, cur > delta ? cur - delta : 0);
}

static uint32_t ext_inode_uid_get(const ext_inode_disk_t *inode) {
    return (uint32_t)inode->i_uid | ((uint32_t)inode->i_uid_high << 16);
}

static uint32_t ext_inode_gid_get(const ext_inode_disk_t *inode) {
    return (uint32_t)inode->i_gid | ((uint32_t)inode->i_gid_high << 16);
}

static void ext_inode_uid_set(ext_inode_disk_t *inode, uint32_t uid) {
    inode->i_uid = (uint16_t)uid;
    inode->i_uid_high = (uint16_t)(uid >> 16);
}

static void ext_inode_gid_set(ext_inode_disk_t *inode, uint32_t gid) {
    inode->i_gid = (uint16_t)gid;
    inode->i_gid_high = (uint16_t)(gid >> 16);
}

static uint32_t ext_inode_rdev_get(const ext_inode_disk_t *inode) {
    return inode->i_block[0] & 0xFFFFu;
}

static void ext_inode_rdev_set(ext_inode_disk_t *inode, uint32_t dev) {
    memset(inode->i_block, 0, sizeof(inode->i_block));
    inode->i_block[0] = dev;
}

static void ext_inode_touch(ext_inode_disk_t *inode, bool atime, bool mtime,
                            bool ctime) {
    uint32_t now = (uint32_t)ext_now();
    if (atime)
        inode->i_atime = now;
    if (mtime)
        inode->i_mtime = now;
    if (ctime)
        inode->i_ctime = now;
    if (!inode->i_crtime)
        inode->i_crtime = now;
}

static uint32_t ext_mode_to_vfs_type(uint16_t mode) {
    switch (mode & S_IFMT) {
    case EXT2_S_IFDIR:
        return file_dir;
    case EXT2_S_IFLNK:
        return file_symlink;
    case EXT2_S_IFBLK:
        return file_block;
    case EXT2_S_IFCHR:
        return file_stream;
    case EXT2_S_IFIFO:
        return file_fifo;
    case EXT2_S_IFSOCK:
        return file_socket;
    case EXT2_S_IFREG:
    default:
        return file_none;
    }
}

static uint8_t ext_mode_to_dir_file_type(uint16_t mode) {
    switch (mode & S_IFMT) {
    case EXT2_S_IFREG:
        return EXT2_FT_REG_FILE;
    case EXT2_S_IFDIR:
        return EXT2_FT_DIR;
    case EXT2_S_IFCHR:
        return EXT2_FT_CHRDEV;
    case EXT2_S_IFBLK:
        return EXT2_FT_BLKDEV;
    case EXT2_S_IFIFO:
        return EXT2_FT_FIFO;
    case EXT2_S_IFSOCK:
        return EXT2_FT_SOCK;
    case EXT2_S_IFLNK:
        return EXT2_FT_SYMLINK;
    default:
        return EXT2_FT_UNKNOWN;
    }
}

static uint32_t ext_dir_file_type_to_vfs(uint8_t type) {
    switch (type) {
    case EXT2_FT_DIR:
        return file_dir;
    case EXT2_FT_SYMLINK:
        return file_symlink;
    case EXT2_FT_CHRDEV:
        return file_stream;
    case EXT2_FT_BLKDEV:
        return file_block;
    case EXT2_FT_FIFO:
        return file_fifo;
    case EXT2_FT_SOCK:
        return file_socket;
    case EXT2_FT_REG_FILE:
    default:
        return file_none;
    }
}

static uint64_t ext_group_first_block(ext_mount_ctx_t *fs, uint32_t group) {
    return (uint64_t)fs->sb.s_first_data_block +
           (uint64_t)group * fs->sb.s_blocks_per_group;
}

static uint64_t ext_group_blocks_count(ext_mount_ctx_t *fs, uint32_t group) {
    uint64_t start = ext_group_first_block(fs, group);
    if (start >= fs->blocks_count)
        return 0;
    return MIN((uint64_t)fs->sb.s_blocks_per_group, fs->blocks_count - start);
}

static uint64_t ext_group_inodes_count(ext_mount_ctx_t *fs, uint32_t group) {
    uint64_t start = (uint64_t)group * fs->sb.s_inodes_per_group;
    if (start >= fs->inodes_count)
        return 0;
    return MIN((uint64_t)fs->sb.s_inodes_per_group, fs->inodes_count - start);
}

static int ext_dev_read_direct(ext_mount_ctx_t *fs, uint64_t offset, void *buf,
                               size_t size) {
    ssize_t ret = device_read(fs->dev, buf, offset, size, 0);
    if (ret < 0)
        return (int)ret;
    if ((size_t)ret != size)
        return -EIO;
    return 0;
}

static int ext_dev_write_direct(ext_mount_ctx_t *fs, uint64_t offset,
                                const void *buf, size_t size) {
    ssize_t ret = device_write(fs->dev, (void *)buf, offset, size, 0);
    if (ret < 0)
        return (int)ret;
    if ((size_t)ret != size)
        return -EIO;
    return 0;
}

static uint32_t ext_map_cache_default_entries(uint32_t block_size) {
    uint32_t entries;

    if (!block_size)
        return 0;

    entries = EXT_MAP_CACHE_TARGET_BYTES / block_size;
    if (entries < EXT_MAP_CACHE_MIN_ENTRIES)
        entries = EXT_MAP_CACHE_MIN_ENTRIES;
    if (entries > EXT_MAP_CACHE_MAX_ENTRIES)
        entries = EXT_MAP_CACHE_MAX_ENTRIES;
    return entries;
}

static int ext_map_cache_init(ext_mount_ctx_t *fs) {
    if (!fs || !fs->block_size)
        return -EINVAL;

    fs->map_cache_entry_count = ext_map_cache_default_entries(fs->block_size);
    fs->map_cache_entries =
        calloc(fs->map_cache_entry_count, sizeof(*fs->map_cache_entries));
    if (!fs->map_cache_entries)
        return -ENOMEM;

    for (uint32_t i = 0; i < fs->map_cache_entry_count; i++) {
        fs->map_cache_entries[i].data = calloc(1, fs->block_size);
        if (!fs->map_cache_entries[i].data) {
            for (uint32_t j = 0; j < i; j++)
                free(fs->map_cache_entries[j].data);
            free(fs->map_cache_entries);
            fs->map_cache_entries = NULL;
            fs->map_cache_entry_count = 0;
            return -ENOMEM;
        }
    }

    return 0;
}

static void ext_map_cache_destroy(ext_mount_ctx_t *fs) {
    if (!fs || !fs->map_cache_entries)
        return;

    for (uint32_t i = 0; i < fs->map_cache_entry_count; i++)
        free(fs->map_cache_entries[i].data);
    free(fs->map_cache_entries);
    fs->map_cache_entries = NULL;
    fs->map_cache_entry_count = 0;
}

static inline ext_map_cache_entry_t *ext_map_cache_slot(ext_mount_ctx_t *fs,
                                                        uint32_t block) {
    if (!fs || !fs->map_cache_entries || !fs->map_cache_entry_count)
        return NULL;
    return &fs->map_cache_entries[block % fs->map_cache_entry_count];
}

static void ext_map_cache_invalidate_locked(ext_mount_ctx_t *fs,
                                            uint32_t block) {
    ext_map_cache_entry_t *entry = ext_map_cache_slot(fs, block);
    if (!entry)
        return;
    if (entry->valid && entry->block == block)
        entry->valid = false;
}

static int ext_map_cache_read_locked(ext_mount_ctx_t *fs, uint32_t block,
                                     void *buf) {
    ext_map_cache_entry_t *entry = ext_map_cache_slot(fs, block);
    if (entry && entry->valid && entry->block == block) {
        memcpy(buf, entry->data, fs->block_size);
        return 0;
    }

    int ret = ext_dev_read_direct(fs, (uint64_t)block * fs->block_size, buf,
                                  fs->block_size);
    if (ret)
        return ret;

    if (entry) {
        memcpy(entry->data, buf, fs->block_size);
        entry->block = block;
        entry->valid = true;
    }
    return 0;
}

static int ext_map_cache_ref_locked(ext_mount_ctx_t *fs, uint32_t block,
                                    uint8_t **buf_out) {
    if (!buf_out)
        return -EINVAL;

    ext_map_cache_entry_t *entry = ext_map_cache_slot(fs, block);
    if (!entry || !entry->data)
        return -EINVAL;

    if (!entry->valid || entry->block != block) {
        int ret = ext_dev_read_direct(fs, (uint64_t)block * fs->block_size,
                                      entry->data, fs->block_size);
        if (ret)
            return ret;
        entry->block = block;
        entry->valid = true;
    }

    *buf_out = entry->data;
    return 0;
}

static void ext_map_cache_store_locked(ext_mount_ctx_t *fs, uint32_t block,
                                       const void *buf) {
    ext_map_cache_entry_t *entry = ext_map_cache_slot(fs, block);
    if (!entry)
        return;

    memcpy(entry->data, buf, fs->block_size);
    entry->block = block;
    entry->valid = true;
}

static int ext_inode_offset(ext_mount_ctx_t *fs, uint32_t ino,
                            uint64_t *offset_out) {
    if (!fs || !offset_out || ino == 0 || ino > fs->inodes_count)
        return -EINVAL;

    uint32_t group = (ino - 1) / fs->sb.s_inodes_per_group;
    uint32_t index = (ino - 1) % fs->sb.s_inodes_per_group;
    uint64_t table_block = fs->groups[group].bg_inode_table_lo;
    *offset_out =
        table_block * fs->block_size + (uint64_t)index * fs->inode_size;
    return 0;
}

static int ext_dev_read(ext_mount_ctx_t *fs, uint64_t offset, void *buf,
                        size_t size) {
    if (!size)
        return 0;
    if (!fs || !buf)
        return -EINVAL;
    return ext_dev_read_direct(fs, offset, buf, size);
}

static int ext_dev_write(ext_mount_ctx_t *fs, uint64_t offset, const void *buf,
                         size_t size) {
    if (!size)
        return 0;
    if (!fs || !buf)
        return -EINVAL;
    return ext_dev_write_direct(fs, offset, buf, size);
}

static void ext_fix_root_recursive(vfs_node_t node, vfs_node_t root) {
    if (!node)
        return;

    if (node != root && node == node->root) {
        return;
    }

    node->root = root;

    vfs_node_t child, tmp;
    llist_for_each(child, tmp, &node->childs, node_for_childs) {
        ext_fix_root_recursive(child, root);
    }
}

static void ext_hide_node(vfs_node_t node) {
    if (!node)
        return;

    vfs_detach_child(node);
    node->flags |= VFS_NODE_FLAGS_FREE_AFTER_USE;

    if (node->refcount <= 0 && node->handle == NULL) {
        vfs_free(node);
    }
}

static int ext_read_block(ext_mount_ctx_t *fs, uint32_t block, void *buf) {
    return ext_dev_read(fs, (uint64_t)block * fs->block_size, buf,
                        fs->block_size);
}

static int ext_write_block(ext_mount_ctx_t *fs, uint32_t block,
                           const void *buf) {
    return ext_dev_write(fs, (uint64_t)block * fs->block_size, buf,
                         fs->block_size);
}

static int ext_zero_block(ext_mount_ctx_t *fs, uint32_t block) {
    void *zero = calloc(1, fs->block_size);
    if (!zero)
        return -ENOMEM;
    int ret = ext_write_block(fs, block, zero);
    free(zero);
    return ret;
}

static ext_mount_ctx_t *ext_find_mount(vfs_node_t node) {
    if (!node)
        return NULL;

    ext_mount_ctx_t *ctx, *tmp;
    for (vfs_node_t cur = node; cur; cur = cur->parent) {
        llist_for_each(ctx, tmp, &ext_mounts, node) {
            if (ctx->root == cur)
                return ctx;
        }
    }

    if (node->dev) {
        llist_for_each(ctx, tmp, &ext_mounts, node) {
            if (ctx->dev == node->dev)
                return ctx;
        }
    }

    return NULL;
}

static int ext_write_super(ext_mount_ctx_t *fs) {
    fs->sb.s_wtime = (uint32_t)ext_now();
    return ext_dev_write(fs, 1024, &fs->sb, sizeof(fs->sb));
}

static int ext_write_group_desc(ext_mount_ctx_t *fs, uint32_t group) {
    uint64_t gdt_block = fs->block_size == 1024 ? 2 : 1;
    uint64_t offset =
        gdt_block * fs->block_size + (uint64_t)group * fs->desc_size;
    return ext_dev_write(fs, offset, &fs->groups[group],
                         MIN((size_t)fs->desc_size, sizeof(ext_group_desc_t)));
}

static int ext_read_inode(ext_mount_ctx_t *fs, uint32_t ino,
                          ext_inode_disk_t *inode) {
    if (!fs || !inode || ino == 0 || ino > fs->inodes_count)
        return -EINVAL;

    uint64_t offset = 0;
    int ret = ext_inode_offset(fs, ino, &offset);
    if (ret)
        return ret;

    uint8_t *raw = calloc(1, fs->inode_size);
    if (!raw)
        return -ENOMEM;

    ret = ext_dev_read(fs, offset, raw, fs->inode_size);
    if (!ret)
        memcpy(inode, raw, MIN((size_t)fs->inode_size, sizeof(*inode)));

    free(raw);
    return ret;
}

static int ext_write_inode(ext_mount_ctx_t *fs, uint32_t ino,
                           const ext_inode_disk_t *inode) {
    if (!fs || !inode || ino == 0 || ino > fs->inodes_count)
        return -EINVAL;

    uint64_t offset = 0;
    int ret = ext_inode_offset(fs, ino, &offset);
    if (ret)
        return ret;

    uint8_t *raw = calloc(1, fs->inode_size);
    if (!raw)
        return -ENOMEM;

    ret = ext_dev_read(fs, offset, raw, fs->inode_size);
    if (ret) {
        free(raw);
        return ret;
    }

    memcpy(raw, inode, MIN((size_t)fs->inode_size, sizeof(*inode)));
    ret = ext_dev_write(fs, offset, raw, fs->inode_size);
    free(raw);
    return ret;
}

static void ext_copy_runtime_inode_state(ext_inode_disk_t *dst,
                                         const ext_inode_disk_t *src) {
    if (!dst || !src)
        return;

    ext_inode_size_set(dst, ext_inode_size_get(src));
    ext_inode_blocks_set(dst, ext_inode_blocks_get(src));
    memcpy(dst->i_block, src->i_block, sizeof(dst->i_block));
    dst->i_mtime = src->i_mtime;
    dst->i_ctime = src->i_ctime;
}

static int ext_flush_handle_inode_locked(ext_mount_ctx_t *fs, vfs_node_t node,
                                         ext_handle_t *handle,
                                         ext_inode_disk_t *inode_out) {
    if (!fs || !handle || !handle->inode_valid) {
        if (inode_out)
            memset(inode_out, 0, sizeof(*inode_out));
        return 0;
    }

    ext_inode_disk_t inode = handle->inode_cache;

    if (handle->inode_dirty && (node->type & file_none)) {
        ext_inode_disk_t disk_inode = {0};
        int ret = ext_read_inode(fs, handle->ino, &disk_inode);
        if (ret)
            return ret;

        ext_copy_runtime_inode_state(&disk_inode, &inode);
        ret = ext_write_inode(fs, handle->ino, &disk_inode);
        if (ret)
            return ret;

        inode = disk_inode;
        handle->inode_cache = inode;
        handle->inode_dirty = false;
        ext_sync_node_from_inode(node, fs, &inode);
    }

    if (inode_out)
        *inode_out = inode;
    return 0;
}

static void ext_sync_node_from_inode(vfs_node_t node, ext_mount_ctx_t *fs,
                                     const ext_inode_disk_t *inode) {
    node->fsid = ext_fsid;
    node->dev = fs->dev;
    node->blksz = fs->block_size;
    node->size = ext_inode_size_get(inode);
    node->realsize = ext_inode_blocks_get(inode) * 512;
    node->createtime = inode->i_crtime ? inode->i_crtime : inode->i_ctime;
    node->readtime = inode->i_atime;
    node->writetime = inode->i_mtime;
    node->owner = ext_inode_uid_get(inode);
    node->group = ext_inode_gid_get(inode);
    node->mode = inode->i_mode & 07777;
    node->type = ext_mode_to_vfs_type(inode->i_mode);
    if ((node->type & file_block) || (node->type & file_stream))
        node->rdev = ext_inode_rdev_get(inode);
    else
        node->rdev = fs->dev;
}

static int ext_lookup_name_locked(ext_mount_ctx_t *fs, uint32_t dir_ino,
                                  const char *name, ext_dir_lookup_t *result) {
    if (!fs || !name || !result)
        return -EINVAL;

    ext_inode_disk_t dir_inode = {0};
    int ret = ext_read_inode(fs, dir_ino, &dir_inode);
    if (ret)
        return ret;
    if ((dir_inode.i_mode & S_IFMT) != EXT2_S_IFDIR)
        return -ENOTDIR;

    memset(result, 0, sizeof(*result));
    uint64_t dir_size = ext_inode_size_get(&dir_inode);
    uint32_t blocks =
        (uint32_t)((dir_size + fs->block_size - 1) / fs->block_size);
    uint8_t *buf = calloc(1, fs->block_size);
    if (!buf)
        return -ENOMEM;

    for (uint32_t lblock = 0; lblock < blocks; lblock++) {
        uint32_t pblock = 0;
        uint32_t offsets[4] = {0};
        uint32_t depth = 0;
        uint32_t ptrs = fs->ptrs_per_block;
        uint32_t logical = lblock;
        if (logical < EXT2_NDIR_BLOCKS) {
            depth = 1;
            offsets[0] = logical;
        } else if ((logical -= EXT2_NDIR_BLOCKS) < ptrs) {
            depth = 2;
            offsets[0] = EXT2_IND_BLOCK;
            offsets[1] = logical;
        } else if ((logical -= ptrs) < ptrs * ptrs) {
            depth = 3;
            offsets[0] = EXT2_DIND_BLOCK;
            offsets[1] = logical / ptrs;
            offsets[2] = logical % ptrs;
        } else {
            logical -= ptrs * ptrs;
            depth = 4;
            offsets[0] = EXT2_TIND_BLOCK;
            offsets[1] = logical / (ptrs * ptrs);
            offsets[2] = (logical / ptrs) % ptrs;
            offsets[3] = logical % ptrs;
        }

        pblock = dir_inode.i_block[offsets[0]];
        if (!pblock)
            continue;
        for (uint32_t level = 1; level < depth; level++) {
            ret = ext_read_block(fs, pblock, buf);
            if (ret) {
                free(buf);
                return ret;
            }
            uint32_t *entries = (uint32_t *)buf;
            pblock = entries[offsets[level]];
            if (!pblock)
                break;
        }
        if (!pblock)
            continue;

        ret = ext_read_block(fs, pblock, buf);
        if (ret) {
            free(buf);
            return ret;
        }

        bool has_prev = false;
        uint16_t prev_off = 0;
        uint16_t prev_rec = 0;
        for (uint32_t off = 0;
             off + sizeof(ext_dir_entry_t) <= fs->block_size;) {
            ext_dir_entry_t *entry = (ext_dir_entry_t *)(buf + off);
            if (entry->rec_len < 8 || (entry->rec_len & 3) ||
                off + entry->rec_len > fs->block_size) {
                free(buf);
                return -EIO;
            }
            if (entry->inode && entry->name_len == strlen(name) &&
                !memcmp(entry->name, name, entry->name_len)) {
                result->found = true;
                result->inode = entry->inode;
                result->file_type = entry->file_type;
                result->lblock = lblock;
                result->offset = off;
                result->rec_len = entry->rec_len;
                result->has_prev = has_prev;
                result->prev_offset = prev_off;
                result->prev_rec_len = prev_rec;
                free(buf);
                return 0;
            }
            if (entry->inode) {
                has_prev = true;
                prev_off = off;
                prev_rec = entry->rec_len;
            }
            off += entry->rec_len;
        }
    }

    free(buf);
    return 0;
}

static int ext_bitmap_update(ext_mount_ctx_t *fs, uint32_t block, uint32_t bit,
                             bool set) {
    uint8_t *bitmap = calloc(1, fs->block_size);
    if (!bitmap)
        return -ENOMEM;
    int ret = ext_read_block(fs, block, bitmap);
    if (ret) {
        free(bitmap);
        return ret;
    }
    uint8_t mask = (uint8_t)(1u << (bit & 7));
    if (set)
        bitmap[bit >> 3] |= mask;
    else
        bitmap[bit >> 3] &= (uint8_t)~mask;
    ret = ext_write_block(fs, block, bitmap);
    free(bitmap);
    return ret;
}

static int ext_alloc_inode_locked(ext_mount_ctx_t *fs, uint16_t mode,
                                  uint32_t *out_ino) {
    if (!fs || !out_ino)
        return -EINVAL;

    for (uint32_t group = 0; group < fs->group_count; group++) {
        ext_group_desc_t *gd = &fs->groups[group];
        if (!gd->bg_free_inodes_count_lo)
            continue;

        uint64_t inode_count = ext_group_inodes_count(fs, group);
        uint8_t *bitmap = calloc(1, fs->block_size);
        if (!bitmap)
            return -ENOMEM;
        int ret = ext_read_block(fs, gd->bg_inode_bitmap_lo, bitmap);
        if (ret) {
            free(bitmap);
            return ret;
        }

        for (uint32_t bit = 0; bit < inode_count; bit++) {
            if (bitmap[bit >> 3] & (1u << (bit & 7)))
                continue;
            bitmap[bit >> 3] |= (uint8_t)(1u << (bit & 7));
            ret = ext_write_block(fs, gd->bg_inode_bitmap_lo, bitmap);
            free(bitmap);
            if (ret)
                return ret;

            gd->bg_free_inodes_count_lo--;
            if ((mode & S_IFMT) == EXT2_S_IFDIR)
                gd->bg_used_dirs_count_lo++;
            fs->sb.s_free_inodes_count--;
            ret = ext_write_group_desc(fs, group);
            if (ret)
                return ret;
            ret = ext_write_super(fs);
            if (ret)
                return ret;

            *out_ino = group * fs->sb.s_inodes_per_group + bit + 1;

            uint8_t *empty = calloc(1, fs->inode_size);
            if (!empty)
                return -ENOMEM;
            uint64_t table_block = gd->bg_inode_table_lo;
            uint64_t offset =
                table_block * fs->block_size + (uint64_t)bit * fs->inode_size;
            ret = ext_dev_write(fs, offset, empty, fs->inode_size);
            free(empty);
            return ret;
        }

        free(bitmap);
    }

    return -ENOSPC;
}

static int ext_free_inode_locked(ext_mount_ctx_t *fs, uint32_t ino,
                                 bool is_dir) {
    if (!fs || ino == 0 || ino > fs->inodes_count)
        return -EINVAL;

    uint32_t group = (ino - 1) / fs->sb.s_inodes_per_group;
    uint32_t bit = (ino - 1) % fs->sb.s_inodes_per_group;
    ext_group_desc_t *gd = &fs->groups[group];
    int ret = ext_bitmap_update(fs, gd->bg_inode_bitmap_lo, bit, false);
    if (ret)
        return ret;

    gd->bg_free_inodes_count_lo++;
    if (is_dir && gd->bg_used_dirs_count_lo)
        gd->bg_used_dirs_count_lo--;
    fs->sb.s_free_inodes_count++;
    ret = ext_write_group_desc(fs, group);
    if (ret)
        return ret;
    return ext_write_super(fs);
}

static int ext_alloc_block_locked(ext_mount_ctx_t *fs, uint32_t prefer_group,
                                  uint32_t *out_block) {
    if (!fs || !out_block)
        return -EINVAL;

    for (uint32_t pass = 0; pass < fs->group_count; pass++) {
        uint32_t group = (prefer_group + pass) % fs->group_count;
        ext_group_desc_t *gd = &fs->groups[group];
        if (!gd->bg_free_blocks_count_lo)
            continue;

        uint64_t block_count = ext_group_blocks_count(fs, group);
        uint8_t *bitmap = calloc(1, fs->block_size);
        if (!bitmap)
            return -ENOMEM;
        int ret = ext_read_block(fs, gd->bg_block_bitmap_lo, bitmap);
        if (ret) {
            free(bitmap);
            return ret;
        }

        for (uint32_t bit = 0; bit < block_count; bit++) {
            if (bitmap[bit >> 3] & (1u << (bit & 7)))
                continue;
            bitmap[bit >> 3] |= (uint8_t)(1u << (bit & 7));
            ret = ext_write_block(fs, gd->bg_block_bitmap_lo, bitmap);
            free(bitmap);
            if (ret)
                return ret;

            gd->bg_free_blocks_count_lo--;
            fs->sb.s_free_blocks_count_lo--;
            ret = ext_write_group_desc(fs, group);
            if (ret)
                return ret;
            ret = ext_write_super(fs);
            if (ret)
                return ret;

            *out_block = (uint32_t)(ext_group_first_block(fs, group) + bit);
            return ext_zero_block(fs, *out_block);
        }

        free(bitmap);
    }

    return -ENOSPC;
}

static int ext_free_block_locked(ext_mount_ctx_t *fs, uint32_t block) {
    if (!fs || block < fs->sb.s_first_data_block || block >= fs->blocks_count)
        return -EINVAL;

    ext_map_cache_invalidate_locked(fs, block);

    uint32_t group =
        (block - fs->sb.s_first_data_block) / fs->sb.s_blocks_per_group;
    uint32_t bit =
        (block - fs->sb.s_first_data_block) % fs->sb.s_blocks_per_group;
    ext_group_desc_t *gd = &fs->groups[group];

    int ret = ext_bitmap_update(fs, gd->bg_block_bitmap_lo, bit, false);
    if (ret)
        return ret;

    gd->bg_free_blocks_count_lo++;
    fs->sb.s_free_blocks_count_lo++;
    ret = ext_write_group_desc(fs, group);
    if (ret)
        return ret;
    return ext_write_super(fs);
}

static int ext_lblock_path(ext_mount_ctx_t *fs, uint32_t lblock,
                           uint32_t offsets[4], uint32_t *depth) {
    uint32_t ptrs = fs->ptrs_per_block;
    if (lblock < EXT2_NDIR_BLOCKS) {
        offsets[0] = lblock;
        *depth = 1;
        return 0;
    }

    lblock -= EXT2_NDIR_BLOCKS;
    if (lblock < ptrs) {
        offsets[0] = EXT2_IND_BLOCK;
        offsets[1] = lblock;
        *depth = 2;
        return 0;
    }

    lblock -= ptrs;
    if (lblock < ptrs * ptrs) {
        offsets[0] = EXT2_DIND_BLOCK;
        offsets[1] = lblock / ptrs;
        offsets[2] = lblock % ptrs;
        *depth = 3;
        return 0;
    }

    lblock -= ptrs * ptrs;
    uint64_t tmax = (uint64_t)ptrs * ptrs * ptrs;
    if (lblock < tmax) {
        offsets[0] = EXT2_TIND_BLOCK;
        offsets[1] = lblock / (ptrs * ptrs);
        offsets[2] = (lblock / ptrs) % ptrs;
        offsets[3] = lblock % ptrs;
        *depth = 4;
        return 0;
    }

    return -EFBIG;
}

static int ext_block_all_zero(void *buf, uint32_t count) {
    uint32_t *entries = (uint32_t *)buf;
    for (uint32_t i = 0; i < count; i++) {
        if (entries[i])
            return 0;
    }
    return 1;
}

static int ext_inode_get_block_run_locked(ext_mount_ctx_t *fs, uint32_t ino,
                                          ext_inode_disk_t *inode,
                                          uint32_t logical_block, bool create,
                                          uint32_t *out_block,
                                          uint32_t *out_run_blocks,
                                          uint32_t max_run_blocks) {
    uint32_t offsets[4] = {0};
    uint32_t depth = 0;
    int ret = ext_lblock_path(fs, logical_block, offsets, &depth);
    if (ret)
        return ret;

    if (!out_block || !out_run_blocks)
        return -EINVAL;
    if (max_run_blocks == 0)
        max_run_blocks = 1;

    uint32_t prefer_group = (ino - 1) / fs->sb.s_inodes_per_group;

    if (depth == 1) {
        if (!inode->i_block[offsets[0]] && create) {
            uint32_t first = 0;
            ret = ext_alloc_block_locked(fs, prefer_group, &first);
            if (ret)
                return ret;
            inode->i_block[offsets[0]] = first;
            ext_inode_add_fs_blocks(fs, inode, 1);
        }
        *out_block = inode->i_block[offsets[0]];
        *out_run_blocks = 1;

        uint32_t limit =
            MIN((uint32_t)EXT2_NDIR_BLOCKS - offsets[0], max_run_blocks);
        for (uint32_t run = 1; run < limit; run++) {
            uint32_t slot = inode->i_block[offsets[0] + run];
            if (!slot && create) {
                ret = ext_alloc_block_locked(fs, prefer_group, &slot);
                if (ret)
                    return ret;
                inode->i_block[offsets[0] + run] = slot;
                ext_inode_add_fs_blocks(fs, inode, 1);
            }

            if (*out_block == 0) {
                if (slot != 0)
                    break;
            } else if (slot != *out_block + run) {
                break;
            }
            *out_run_blocks = run + 1;
        }
        return 0;
    }

    uint32_t cur = inode->i_block[offsets[0]];
    if (!cur && create) {
        ret = ext_alloc_block_locked(fs, prefer_group, &cur);
        if (ret)
            return ret;
        inode->i_block[offsets[0]] = cur;
        ext_inode_add_fs_blocks(fs, inode, 1);
    }
    if (!cur) {
        *out_block = 0;
        *out_run_blocks = 1;
        return 0;
    }

    uint8_t *buf = NULL;

    for (uint32_t level = 1; level < depth - 1; level++) {
        ret = ext_map_cache_ref_locked(fs, cur, &buf);
        if (ret)
            return ret;

        uint32_t *entries = (uint32_t *)buf;
        uint32_t next = entries[offsets[level]];
        if (!next && create) {
            ret = ext_alloc_block_locked(fs, prefer_group, &next);
            if (ret)
                return ret;
            entries[offsets[level]] = next;
            ret = ext_write_block(fs, cur, buf);
            if (ret)
                return ret;
            ext_inode_add_fs_blocks(fs, inode, 1);
        }
        if (!next) {
            *out_block = 0;
            *out_run_blocks = 1;
            return 0;
        }
        cur = next;
    }

    ret = ext_map_cache_ref_locked(fs, cur, &buf);
    if (ret)
        return ret;

    uint32_t *entries = (uint32_t *)buf;
    uint32_t first = entries[offsets[depth - 1]];
    bool dirty = false;
    if (!first && create) {
        ret = ext_alloc_block_locked(fs, prefer_group, &first);
        if (ret)
            return ret;
        entries[offsets[depth - 1]] = first;
        ext_inode_add_fs_blocks(fs, inode, 1);
        dirty = true;
    }

    *out_block = first;
    *out_run_blocks = 1;

    uint32_t limit =
        MIN(fs->ptrs_per_block - offsets[depth - 1], max_run_blocks);
    for (uint32_t run = 1; run < limit; run++) {
        uint32_t *slot = &entries[offsets[depth - 1] + run];
        if (!*slot && create) {
            ret = ext_alloc_block_locked(fs, prefer_group, slot);
            if (ret)
                return ret;
            ext_inode_add_fs_blocks(fs, inode, 1);
            dirty = true;
        }

        if (first == 0) {
            if (*slot != 0)
                break;
        } else if (*slot != first + run) {
            break;
        }
        *out_run_blocks = run + 1;
    }

    if (dirty) {
        ret = ext_write_block(fs, cur, buf);
        if (ret)
            return ret;
    }

    return 0;
}

static int ext_inode_get_block_locked(ext_mount_ctx_t *fs, uint32_t ino,
                                      ext_inode_disk_t *inode,
                                      uint32_t logical_block, bool create,
                                      uint32_t *out_block) {
    uint32_t run_blocks = 0;
    return ext_inode_get_block_run_locked(fs, ino, inode, logical_block, create,
                                          out_block, &run_blocks, 1);
}

static int ext_inode_clear_block_locked(ext_mount_ctx_t *fs,
                                        ext_inode_disk_t *inode,
                                        uint32_t logical_block) {
    uint32_t offsets[4] = {0};
    uint32_t depth = 0;
    int ret = ext_lblock_path(fs, logical_block, offsets, &depth);
    if (ret)
        return ret;

    if (depth == 1) {
        uint32_t block = inode->i_block[offsets[0]];
        if (!block)
            return 0;
        ret = ext_free_block_locked(fs, block);
        if (ret)
            return ret;
        inode->i_block[offsets[0]] = 0;
        ext_inode_sub_fs_blocks(fs, inode, 1);
        return 0;
    }

    uint32_t blocks[3] = {0};
    uint8_t *bufs[3] = {0};
    uint32_t *entries[3] = {0};

    uint32_t cur = inode->i_block[offsets[0]];
    if (!cur)
        return 0;

    for (uint32_t level = 1; level < depth; level++) {
        bufs[level - 1] = calloc(1, fs->block_size);
        if (!bufs[level - 1]) {
            ret = -ENOMEM;
            goto cleanup;
        }
        ret = ext_map_cache_read_locked(fs, cur, bufs[level - 1]);
        if (ret)
            goto cleanup;
        blocks[level - 1] = cur;
        entries[level - 1] = (uint32_t *)bufs[level - 1];
        cur = entries[level - 1][offsets[level]];
        if (!cur) {
            ret = 0;
            goto cleanup;
        }
    }

    ret = ext_free_block_locked(fs, cur);
    if (ret)
        goto cleanup;
    ext_inode_sub_fs_blocks(fs, inode, 1);
    entries[depth - 2][offsets[depth - 1]] = 0;

    for (int level = (int)depth - 2; level >= 0; level--) {
        if (!ext_block_all_zero(bufs[level], fs->ptrs_per_block)) {
            ret = ext_write_block(fs, blocks[level], bufs[level]);
            if (ret)
                goto cleanup;
            ext_map_cache_store_locked(fs, blocks[level], bufs[level]);
            break;
        }

        ret = ext_free_block_locked(fs, blocks[level]);
        if (ret)
            goto cleanup;
        ext_inode_sub_fs_blocks(fs, inode, 1);

        if (level == 0) {
            inode->i_block[offsets[0]] = 0;
            break;
        }
        entries[level - 1][offsets[level]] = 0;
    }

cleanup:
    for (size_t i = 0; i < 3; i++)
        free(bufs[i]);
    return ret;
}

static int ext_inode_truncate_locked(ext_mount_ctx_t *fs, uint32_t ino,
                                     ext_inode_disk_t *inode,
                                     uint64_t new_size) {
    uint64_t old_size = ext_inode_size_get(inode);
    uint64_t old_blocks = (old_size + fs->block_size - 1) / fs->block_size;
    uint64_t new_blocks = (new_size + fs->block_size - 1) / fs->block_size;

    while (old_blocks > new_blocks) {
        int ret =
            ext_inode_clear_block_locked(fs, inode, (uint32_t)(old_blocks - 1));
        if (ret)
            return ret;
        old_blocks--;
    }

    ext_inode_size_set(inode, new_size);
    ext_inode_touch(inode, false, true, true);
    return ext_write_inode(fs, ino, inode);
}

static int ext_read_inode_data_locked(ext_mount_ctx_t *fs, uint32_t ino,
                                      ext_inode_disk_t *inode, void *buf,
                                      size_t offset, size_t size) {
    uint64_t file_size = ext_inode_size_get(inode);
    if (offset >= file_size)
        return 0;

    size_t total = MIN((size_t)(file_size - offset), size);
    size_t done = 0;
    uint8_t *block = calloc(1, fs->block_size);
    if (!block)
        return -ENOMEM;

    while (done < total) {
        uint64_t pos = offset + done;
        uint32_t lblock = (uint32_t)(pos / fs->block_size);
        uint32_t boff = (uint32_t)(pos % fs->block_size);
        size_t chunk = MIN((size_t)fs->block_size - boff, total - done);

        if (boff == 0 && chunk == fs->block_size) {
            uint32_t pblock = 0;
            uint32_t run_blocks = 0;
            uint32_t max_blocks = (uint32_t)((total - done) / fs->block_size);
            int ret = ext_inode_get_block_run_locked(fs, ino, inode, lblock,
                                                     false, &pblock,
                                                     &run_blocks, max_blocks);
            if (ret) {
                free(block);
                return ret;
            }
            size_t run_size = (size_t)run_blocks * fs->block_size;

            if (!pblock) {
                memset((uint8_t *)buf + done, 0, run_size);
            } else {
                ret = ext_dev_read_direct(fs, (uint64_t)pblock * fs->block_size,
                                          (uint8_t *)buf + done, run_size);
                if (ret) {
                    free(block);
                    return ret;
                }
            }

            done += run_size;
            continue;
        }

        uint32_t pblock = 0;
        int ret =
            ext_inode_get_block_locked(fs, ino, inode, lblock, false, &pblock);
        if (ret) {
            free(block);
            return ret;
        }
        if (!pblock) {
            memset((uint8_t *)buf + done, 0, chunk);
        } else {
            ret = ext_dev_read_direct(fs, (uint64_t)pblock * fs->block_size,
                                      block, fs->block_size);
            if (ret) {
                free(block);
                return ret;
            }
            memcpy((uint8_t *)buf + done, block + boff, chunk);
        }
        done += chunk;
    }

    free(block);
    return (int)done;
}

static int ext_write_inode_data_locked(ext_mount_ctx_t *fs, uint32_t ino,
                                       ext_inode_disk_t *inode, const void *buf,
                                       size_t offset, size_t size) {
    size_t done = 0;
    uint8_t *block = calloc(1, fs->block_size);
    if (!block)
        return -ENOMEM;

    while (done < size) {
        uint64_t pos = offset + done;
        uint32_t lblock = (uint32_t)(pos / fs->block_size);
        uint32_t boff = (uint32_t)(pos % fs->block_size);
        size_t chunk = MIN((size_t)fs->block_size - boff, size - done);

        if (boff == 0 && chunk == fs->block_size) {
            uint32_t pblock = 0;
            uint32_t run_blocks = 0;
            uint32_t max_blocks = (uint32_t)((size - done) / fs->block_size);
            int ret = ext_inode_get_block_run_locked(
                fs, ino, inode, lblock, true, &pblock, &run_blocks, max_blocks);
            if (ret) {
                free(block);
                return ret;
            }
            if (!pblock) {
                free(block);
                return -ENOSPC;
            }
            size_t run_size = (size_t)run_blocks * fs->block_size;

            ret = ext_dev_write_direct(fs, (uint64_t)pblock * fs->block_size,
                                       (const uint8_t *)buf + done, run_size);
            if (ret) {
                free(block);
                return ret;
            }

            done += run_size;
            continue;
        }

        uint32_t pblock = 0;
        int ret =
            ext_inode_get_block_locked(fs, ino, inode, lblock, true, &pblock);
        if (ret) {
            free(block);
            return ret;
        }
        if (!pblock) {
            free(block);
            return -ENOSPC;
        }

        if (chunk != fs->block_size || boff != 0) {
            ret = ext_dev_read_direct(fs, (uint64_t)pblock * fs->block_size,
                                      block, fs->block_size);
            if (ret) {
                free(block);
                return ret;
            }
        } else {
            memset(block, 0, fs->block_size);
        }

        memcpy(block + boff, (const uint8_t *)buf + done, chunk);
        ret = ext_dev_write_direct(fs, (uint64_t)pblock * fs->block_size, block,
                                   fs->block_size);
        if (ret) {
            free(block);
            return ret;
        }
        done += chunk;
    }

    uint64_t end = (uint64_t)offset + size;
    if (end > ext_inode_size_get(inode))
        ext_inode_size_set(inode, end);
    ext_inode_touch(inode, false, true, true);
    free(block);
    return (int)done;
}

static int ext_dir_find_locked(ext_mount_ctx_t *fs, uint32_t dir_ino,
                               ext_inode_disk_t *dir_inode, const char *name,
                               ext_dir_lookup_t *result) {
    if (!dir_inode)
        return -EINVAL;

    uint64_t dir_size = ext_inode_size_get(dir_inode);
    uint32_t blocks =
        (uint32_t)((dir_size + fs->block_size - 1) / fs->block_size);
    uint8_t *buf = calloc(1, fs->block_size);
    if (!buf)
        return -ENOMEM;

    memset(result, 0, sizeof(*result));

    for (uint32_t lblock = 0; lblock < blocks; lblock++) {
        uint32_t pblock = 0;
        int ret = ext_inode_get_block_locked(fs, dir_ino, dir_inode, lblock,
                                             false, &pblock);
        if (ret) {
            free(buf);
            return ret;
        }
        if (!pblock)
            continue;

        ret = ext_read_block(fs, pblock, buf);
        if (ret) {
            free(buf);
            return ret;
        }

        bool has_prev = false;
        uint16_t prev_off = 0;
        uint16_t prev_rec = 0;
        for (uint32_t off = 0;
             off + sizeof(ext_dir_entry_t) <= fs->block_size;) {
            ext_dir_entry_t *entry = (ext_dir_entry_t *)(buf + off);
            if (entry->rec_len < 8 || (entry->rec_len & 3) ||
                off + entry->rec_len > fs->block_size) {
                free(buf);
                return -EIO;
            }
            if (entry->inode && entry->name_len == strlen(name) &&
                !memcmp(entry->name, name, entry->name_len)) {
                result->found = true;
                result->inode = entry->inode;
                result->file_type = entry->file_type;
                result->lblock = lblock;
                result->offset = off;
                result->rec_len = entry->rec_len;
                result->has_prev = has_prev;
                result->prev_offset = prev_off;
                result->prev_rec_len = prev_rec;
                free(buf);
                return 0;
            }
            if (entry->inode) {
                has_prev = true;
                prev_off = off;
                prev_rec = entry->rec_len;
            }
            off += entry->rec_len;
        }
    }

    free(buf);
    return 0;
}

static int ext_dir_add_entry_locked(ext_mount_ctx_t *fs, uint32_t dir_ino,
                                    ext_inode_disk_t *dir_inode,
                                    uint32_t child_ino, const char *name,
                                    uint8_t file_type) {
    size_t name_len = strlen(name);
    if (!name_len || name_len > 255)
        return -EINVAL;

    ext_dir_lookup_t lookup = {0};
    int ret = ext_dir_find_locked(fs, dir_ino, dir_inode, name, &lookup);
    if (ret)
        return ret;
    if (lookup.found)
        return -EEXIST;

    uint16_t need = ext_dir_rec_len(name_len);
    uint64_t dir_size = ext_inode_size_get(dir_inode);
    uint32_t blocks =
        (uint32_t)((dir_size + fs->block_size - 1) / fs->block_size);
    uint8_t *buf = calloc(1, fs->block_size);
    if (!buf)
        return -ENOMEM;

    for (uint32_t lblock = 0; lblock < blocks; lblock++) {
        uint32_t pblock = 0;
        ret = ext_inode_get_block_locked(fs, dir_ino, dir_inode, lblock, false,
                                         &pblock);
        if (ret) {
            free(buf);
            return ret;
        }
        if (!pblock)
            continue;

        ret = ext_read_block(fs, pblock, buf);
        if (ret) {
            free(buf);
            return ret;
        }

        for (uint32_t off = 0;
             off + sizeof(ext_dir_entry_t) <= fs->block_size;) {
            ext_dir_entry_t *entry = (ext_dir_entry_t *)(buf + off);
            if (entry->rec_len < 8 || (entry->rec_len & 3) ||
                off + entry->rec_len > fs->block_size) {
                free(buf);
                return -EIO;
            }

            if (!entry->inode && entry->rec_len >= need) {
                uint16_t full_rec_len = entry->rec_len;
                memset(entry, 0, full_rec_len);
                entry->inode = child_ino;
                entry->rec_len = full_rec_len;
                entry->name_len = (uint8_t)name_len;
                entry->file_type = file_type;
                memcpy(entry->name, name, name_len);
                ret = ext_write_block(fs, pblock, buf);
                if (ret) {
                    free(buf);
                    return ret;
                }
                ext_inode_touch(dir_inode, false, true, true);
                free(buf);
                return ext_write_inode(fs, dir_ino, dir_inode);
            }

            if (entry->inode) {
                uint16_t ideal = ext_dir_rec_len(entry->name_len);
                if (entry->rec_len >= ideal + need) {
                    uint16_t old_rec = entry->rec_len;
                    entry->rec_len = ideal;
                    ext_dir_entry_t *new_entry =
                        (ext_dir_entry_t *)((uint8_t *)entry + ideal);
                    memset(new_entry, 0, old_rec - ideal);
                    new_entry->inode = child_ino;
                    new_entry->rec_len = old_rec - ideal;
                    new_entry->name_len = (uint8_t)name_len;
                    new_entry->file_type = file_type;
                    memcpy(new_entry->name, name, name_len);
                    ret = ext_write_block(fs, pblock, buf);
                    if (ret) {
                        free(buf);
                        return ret;
                    }
                    ext_inode_touch(dir_inode, false, true, true);
                    free(buf);
                    return ext_write_inode(fs, dir_ino, dir_inode);
                }
            }
            off += entry->rec_len;
        }
    }

    uint32_t new_lblock = blocks;
    uint32_t pblock = 0;
    ret = ext_inode_get_block_locked(fs, dir_ino, dir_inode, new_lblock, true,
                                     &pblock);
    if (ret) {
        free(buf);
        return ret;
    }
    memset(buf, 0, fs->block_size);
    ext_dir_entry_t *entry = (ext_dir_entry_t *)buf;
    entry->inode = child_ino;
    entry->rec_len = (uint16_t)fs->block_size;
    entry->name_len = (uint8_t)name_len;
    entry->file_type = file_type;
    memcpy(entry->name, name, name_len);
    ret = ext_write_block(fs, pblock, buf);
    if (ret) {
        free(buf);
        return ret;
    }
    if ((uint64_t)(new_lblock + 1) * fs->block_size >
        ext_inode_size_get(dir_inode))
        ext_inode_size_set(dir_inode,
                           (uint64_t)(new_lblock + 1) * fs->block_size);
    ext_inode_touch(dir_inode, false, true, true);
    free(buf);
    return ext_write_inode(fs, dir_ino, dir_inode);
}

static int ext_dir_remove_entry_locked(ext_mount_ctx_t *fs, uint32_t dir_ino,
                                       ext_inode_disk_t *dir_inode,
                                       const char *name,
                                       ext_dir_lookup_t *removed) {
    ext_dir_lookup_t lookup = {0};
    int ret = ext_dir_find_locked(fs, dir_ino, dir_inode, name, &lookup);
    if (ret)
        return ret;
    if (!lookup.found)
        return -ENOENT;

    uint8_t *buf = calloc(1, fs->block_size);
    if (!buf)
        return -ENOMEM;

    uint32_t pblock = 0;
    ret = ext_inode_get_block_locked(fs, dir_ino, dir_inode, lookup.lblock,
                                     false, &pblock);
    if (ret) {
        free(buf);
        return ret;
    }
    ret = ext_read_block(fs, pblock, buf);
    if (ret) {
        free(buf);
        return ret;
    }

    ext_dir_entry_t *entry = (ext_dir_entry_t *)(buf + lookup.offset);
    if (lookup.has_prev) {
        ext_dir_entry_t *prev = (ext_dir_entry_t *)(buf + lookup.prev_offset);
        prev->rec_len += entry->rec_len;
    } else {
        memset(entry, 0, entry->rec_len);
        entry->rec_len = lookup.rec_len;
    }

    ret = ext_write_block(fs, pblock, buf);
    free(buf);
    if (ret)
        return ret;

    ext_inode_touch(dir_inode, false, true, true);
    ret = ext_write_inode(fs, dir_ino, dir_inode);
    if (!ret && removed)
        *removed = lookup;
    return ret;
}

static int ext_dir_replace_entry_locked(ext_mount_ctx_t *fs, uint32_t dir_ino,
                                        ext_inode_disk_t *dir_inode,
                                        const char *name, uint32_t child_ino,
                                        uint8_t file_type) {
    ext_dir_lookup_t lookup = {0};
    int ret = ext_dir_find_locked(fs, dir_ino, dir_inode, name, &lookup);
    if (ret)
        return ret;
    if (!lookup.found)
        return -ENOENT;

    uint8_t *buf = calloc(1, fs->block_size);
    if (!buf)
        return -ENOMEM;

    uint32_t pblock = 0;
    ret = ext_inode_get_block_locked(fs, dir_ino, dir_inode, lookup.lblock,
                                     false, &pblock);
    if (ret) {
        free(buf);
        return ret;
    }

    ret = ext_read_block(fs, pblock, buf);
    if (ret) {
        free(buf);
        return ret;
    }

    ext_dir_entry_t *entry = (ext_dir_entry_t *)(buf + lookup.offset);
    entry->inode = child_ino;
    entry->file_type = file_type;

    ret = ext_write_block(fs, pblock, buf);
    free(buf);
    if (ret)
        return ret;

    ext_inode_touch(dir_inode, false, true, true);
    return ext_write_inode(fs, dir_ino, dir_inode);
}

static int ext_dir_is_empty_locked(ext_mount_ctx_t *fs, uint32_t dir_ino,
                                   ext_inode_disk_t *dir_inode) {
    uint64_t dir_size = ext_inode_size_get(dir_inode);
    uint32_t blocks =
        (uint32_t)((dir_size + fs->block_size - 1) / fs->block_size);
    uint8_t *buf = calloc(1, fs->block_size);
    if (!buf)
        return -ENOMEM;

    for (uint32_t lblock = 0; lblock < blocks; lblock++) {
        uint32_t pblock = 0;
        int ret = ext_inode_get_block_locked(fs, dir_ino, dir_inode, lblock,
                                             false, &pblock);
        if (ret) {
            free(buf);
            return ret;
        }
        if (!pblock)
            continue;
        ret = ext_read_block(fs, pblock, buf);
        if (ret) {
            free(buf);
            return ret;
        }
        for (uint32_t off = 0;
             off + sizeof(ext_dir_entry_t) <= fs->block_size;) {
            ext_dir_entry_t *entry = (ext_dir_entry_t *)(buf + off);
            if (entry->rec_len < 8 || (entry->rec_len & 3) ||
                off + entry->rec_len > fs->block_size) {
                free(buf);
                return -EIO;
            }
            if (entry->inode) {
                bool is_dot = entry->name_len == 1 && entry->name[0] == '.';
                bool is_dotdot = entry->name_len == 2 &&
                                 entry->name[0] == '.' && entry->name[1] == '.';
                if (!is_dot && !is_dotdot) {
                    free(buf);
                    return 0;
                }
            }
            off += entry->rec_len;
        }
    }

    free(buf);
    return 1;
}

static int ext_dir_set_dotdot_locked(ext_mount_ctx_t *fs, uint32_t dir_ino,
                                     ext_inode_disk_t *dir_inode,
                                     uint32_t new_parent_ino) {
    uint64_t dir_size = ext_inode_size_get(dir_inode);
    uint32_t blocks =
        (uint32_t)((dir_size + fs->block_size - 1) / fs->block_size);
    uint8_t *buf = calloc(1, fs->block_size);
    if (!buf)
        return -ENOMEM;

    for (uint32_t lblock = 0; lblock < blocks; lblock++) {
        uint32_t pblock = 0;
        int ret = ext_inode_get_block_locked(fs, dir_ino, dir_inode, lblock,
                                             false, &pblock);
        if (ret) {
            free(buf);
            return ret;
        }
        if (!pblock)
            continue;
        ret = ext_read_block(fs, pblock, buf);
        if (ret) {
            free(buf);
            return ret;
        }
        for (uint32_t off = 0;
             off + sizeof(ext_dir_entry_t) <= fs->block_size;) {
            ext_dir_entry_t *entry = (ext_dir_entry_t *)(buf + off);
            if (entry->rec_len < 8 || (entry->rec_len & 3) ||
                off + entry->rec_len > fs->block_size) {
                free(buf);
                return -EIO;
            }
            bool is_dotdot = entry->inode && entry->name_len == 2 &&
                             entry->name[0] == '.' && entry->name[1] == '.';
            if (is_dotdot) {
                entry->inode = new_parent_ino;
                ret = ext_write_block(fs, pblock, buf);
                free(buf);
                return ret;
            }
            off += entry->rec_len;
        }
    }

    free(buf);
    return -ENOENT;
}

static int ext_release_inode_locked(ext_mount_ctx_t *fs, uint32_t ino,
                                    ext_inode_disk_t *inode) {
    uint64_t blocks = 0;
    if (!((inode->i_mode & S_IFMT) == EXT2_S_IFLNK &&
          ext_inode_blocks_get(inode) == 0)) {
        blocks =
            (ext_inode_size_get(inode) + fs->block_size - 1) / fs->block_size;
    }
    while (blocks > 0) {
        int ret =
            ext_inode_clear_block_locked(fs, inode, (uint32_t)(blocks - 1));
        if (ret)
            return ret;
        blocks--;
    }
    ext_inode_size_set(inode, 0);
    inode->i_dtime = (uint32_t)ext_now();
    int ret = ext_write_inode(fs, ino, inode);
    if (ret)
        return ret;
    return ext_free_inode_locked(fs, ino,
                                 (inode->i_mode & S_IFMT) == EXT2_S_IFDIR);
}

static int ext_drop_link_locked(ext_mount_ctx_t *fs, uint32_t ino,
                                ext_inode_disk_t *inode,
                                vfs_node_t cached_node) {
    if (!fs || !inode)
        return -EINVAL;

    if (inode->i_links_count)
        inode->i_links_count--;
    ext_inode_touch(inode, false, false, true);

    if (inode->i_links_count == 0) {
        if (cached_node && cached_node->refcount > 0) {
            inode->i_dtime = (uint32_t)ext_now();
            return ext_write_inode(fs, ino, inode);
        }
        return ext_release_inode_locked(fs, ino, inode);
    }

    return ext_write_inode(fs, ino, inode);
}

static int ext_lookup_node_locked(vfs_node_t parent, const char *name,
                                  vfs_node_t node) {
    ext_mount_ctx_t *fs = ext_find_mount(parent ? parent : node);
    if (!fs)
        return -ENOENT;
    if (!parent) {
        node->inode = EXT_ROOT_INO;
        ext_inode_disk_t inode = {0};
        int ret = ext_read_inode(fs, node->inode, &inode);
        if (ret)
            return ret;
        ext_sync_node_from_inode(node, fs, &inode);
        return 0;
    }

    ext_dir_lookup_t lookup = {0};
    int ret = ext_lookup_name_locked(fs, parent->inode, name, &lookup);
    if (ret)
        return ret;
    if (!lookup.found)
        return -ENOENT;

    ext_inode_disk_t inode = {0};
    ret = ext_read_inode(fs, lookup.inode, &inode);
    if (ret)
        return ret;

    node->inode = lookup.inode;
    ext_sync_node_from_inode(node, fs, &inode);
    return 0;
}

static void ext_prune_children(vfs_node_t parent, const char *name) {
    if (!parent || !name)
        return;

    uint64_t nodes_count = 0;
    vfs_node_t child, tmp;
    llist_for_each(child, tmp, &parent->childs, node_for_childs) {
        if (!child->name || strcmp(child->name, name))
            continue;
        if (child == child->root)
            continue;
        nodes_count++;
    }

    if (!nodes_count)
        return;

    vfs_node_t *nodes = calloc(nodes_count, sizeof(vfs_node_t));
    if (!nodes)
        return;

    uint64_t idx = 0;
    llist_for_each(child, tmp, &parent->childs, node_for_childs) {
        if (!child->name || strcmp(child->name, name))
            continue;
        if (child == child->root)
            continue;
        nodes[idx++] = child;
    }

    for (uint64_t i = 0; i < idx; i++)
        vfs_free(nodes[i]);

    free(nodes);
}

static void ext_resolve_children_conflict(vfs_node_t parent, const char *name) {
    if (!parent || !name)
        return;

    uint64_t nodes_count = 0;
    vfs_node_t child, tmp;
    llist_for_each(child, tmp, &parent->childs, node_for_childs) {
        if (!child->name || strcmp(child->name, name))
            continue;
        nodes_count++;
    }

    if (nodes_count <= 1)
        return;

    vfs_node_t *nodes = calloc(nodes_count, sizeof(vfs_node_t));
    if (!nodes)
        return;

    uint64_t idx = 0;
    llist_for_each(child, tmp, &parent->childs, node_for_childs) {
        if (!child->name || strcmp(child->name, name))
            continue;
        nodes[idx++] = child;
    }

    vfs_node_t keep = NULL;
    for (uint64_t i = 0; i < idx; i++) {
        if (nodes[i] == nodes[i]->root) {
            keep = nodes[i];
            break;
        }
    }
    if (!keep) {
        for (uint64_t i = 0; i < idx; i++) {
            if (nodes[i]->fsid == (uint32_t)ext_fsid) {
                keep = nodes[i];
                break;
            }
        }
    }
    if (!keep)
        keep = nodes[0];

    for (uint64_t i = 0; i < idx; i++) {
        if (nodes[i] == keep)
            continue;
        ext_hide_node(nodes[i]);
    }

    free(nodes);
}

static int ext_populate_dir_with_fs_locked(ext_mount_ctx_t *fs,
                                           vfs_node_t node) {
    if (!fs)
        return -ENOENT;

    ext_inode_disk_t dir_inode = {0};
    int ret = ext_read_inode(fs, node->inode, &dir_inode);
    if (ret)
        return ret;
    if ((dir_inode.i_mode & S_IFMT) != EXT2_S_IFDIR)
        return -ENOTDIR;

    uint64_t dir_size = ext_inode_size_get(&dir_inode);
    uint32_t blocks =
        (uint32_t)((dir_size + fs->block_size - 1) / fs->block_size);
    uint8_t *buf = calloc(1, fs->block_size);
    if (!buf)
        return -ENOMEM;

    for (uint32_t lblock = 0; lblock < blocks; lblock++) {
        uint32_t pblock = 0;
        ret = ext_inode_get_block_locked(fs, node->inode, &dir_inode, lblock,
                                         false, &pblock);
        if (ret) {
            free(buf);
            return ret;
        }
        if (!pblock)
            continue;
        ret = ext_read_block(fs, pblock, buf);
        if (ret) {
            free(buf);
            return ret;
        }
        for (uint32_t off = 0;
             off + sizeof(ext_dir_entry_t) <= fs->block_size;) {
            ext_dir_entry_t *entry = (ext_dir_entry_t *)(buf + off);
            if (entry->rec_len < 8 || (entry->rec_len & 3) ||
                off + entry->rec_len > fs->block_size) {
                free(buf);
                return -EIO;
            }
            if (entry->inode &&
                !(entry->name_len == 1 && entry->name[0] == '.') &&
                !(entry->name_len == 2 && entry->name[0] == '.' &&
                  entry->name[1] == '.')) {
                char name[256];
                memset(name, 0, sizeof(name));
                memcpy(name, entry->name, entry->name_len);

                vfs_node_t exist = vfs_child_find(node, name);
                if (exist) {
                    if (exist == exist->root) {
                        goto next;
                    }
                    if (exist->fsid != (uint32_t)ext_fsid ||
                        (exist->inode && exist->inode != entry->inode)) {
                        ext_hide_node(exist);
                        exist = NULL;
                    }
                }

                vfs_node_t child = exist;
                if (!child) {
                    child = vfs_child_append(node, name, NULL);
                    if (!child) {
                        free(buf);
                        return -ENOMEM;
                    }
                }
                child->inode = entry->inode;
                child->fsid = ext_fsid;
                child->dev = node->dev;
                child->rdev = node->dev;
                child->blksz = fs->block_size;
                child->type = ext_dir_file_type_to_vfs(entry->file_type);
            }
        next:
            off += entry->rec_len;
        }
    }

    free(buf);
    node->flags |= VFS_NODE_FLAGS_CHILDREN_POPULATED;
    node->flags &= ~VFS_NODE_FLAGS_DIRTY_CHILDREN;
    return 0;
}

static int ext_populate_dir_locked(vfs_node_t node) {
    return ext_populate_dir_with_fs_locked(ext_find_mount(node), node);
}

static int ext_create_inode_common_locked(ext_mount_ctx_t *fs,
                                          vfs_node_t parent, vfs_node_t node,
                                          uint16_t mode, uint32_t rdev,
                                          const void *payload,
                                          size_t payload_size) {
    uint32_t ino = 0;
    int ret = ext_alloc_inode_locked(fs, mode, &ino);
    if (ret)
        return ret;

    ext_inode_disk_t inode = {0};
    inode.i_mode = mode;
    inode.i_links_count = (mode & S_IFMT) == EXT2_S_IFDIR ? 2 : 1;
    ext_inode_uid_set(&inode, node->owner);
    ext_inode_gid_set(&inode, node->group);
    ext_inode_touch(&inode, true, true, true);
    if ((mode & S_IFMT) == EXT2_S_IFCHR || (mode & S_IFMT) == EXT2_S_IFBLK)
        ext_inode_rdev_set(&inode, rdev);

    if ((mode & S_IFMT) == EXT2_S_IFDIR) {
        uint32_t block = 0;
        uint32_t prefer_group = (ino - 1) / fs->sb.s_inodes_per_group;
        ret = ext_alloc_block_locked(fs, prefer_group, &block);
        if (ret)
            goto rollback_inode;
        inode.i_block[0] = block;
        ext_inode_add_fs_blocks(fs, &inode, 1);
        ext_inode_size_set(&inode, fs->block_size);

        uint8_t *buf = calloc(1, fs->block_size);
        if (!buf) {
            ret = -ENOMEM;
            goto rollback_inode_release;
        }
        ext_dir_entry_t *dot = (ext_dir_entry_t *)buf;
        dot->inode = ino;
        dot->rec_len = ext_dir_rec_len(1);
        dot->name_len = 1;
        dot->file_type = EXT2_FT_DIR;
        dot->name[0] = '.';

        ext_dir_entry_t *dotdot = (ext_dir_entry_t *)(buf + dot->rec_len);
        dotdot->inode = parent ? parent->inode : ino;
        dotdot->rec_len = fs->block_size - dot->rec_len;
        dotdot->name_len = 2;
        dotdot->file_type = EXT2_FT_DIR;
        dotdot->name[0] = '.';
        dotdot->name[1] = '.';

        ret = ext_write_block(fs, block, buf);
        free(buf);
        if (ret)
            goto rollback_inode_release;
    } else if ((mode & S_IFMT) == EXT2_S_IFLNK) {
        if (payload_size <= sizeof(inode.i_block)) {
            memcpy(inode.i_block, payload, payload_size);
            ext_inode_size_set(&inode, payload_size);
        } else {
            ret = ext_write_inode_data_locked(fs, ino, &inode, payload, 0,
                                              payload_size);
            if (ret < 0)
                goto rollback_inode_release;
        }
    }

    ret = ext_write_inode(fs, ino, &inode);
    if (ret)
        goto rollback_inode_release;

    ext_inode_disk_t parent_inode = {0};
    ret = ext_read_inode(fs, parent->inode, &parent_inode);
    if (ret)
        goto rollback_inode_release;

    ret = ext_dir_add_entry_locked(fs, parent->inode, &parent_inode, ino,
                                   node->name,
                                   ext_mode_to_dir_file_type(inode.i_mode));
    if (ret)
        goto rollback_inode_release;

    if ((mode & S_IFMT) == EXT2_S_IFDIR) {
        parent_inode.i_links_count++;
        ext_inode_touch(&parent_inode, false, true, true);
        ret = ext_write_inode(fs, parent->inode, &parent_inode);
        if (ret)
            return ret;
    }

    node->inode = ino;
    ext_sync_node_from_inode(node, fs, &inode);
    if ((mode & S_IFMT) == EXT2_S_IFCHR || (mode & S_IFMT) == EXT2_S_IFBLK)
        node->rdev = rdev;
    return 0;

rollback_inode_release:
    ext_release_inode_locked(fs, ino, &inode);
    return ret;
rollback_inode:
    ext_free_inode_locked(fs, ino, (mode & S_IFMT) == EXT2_S_IFDIR);
    return ret;
}

int ext_mount(uint64_t dev, vfs_node_t node) {
    if (!dev || !node)
        return -EINVAL;

    spin_lock(&rwlock);

    bool linked = false;
    ext_mount_ctx_t *fs = calloc(1, sizeof(*fs));
    if (!fs) {
        spin_unlock(&rwlock);
        return -ENOMEM;
    }

    fs->dev = dev;
    int ret = ext_dev_read(fs, 1024, &fs->sb, sizeof(fs->sb));
    if (ret)
        goto fail;
    if (fs->sb.s_magic != EXT_SUPER_MAGIC) {
        ret = -EINVAL;
        goto fail;
    }

    fs->block_size = 1024u << fs->sb.s_log_block_size;
    fs->inode_size =
        fs->sb.s_inode_size ? fs->sb.s_inode_size : EXT2_GOOD_OLD_INODE_SIZE;
    fs->desc_size = fs->sb.s_desc_size ? fs->sb.s_desc_size : 32;
    fs->ptrs_per_block = fs->block_size / sizeof(uint32_t);
    fs->blocks_count = (uint64_t)fs->sb.s_blocks_count_lo |
                       ((uint64_t)fs->sb.s_blocks_count_hi << 32);
    fs->inodes_count = fs->sb.s_inodes_count;
    fs->group_count = (uint32_t)((fs->blocks_count - fs->sb.s_first_data_block +
                                  fs->sb.s_blocks_per_group - 1) /
                                 fs->sb.s_blocks_per_group);

    uint32_t compat_ok =
        EXT2_FEATURE_COMPAT_EXT_ATTR | EXT2_FEATURE_COMPAT_RESIZE_INODE;
    uint32_t ro_ok = EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER |
                     EXT2_FEATURE_RO_COMPAT_LARGE_FILE |
                     EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE;
    uint32_t incompat_ok = EXT2_FEATURE_INCOMPAT_FILETYPE;
    if ((fs->sb.s_feature_compat & ~compat_ok) ||
        (fs->sb.s_feature_ro_compat & ~ro_ok) ||
        (fs->sb.s_feature_incompat & ~incompat_ok)) {
        ret = -ENOTSUP;
        goto fail;
    }

    ret = ext_map_cache_init(fs);
    if (ret)
        goto fail;

    fs->groups = calloc(fs->group_count, sizeof(ext_group_desc_t));
    if (!fs->groups) {
        ret = -ENOMEM;
        goto fail;
    }

    uint64_t gdt_block = fs->block_size == 1024 ? 2 : 1;
    for (uint32_t i = 0; i < fs->group_count; i++) {
        uint64_t offset =
            gdt_block * fs->block_size + (uint64_t)i * fs->desc_size;
        ret =
            ext_dev_read(fs, offset, &fs->groups[i],
                         MIN((size_t)fs->desc_size, sizeof(ext_group_desc_t)));
        if (ret)
            goto fail;
    }

    llist_init_head(&fs->node);
    llist_prepend(&ext_mounts, &fs->node);
    linked = true;
    fs->root = node;

    node->inode = EXT_ROOT_INO;
    node->fsid = ext_fsid;
    node->dev = dev;
    node->rdev = dev;
    node->blksz = fs->block_size;
    node->type = file_dir;

    ext_inode_disk_t root_inode = {0};
    ret = ext_read_inode(fs, EXT_ROOT_INO, &root_inode);
    if (ret) {
        goto fail;
    }
    ext_sync_node_from_inode(node, fs, &root_inode);
    ret = ext_populate_dir_with_fs_locked(fs, node);
    if (ret) {
        goto fail;
    }

    spin_unlock(&rwlock);
    return 0;

fail:
    if (linked)
        llist_delete(&fs->node);
    ext_map_cache_destroy(fs);
    if (fs->groups)
        free(fs->groups);
    free(fs);
    spin_unlock(&rwlock);
    return ret;
}

void ext_unmount(vfs_node_t node) {
    if (!node)
        return;

    spin_lock(&rwlock);
    ext_mount_ctx_t *ctx = ext_find_mount(node);
    if (ctx) {
        llist_delete(&ctx->node);
        ext_map_cache_destroy(ctx);
        free(ctx->groups);
        free(ctx);
    }

    node->dev = node->parent ? node->parent->dev : 0;
    node->rdev = node->parent ? node->parent->rdev : 0;

    vfs_node_t child, tmp;
    uint64_t nodes_count = 0;
    llist_for_each(child, tmp, &node->childs, node_for_childs) {
        nodes_count++;
    }
    vfs_node_t *nodes = calloc(nodes_count, sizeof(vfs_node_t));
    if (nodes) {
        uint64_t idx = 0;
        llist_for_each(child, tmp, &node->childs, node_for_childs) {
            nodes[idx++] = child;
        }
        for (uint64_t i = 0; i < idx; i++)
            vfs_free(nodes[i]);
        free(nodes);
    }
    spin_unlock(&rwlock);
}

int ext_remount(vfs_node_t old, vfs_node_t node) {
    if (!old || !node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *ctx = ext_find_mount(old);
    if (!ctx) {
        spin_unlock(&rwlock);
        return -ENOENT;
    }

    if (old->parent == node) {
        vfs_detach_child(old);
        old->parent = NULL;
    }

    ctx->root = node;
    node->root = node;
    vfs_merge_nodes_to(node, old);
    node->inode = old->inode;
    node->fsid = old->fsid;
    node->dev = old->dev;
    node->rdev = old->rdev;
    node->type = old->type;
    node->mode = old->mode;
    node->blksz = old->blksz;

    int ret = ext_populate_dir_with_fs_locked(ctx, node);
    if (!ret) {
        uint64_t nodes_count = 0;
        vfs_node_t child, tmp;
        llist_for_each(child, tmp, &node->childs, node_for_childs) {
            nodes_count++;
        }

        char **names = calloc(nodes_count, sizeof(char *));
        if (names) {
            uint64_t idx = 0;
            llist_for_each(child, tmp, &node->childs, node_for_childs) {
                names[idx++] = child->name ? strdup(child->name) : NULL;
            }
            for (uint64_t i = 0; i < idx; i++) {
                if (names[i]) {
                    ext_resolve_children_conflict(node, names[i]);
                    free(names[i]);
                }
            }
            free(names);
        }
    }

    ext_fix_root_recursive(node, node);

    spin_unlock(&rwlock);
    return ret;
}

void ext_open(vfs_node_t parent, const char *name, vfs_node_t node) {
    spin_lock(&rwlock);

    ext_mount_ctx_t *fs = ext_find_mount(node ? node : parent);
    if (!fs) {
        spin_unlock(&rwlock);
        return;
    }

    if (node->inode == 0) {
        if (ext_lookup_node_locked(parent, name, node) != 0) {
            spin_unlock(&rwlock);
            return;
        }
    }

    ext_inode_disk_t inode = {0};
    if (ext_read_inode(fs, node->inode, &inode) != 0) {
        spin_unlock(&rwlock);
        return;
    }
    ext_sync_node_from_inode(node, fs, &inode);

    ext_handle_t *handle = node->handle;
    if (!handle) {
        handle = calloc(1, sizeof(*handle));
        if (!handle) {
            spin_unlock(&rwlock);
            return;
        }
        node->handle = handle;
    }
    handle->node = node;
    handle->ino = node->inode;
    handle->inode_cache = inode;
    handle->inode_valid = true;
    handle->inode_dirty = false;

    if (((node->type & file_block) || (node->type & file_stream)) &&
        !handle->device_opened) {
        if (!device_open(node->rdev, NULL)) {
            handle->device_opened = true;
        }
    }

    if ((node->type & file_dir) &&
        (!(node->flags & VFS_NODE_FLAGS_CHILDREN_POPULATED) ||
         (node->flags & VFS_NODE_FLAGS_DIRTY_CHILDREN))) {
        ext_populate_dir_with_fs_locked(fs, node);
    }

    spin_unlock(&rwlock);
}

bool ext_close(vfs_node_t node) {
    ext_handle_t *handle = node ? node->handle : NULL;
    if (!handle)
        return true;

    spin_lock(&rwlock);

    ext_mount_ctx_t *fs = ext_find_mount(node);
    ext_inode_disk_t inode = {0};
    int inode_ret = ext_flush_handle_inode_locked(fs, node, handle, &inode);

    if (handle->device_opened)
        device_close(node->rdev);

    if ((node->flags & VFS_NODE_FLAGS_DELETED) && node->inode) {
        if (fs && !inode_ret) {
            if (!handle->inode_valid) {
                inode_ret = ext_read_inode(fs, handle->ino, &inode);
            }
        }
        if (fs && !inode_ret && inode.i_links_count == 0) {
            ext_release_inode_locked(fs, handle->ino, &inode);
        }
    }

    free(handle);
    node->handle = NULL;

    spin_unlock(&rwlock);
    return true;
}

ssize_t ext_write(fd_t *fd, const void *addr, size_t offset, size_t size) {
    if (!fd || !fd->node)
        return -EBADF;

    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_write(fd->node->rdev, (void *)addr, offset, size,
                            fd->flags);
    }
    if (!(fd->node->type & file_none))
        return -EINVAL;

    spin_lock(&rwlock);
    ext_handle_t *handle = fd->node->handle;
    ext_mount_ctx_t *fs = ext_find_mount(fd->node);
    if (!handle || !fs) {
        spin_unlock(&rwlock);
        return -ENOENT;
    }

    ext_inode_disk_t inode =
        handle->inode_valid ? handle->inode_cache : (ext_inode_disk_t){0};
    int ret = 0;
    if (!handle->inode_valid) {
        ret = ext_read_inode(fs, handle->ino, &inode);
        if (ret) {
            spin_unlock(&rwlock);
            return ret;
        }
        handle->inode_cache = inode;
        handle->inode_valid = true;
    }

    ret = ext_write_inode_data_locked(fs, handle->ino, &inode, addr, offset,
                                      size);
    if (ret >= 0) {
        handle->inode_cache = inode;
        ext_sync_node_from_inode(fd->node, fs, &inode);
        handle->inode_dirty = true;
    }
    spin_unlock(&rwlock);
    return ret;
}

ssize_t ext_read(fd_t *fd, void *addr, size_t offset, size_t size) {
    if (!fd || !fd->node)
        return -EBADF;

    if ((fd->node->type & file_block) || (fd->node->type & file_stream)) {
        return device_read(fd->node->rdev, addr, offset, size, fd->flags);
    }
    if (!(fd->node->type & file_none))
        return -EINVAL;

    spin_lock(&rwlock);
    ext_handle_t *handle = fd->node->handle;
    ext_mount_ctx_t *fs = ext_find_mount(fd->node);
    if (!handle || !fs) {
        spin_unlock(&rwlock);
        return -ENOENT;
    }

    ext_inode_disk_t inode =
        handle->inode_valid ? handle->inode_cache : (ext_inode_disk_t){0};
    int ret = 0;
    if (!handle->inode_valid) {
        ret = ext_read_inode(fs, handle->ino, &inode);
        if (ret) {
            spin_unlock(&rwlock);
            return ret;
        }
        handle->inode_cache = inode;
        handle->inode_valid = true;
    }
    ret =
        ext_read_inode_data_locked(fs, handle->ino, &inode, addr, offset, size);
    if (ret >= 0) {
        handle->inode_cache = inode;
        fd->node->size = ext_inode_size_get(&inode);
        fd->node->realsize = ext_inode_blocks_get(&inode) * 512;
        fd->node->readtime = (uint32_t)ext_now();
    }
    spin_unlock(&rwlock);
    return ret;
}

ssize_t ext_readlink(vfs_node_t node, void *addr, size_t offset, size_t size) {
    if (!node || !(node->type & file_symlink))
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(node);
    if (!fs) {
        spin_unlock(&rwlock);
        return -ENOENT;
    }

    ext_inode_disk_t inode = {0};
    int ret = ext_read_inode(fs, node->inode, &inode);
    if (ret) {
        spin_unlock(&rwlock);
        return ret;
    }

    size_t link_size = (size_t)ext_inode_size_get(&inode);
    if (offset >= link_size) {
        spin_unlock(&rwlock);
        return 0;
    }

    size_t to_copy = MIN(size, link_size - offset);
    if (link_size <= sizeof(inode.i_block)) {
        memcpy(addr, ((uint8_t *)inode.i_block) + offset, to_copy);
        spin_unlock(&rwlock);
        return to_copy;
    }

    char *tmp = calloc(1, link_size);
    if (!tmp) {
        spin_unlock(&rwlock);
        return -ENOMEM;
    }
    ret =
        ext_read_inode_data_locked(fs, node->inode, &inode, tmp, 0, link_size);
    if (ret >= 0)
        memcpy(addr, tmp + offset, to_copy);
    free(tmp);
    spin_unlock(&rwlock);
    return ret < 0 ? ret : (ssize_t)to_copy;
}

int ext_mkfile(vfs_node_t parent, const char *name, vfs_node_t node) {
    (void)name;
    if (!parent || !node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(parent);
    int ret = fs ? ext_create_inode_common_locked(
                       fs, parent, node, EXT2_S_IFREG | 0700, 0, NULL, 0)
                 : -ENOENT;
    spin_unlock(&rwlock);
    return ret;
}

static int ext_link_node_locked(ext_mount_ctx_t *fs, vfs_node_t parent,
                                vfs_node_t target, vfs_node_t node) {
    if (!fs || !parent || !target || !node)
        return -EINVAL;

    ext_mount_ctx_t *target_fs = ext_find_mount(target);
    if (target_fs != fs) {
        return -EXDEV;
    }

    if (!target->inode) {
        int ret = ext_lookup_node_locked(target->parent, target->name, target);
        if (ret)
            return ret;
    }

    ext_inode_disk_t target_inode = {0};
    int ret = ext_read_inode(fs, target->inode, &target_inode);
    if (ret)
        return ret;
    if ((target_inode.i_mode & S_IFMT) == EXT2_S_IFDIR)
        return -EPERM;

    ext_inode_disk_t parent_inode = {0};
    ret = ext_read_inode(fs, parent->inode, &parent_inode);
    if (ret)
        return ret;

    ret = ext_dir_add_entry_locked(
        fs, parent->inode, &parent_inode, target->inode, node->name,
        ext_mode_to_dir_file_type(target_inode.i_mode));
    if (!ret) {
        target_inode.i_links_count++;
        target_inode.i_dtime = 0;
        ext_inode_touch(&target_inode, false, false, true);
        ret = ext_write_inode(fs, target->inode, &target_inode);
        if (!ret) {
            node->inode = target->inode;
            ext_sync_node_from_inode(node, fs, &target_inode);
        }
    }

    return ret;
}

static int ext_link_existing(vfs_node_t parent, vfs_node_t target,
                             vfs_node_t node) {
    if (!parent || !target || !node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(parent);
    int ret = fs ? ext_link_node_locked(fs, parent, target, node) : -ENOENT;
    spin_unlock(&rwlock);
    return ret;
}

int ext_link(vfs_node_t parent, const char *name, vfs_node_t node) {
    if (!parent || !name || !node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(parent);
    if (!fs) {
        spin_unlock(&rwlock);
        return -ENOENT;
    }

    vfs_node_t target = vfs_open(name, O_NOFOLLOW);
    int ret = target ? ext_link_node_locked(fs, parent, target, node) : -ENOENT;

    spin_unlock(&rwlock);
    return ret;
}

int ext_symlink(vfs_node_t parent, const char *name, vfs_node_t node) {
    if (!parent || !name || !node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(parent);
    int ret = fs ? ext_create_inode_common_locked(fs, parent, node,
                                                  EXT2_S_IFLNK | 0777, 0, name,
                                                  strlen(name))
                 : -ENOENT;
    spin_unlock(&rwlock);
    return ret;
}

int ext_mknod(vfs_node_t parent, const char *name, vfs_node_t node,
              uint16_t mode, int dev) {
    (void)name;
    if (!parent || !node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(parent);
    int ret = fs ? ext_create_inode_common_locked(fs, parent, node, mode, dev,
                                                  NULL, 0)
                 : -ENOENT;
    spin_unlock(&rwlock);
    return ret;
}

int ext_mkdir(vfs_node_t parent, const char *name, vfs_node_t node) {
    (void)name;
    if (!parent || !node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(parent);
    int ret = fs ? ext_create_inode_common_locked(
                       fs, parent, node, EXT2_S_IFDIR | 0700, 0, NULL, 0)
                 : -ENOENT;
    spin_unlock(&rwlock);
    return ret;
}

int ext_chmod(vfs_node_t node, uint16_t mode) {
    if (!node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(node);
    if (!fs) {
        spin_unlock(&rwlock);
        return -ENOENT;
    }

    ext_inode_disk_t inode = {0};
    int ret = ext_read_inode(fs, node->inode, &inode);
    if (!ret) {
        inode.i_mode = (inode.i_mode & S_IFMT) | (mode & 07777);
        ext_inode_touch(&inode, false, false, true);
        ret = ext_write_inode(fs, node->inode, &inode);
        if (!ret)
            ext_sync_node_from_inode(node, fs, &inode);
    }
    spin_unlock(&rwlock);
    return ret;
}

int ext_chown(vfs_node_t node, uint64_t uid, uint64_t gid) {
    if (!node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(node);
    if (!fs) {
        spin_unlock(&rwlock);
        return -ENOENT;
    }

    ext_inode_disk_t inode = {0};
    int ret = ext_read_inode(fs, node->inode, &inode);
    if (!ret) {
        ext_inode_uid_set(&inode, (uint32_t)uid);
        ext_inode_gid_set(&inode, (uint32_t)gid);
        ext_inode_touch(&inode, false, false, true);
        ret = ext_write_inode(fs, node->inode, &inode);
        if (!ret)
            ext_sync_node_from_inode(node, fs, &inode);
    }
    spin_unlock(&rwlock);
    return ret;
}

int ext_delete(vfs_node_t parent, vfs_node_t node) {
    if (!parent || !node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(parent);
    if (!fs) {
        spin_unlock(&rwlock);
        return -ENOENT;
    }

    ext_inode_disk_t parent_inode = {0};
    ext_inode_disk_t inode = {0};
    int ret = ext_read_inode(fs, parent->inode, &parent_inode);
    if (ret) {
        spin_unlock(&rwlock);
        return ret;
    }
    ret = ext_read_inode(fs, node->inode, &inode);
    if (ret) {
        spin_unlock(&rwlock);
        return ret;
    }

    if ((inode.i_mode & S_IFMT) == EXT2_S_IFDIR) {
        ret = ext_dir_is_empty_locked(fs, node->inode, &inode);
        if (ret < 0) {
            spin_unlock(&rwlock);
            return ret;
        }
        if (!ret) {
            spin_unlock(&rwlock);
            return -ENOTEMPTY;
        }
    }

    ret = ext_dir_remove_entry_locked(fs, parent->inode, &parent_inode,
                                      node->name, NULL);
    if (ret) {
        spin_unlock(&rwlock);
        return ret;
    }

    if ((inode.i_mode & S_IFMT) == EXT2_S_IFDIR && parent_inode.i_links_count) {
        parent_inode.i_links_count--;
        ext_inode_touch(&parent_inode, false, true, true);
        ret = ext_write_inode(fs, parent->inode, &parent_inode);
        if (ret) {
            spin_unlock(&rwlock);
            return ret;
        }
    }

    if (inode.i_links_count)
        inode.i_links_count--;
    ext_inode_touch(&inode, false, false, true);

    if (inode.i_links_count == 0) {
        if (node->refcount > 0) {
            inode.i_dtime = (uint32_t)ext_now();
            ret = ext_write_inode(fs, node->inode, &inode);
        } else {
            ret = ext_release_inode_locked(fs, node->inode, &inode);
        }
    } else {
        ret = ext_write_inode(fs, node->inode, &inode);
    }

    spin_unlock(&rwlock);
    return ret;
}

int ext_rename(vfs_node_t node, const char *new) {
    if (!node || !new)
        return -EINVAL;

    char *path = strdup(new);
    if (!path)
        return -ENOMEM;

    size_t path_len = strlen(path);
    while (path_len > 1 && path[path_len - 1] == '/') {
        path[--path_len] = '\0';
    }

    char *slash = strrchr(path, '/');
    char *new_name = slash ? slash + 1 : path;
    if (!strlen(new_name)) {
        free(path);
        return -EINVAL;
    }

    char parent_path[512];
    memset(parent_path, 0, sizeof(parent_path));
    if (slash) {
        size_t len = slash == path ? 1 : (size_t)(slash - path);
        memcpy(parent_path, path, len);
        if (len == 0)
            strcpy(parent_path, "/");
    } else {
        strcpy(parent_path, ".");
    }

    vfs_node_t new_parent = vfs_open(parent_path, 0);
    if (!new_parent) {
        free(path);
        return -ENOENT;
    }

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(node);
    if (!fs) {
        free(path);
        spin_unlock(&rwlock);
        return -ENOENT;
    }
    ext_mount_ctx_t *new_fs = ext_find_mount(new_parent);
    if (new_fs != fs) {
        free(path);
        spin_unlock(&rwlock);
        return -EXDEV;
    }

    ext_inode_disk_t inode = {0};
    ext_inode_disk_t old_parent_inode = {0};
    ext_inode_disk_t new_parent_inode = {0};
    ext_inode_disk_t target_inode = {0};
    ext_dir_lookup_t target_lookup = {0};
    bool target_exists = false;
    bool target_is_dir = false;
    bool source_is_dir = false;
    int ret = ext_read_inode(fs, node->inode, &inode);
    if (ret)
        goto out;
    ret = ext_read_inode(fs, node->parent->inode, &old_parent_inode);
    if (ret)
        goto out;
    ret = ext_read_inode(fs, new_parent->inode, &new_parent_inode);
    if (ret)
        goto out;

    source_is_dir = (inode.i_mode & S_IFMT) == EXT2_S_IFDIR;

    ret = ext_dir_find_locked(fs, new_parent->inode, &new_parent_inode,
                              new_name, &target_lookup);
    if (ret)
        goto out;
    target_exists = target_lookup.found;

    if ((new_parent == node->parent && !strcmp(new_name, node->name)) ||
        (target_exists && target_lookup.inode == node->inode)) {
        ret = 0;
        goto out;
    }

    if (target_exists) {
        ret = ext_read_inode(fs, target_lookup.inode, &target_inode);
        if (ret)
            goto out;

        target_is_dir = (target_inode.i_mode & S_IFMT) == EXT2_S_IFDIR;
        if (source_is_dir != target_is_dir) {
            ret = source_is_dir ? -ENOTDIR : -EISDIR;
            goto out;
        }

        if (target_is_dir) {
            ret =
                ext_dir_is_empty_locked(fs, target_lookup.inode, &target_inode);
            if (ret < 0)
                goto out;
            if (!ret) {
                ret = -ENOTEMPTY;
                goto out;
            }
        }

        ret = ext_dir_replace_entry_locked(
            fs, new_parent->inode, &new_parent_inode, new_name, node->inode,
            ext_mode_to_dir_file_type(inode.i_mode));
        if (ret)
            goto out;

        vfs_node_t cached_target = vfs_find_node_by_inode(target_lookup.inode);
        if (cached_target == node)
            cached_target = NULL;
        ret = ext_drop_link_locked(fs, target_lookup.inode, &target_inode,
                                   cached_target);
        if (ret)
            goto out;
    } else {
        ret = ext_dir_add_entry_locked(fs, new_parent->inode, &new_parent_inode,
                                       node->inode, new_name,
                                       ext_mode_to_dir_file_type(inode.i_mode));
        if (ret)
            goto out;
    }

    ret = ext_dir_remove_entry_locked(fs, node->parent->inode,
                                      &old_parent_inode, node->name, NULL);
    if (ret)
        goto out;

    if (source_is_dir && new_parent != node->parent) {
        ret = ext_dir_set_dotdot_locked(fs, node->inode, &inode,
                                        new_parent->inode);
        if (ret)
            goto out;
    }

    if (source_is_dir) {
        bool write_old_parent = false;
        bool write_new_parent = false;

        if (new_parent != node->parent) {
            if (old_parent_inode.i_links_count)
                old_parent_inode.i_links_count--;
            write_old_parent = true;

            if (!target_exists) {
                new_parent_inode.i_links_count++;
                write_new_parent = true;
            }
        } else if (target_exists) {
            if (old_parent_inode.i_links_count)
                old_parent_inode.i_links_count--;
            write_old_parent = true;
        }

        if (write_old_parent) {
            ext_inode_touch(&old_parent_inode, false, true, true);
            ret = ext_write_inode(fs, node->parent->inode, &old_parent_inode);
            if (ret)
                goto out;
        }

        if (write_new_parent) {
            ext_inode_touch(&new_parent_inode, false, true, true);
            ret = ext_write_inode(fs, new_parent->inode, &new_parent_inode);
            if (ret)
                goto out;
        }
    }

    ext_inode_touch(&inode, false, false, true);
    ret = ext_write_inode(fs, node->inode, &inode);

out:
    free(path);
    spin_unlock(&rwlock);
    return ret;
}

int ext_stat(vfs_node_t node) {
    if (!node)
        return -EINVAL;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(node);
    if (!fs) {
        spin_unlock(&rwlock);
        return -ENOENT;
    }

    if (!node->inode) {
        int ret = ext_lookup_node_locked(node->parent, node->name, node);
        spin_unlock(&rwlock);
        return ret;
    }

    ext_handle_t *handle = node->handle;
    ext_inode_disk_t inode = (handle && handle->inode_valid)
                                 ? handle->inode_cache
                                 : (ext_inode_disk_t){0};
    int ret = 0;
    if (!handle || !handle->inode_valid) {
        ret = ext_read_inode(fs, node->inode, &inode);
        if (!ret && handle) {
            handle->inode_cache = inode;
            handle->inode_valid = true;
        }
    }
    if (!ret)
        ext_sync_node_from_inode(node, fs, &inode);
    spin_unlock(&rwlock);
    return ret;
}

int ext_ioctl(vfs_node_t node, ssize_t cmd, ssize_t arg) {
    if (!node)
        return -EBADF;
    if ((node->type & file_block) || (node->type & file_stream))
        return device_ioctl(node->rdev, cmd, (void *)arg);
    return -ENOSYS;
}

int ext_poll(vfs_node_t node, size_t events) {
    if (!node)
        return EPOLLNVAL;
    if ((node->type & file_block) || (node->type & file_stream))
        return device_poll(node->rdev, events);
    return 0;
}

void ext_resize(vfs_node_t node, uint64_t size) {
    if (!node || !(node->type & file_none))
        return;

    spin_lock(&rwlock);
    ext_mount_ctx_t *fs = ext_find_mount(node);
    if (!fs) {
        spin_unlock(&rwlock);
        return;
    }

    ext_inode_disk_t inode = {0};
    if (!ext_read_inode(fs, node->inode, &inode) &&
        !ext_inode_truncate_locked(fs, node->inode, &inode, size)) {
        ext_handle_t *handle = node->handle;
        if (handle && handle->ino == node->inode) {
            handle->inode_cache = inode;
            handle->inode_valid = true;
            handle->inode_dirty = false;
        }
        ext_sync_node_from_inode(node, fs, &inode);
    }
    spin_unlock(&rwlock);
}

void *ext_map(fd_t *file, void *addr, size_t offset, size_t size, size_t prot,
              size_t flags) {
    if ((file->node->type & file_block) || (file->node->type & file_stream))
        return device_map(file->node->rdev, addr, offset, size, prot, flags);
    return general_map(file, (uint64_t)addr, size, prot, flags, offset);
}

void ext_free_handle(vfs_node_t node) {
    if (!node || !node->handle)
        return;
    spin_lock(&rwlock);
    ext_handle_t *handle = node->handle;
    if (handle->device_opened)
        device_close(node->rdev);
    free(handle);
    node->handle = NULL;
    spin_unlock(&rwlock);
}

static vfs_operations_t ext_vfs_ops = {
    .mount = ext_mount,
    .unmount = ext_unmount,
    .remount = ext_remount,
    .open = ext_open,
    .close = ext_close,
    .read = ext_read,
    .write = ext_write,
    .readlink = ext_readlink,
    .mkdir = ext_mkdir,
    .mkfile = ext_mkfile,
    .link = ext_link,
    .link_node = ext_link_existing,
    .symlink = ext_symlink,
    .mknod = ext_mknod,
    .chmod = ext_chmod,
    .chown = ext_chown,
    .delete = ext_delete,
    .rename = ext_rename,
    .map = ext_map,
    .stat = ext_stat,
    .ioctl = ext_ioctl,
    .poll = ext_poll,
    .resize = ext_resize,
    .free_handle = ext_free_handle,
};

fs_t extfs = {
    .name = "ext",
    .magic = EXT_SUPER_MAGIC,
    .ops = &ext_vfs_ops,
    .flags = 0,
};

__attribute__((visibility("default"))) void dlmain() {
    ext_fsid = vfs_regist(&extfs);
}

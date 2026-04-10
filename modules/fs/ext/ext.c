#include <ext.h>
#include <ext_disk.h>

#include <boot/boot.h>

#include <dev/device.h>
#include <fs/fs_syscall.h>
#include <mm/mm_syscall.h>

#include <mm/mm.h>
#include <arch/arch.h>
#include <task/task.h>

static spinlock_t rwlock = SPIN_INIT;

#define EXT_MAP_CACHE_TARGET_BYTES (128u * 1024u)
#define EXT_MAP_CACHE_MIN_ENTRIES 16u
#define EXT_MAP_CACHE_MAX_ENTRIES 128u

#define EXT_QUOTA_USER_MAGIC 0xd9c01f11u
#define EXT_QUOTA_BLOCK_SIZE 1024u
#define EXT_QUOTA_TREEOFF 1u
#define EXT_QUOTA_BLOCK_HEADER_SIZE 16u
#define EXT_QUOTA_ENTRY_SIZE 72u
#define EXT_QUOTA_PTRS_PER_BLOCK                                               \
    ((EXT_QUOTA_BLOCK_SIZE - EXT_QUOTA_BLOCK_HEADER_SIZE) / sizeof(uint32_t))
#define EXT_QUOTA_ENTRIES_PER_BLOCK                                            \
    ((EXT_QUOTA_BLOCK_SIZE - EXT_QUOTA_BLOCK_HEADER_SIZE) /                    \
     EXT_QUOTA_ENTRY_SIZE)

typedef struct ext_map_cache_entry {
    uint32_t block;
    uint8_t *data;
    bool valid;
} ext_map_cache_entry_t;

typedef struct ext_mount_ctx {
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

typedef struct ext_inode_info {
    struct vfs_inode vfs_inode;
    ext_inode_disk_t inode_cache;
    bool inode_valid;
    char *symlink;
} ext_inode_info_t;

typedef struct ext_quota_header {
    uint32_t dqh_magic;
    uint32_t dqh_version;
} __attribute__((packed)) ext_quota_header_t;

typedef struct ext_quota_block_header {
    uint32_t dqdh_next_free;
    uint32_t dqdh_prev_free;
    uint16_t dqdh_entries;
    uint16_t dqdh_pad1;
    uint32_t dqdh_pad2;
} __attribute__((packed)) ext_quota_block_header_t;

typedef struct ext_quota_disk_entry {
    uint32_t dqb_id;
    uint32_t dqb_pad;
    uint64_t dqb_ihardlimit;
    uint64_t dqb_isoftlimit;
    uint64_t dqb_curinodes;
    uint64_t dqb_bhardlimit;
    uint64_t dqb_bsoftlimit;
    uint64_t dqb_curspace;
    uint64_t dqb_btime;
    uint64_t dqb_itime;
} __attribute__((packed)) ext_quota_disk_entry_t;

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

static int ext_dev_read(ext_mount_ctx_t *fs, uint64_t offset, void *buf,
                        size_t size);
static int ext_dev_write(ext_mount_ctx_t *fs, uint64_t offset, const void *buf,
                         size_t size);
static void ext_sync_vfs_inode(struct vfs_inode *inode, ext_mount_ctx_t *fs,
                               const ext_inode_disk_t *disk_inode);
static struct vfs_inode *ext_iget_locked(struct vfs_super_block *sb,
                                         uint32_t ino);

static struct vfs_file_system_type ext_fs_type;
static const struct vfs_super_operations ext_super_ops;
static const struct vfs_inode_operations ext_inode_ops;
static const struct vfs_file_operations ext_dir_ops;
static const struct vfs_file_operations ext_file_ops;

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

static unsigned char ext_dir_file_type_to_dtype(uint8_t type) {
    switch (type) {
    case EXT2_FT_DIR:
        return DT_DIR;
    case EXT2_FT_SYMLINK:
        return DT_LNK;
    case EXT2_FT_CHRDEV:
        return DT_CHR;
    case EXT2_FT_BLKDEV:
        return DT_BLK;
    case EXT2_FT_FIFO:
        return DT_FIFO;
    case EXT2_FT_SOCK:
        return DT_SOCK;
    case EXT2_FT_REG_FILE:
    default:
        return DT_REG;
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

static uint64_t ext_sb_reserved_blocks_count(const ext_super_block_t *sb) {
    if (!sb)
        return 0;

    return (uint64_t)sb->s_r_blocks_count_lo |
           ((uint64_t)sb->s_r_blocks_count_hi << 32);
}

static uint64_t ext_group_free_blocks_count(const ext_group_desc_t *gd) {
    if (!gd)
        return 0;

    return (uint64_t)gd->bg_free_blocks_count_lo |
           ((uint64_t)gd->bg_free_blocks_count_hi << 16);
}

static uint64_t ext_group_free_inodes_count(const ext_group_desc_t *gd) {
    if (!gd)
        return 0;

    return (uint64_t)gd->bg_free_inodes_count_lo |
           ((uint64_t)gd->bg_free_inodes_count_hi << 16);
}

static bool ext_reserved_blocks_available_to_caller(const ext_mount_ctx_t *fs) {
    task_t *task = current_task;

    if (!fs || !task)
        return false;

    return task->euid == 0 || task->uid == (int64_t)fs->sb.s_def_resuid ||
           task->euid == (int64_t)fs->sb.s_def_resuid ||
           task->gid == (int64_t)fs->sb.s_def_resgid ||
           task->egid == (int64_t)fs->sb.s_def_resgid;
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

static inline ext_mount_ctx_t *ext_sb_info(struct vfs_super_block *sb) {
    return sb ? (ext_mount_ctx_t *)sb->s_fs_info : NULL;
}

static inline ext_inode_info_t *ext_i(struct vfs_inode *inode) {
    return inode ? container_of(inode, ext_inode_info_t, vfs_inode) : NULL;
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

static uint32_t ext_block_bits(uint32_t block_size) {
    uint32_t bits = 0;

    while (block_size > 1) {
        bits++;
        block_size >>= 1;
    }
    return bits;
}

static void ext_sync_vfs_inode(struct vfs_inode *inode, ext_mount_ctx_t *fs,
                               const ext_inode_disk_t *disk_inode) {
    if (!inode || !fs || !disk_inode)
        return;

    inode->i_mode = disk_inode->i_mode;
    inode->i_uid = ext_inode_uid_get(disk_inode);
    inode->i_gid = ext_inode_gid_get(disk_inode);
    inode->i_nlink = disk_inode->i_links_count;
    inode->i_size = ext_inode_size_get(disk_inode);
    inode->i_blocks = ext_inode_blocks_get(disk_inode);
    inode->i_blkbits = ext_block_bits(fs->block_size);
    inode->i_atime.sec = disk_inode->i_atime;
    inode->i_btime.sec =
        disk_inode->i_crtime ? disk_inode->i_crtime : disk_inode->i_ctime;
    inode->i_ctime.sec = disk_inode->i_ctime;
    inode->i_mtime.sec = disk_inode->i_mtime;
    inode->inode = inode->i_ino;
    inode->type = ext_mode_to_vfs_type(disk_inode->i_mode);
    if ((inode->type & file_block) || (inode->type & file_stream))
        inode->i_rdev = ext_inode_rdev_get(disk_inode);
    else
        inode->i_rdev = fs->dev;

    inode->i_op = &ext_inode_ops;
    inode->i_fop = S_ISDIR(inode->i_mode) ? &ext_dir_ops : &ext_file_ops;
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
            if (!memcmp(entry->name, ".", MIN(1, entry->name_len)) ||
                !memcmp(entry->name, "..", MIN(2, entry->name_len))) {
                goto next;
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
        next:
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

static int ext_quota_read_locked(ext_mount_ctx_t *fs, uint32_t quota_ino,
                                 ext_inode_disk_t *quota_inode, uint32_t block,
                                 void *buf) {
    int ret;

    if (!buf)
        return -EINVAL;

    ret = ext_read_inode_data_locked(fs, quota_ino, quota_inode, buf,
                                     (size_t)block * EXT_QUOTA_BLOCK_SIZE,
                                     EXT_QUOTA_BLOCK_SIZE);
    if (ret < 0)
        return ret;
    if ((size_t)ret != EXT_QUOTA_BLOCK_SIZE)
        return -EIO;
    return 0;
}

static unsigned int ext_quota_tree_depth(void) {
    uint64_t entries = EXT_QUOTA_PTRS_PER_BLOCK;
    unsigned int depth = 1;

    while (entries < (1ULL << 32)) {
        entries *= EXT_QUOTA_PTRS_PER_BLOCK;
        depth++;
    }

    return depth;
}

static void ext_quota_tree_path(uint32_t id, uint32_t *path,
                                unsigned int depth) {
    uint64_t div = 1;

    for (unsigned int i = 1; i < depth; i++)
        div *= EXT_QUOTA_PTRS_PER_BLOCK;

    for (unsigned int i = 0; i < depth; i++) {
        path[i] = (uint32_t)((id / div) % EXT_QUOTA_PTRS_PER_BLOCK);
        if (div > 1)
            div /= EXT_QUOTA_PTRS_PER_BLOCK;
    }
}

static int ext_quota_find_data_block_locked(ext_mount_ctx_t *fs,
                                            uint32_t quota_ino,
                                            ext_inode_disk_t *quota_inode,
                                            uint32_t id, uint32_t *block_out) {
    uint8_t block[EXT_QUOTA_BLOCK_SIZE];
    uint32_t tree_path[8] = {0};
    uint32_t block_no = EXT_QUOTA_TREEOFF;
    unsigned int depth = ext_quota_tree_depth();
    int ret;

    if (!block_out)
        return -EINVAL;
    if (depth > sizeof(tree_path) / sizeof(tree_path[0]))
        return -EIO;

    ext_quota_tree_path(id, tree_path, depth);

    for (unsigned int level = 0; level < depth; level++) {
        uint32_t *entries;

        ret =
            ext_quota_read_locked(fs, quota_ino, quota_inode, block_no, block);
        if (ret)
            return ret;

        entries = (uint32_t *)(block + EXT_QUOTA_BLOCK_HEADER_SIZE);
        block_no = entries[tree_path[level]];
        if (!block_no) {
            *block_out = 0;
            return 0;
        }
    }

    *block_out = block_no;
    return 0;
}

static bool ext_quota_entry_empty(const ext_quota_disk_entry_t *entry) {
    return entry && entry->dqb_id == 0 && entry->dqb_pad == 0 &&
           entry->dqb_ihardlimit == 0 && entry->dqb_isoftlimit == 0 &&
           entry->dqb_curinodes == 0 && entry->dqb_bhardlimit == 0 &&
           entry->dqb_bsoftlimit == 0 && entry->dqb_curspace == 0 &&
           entry->dqb_btime == 0 && entry->dqb_itime == 0;
}

static int ext_quota_extract_bhardlimit_locked(
    ext_mount_ctx_t *fs, uint32_t quota_ino, ext_inode_disk_t *quota_inode,
    uint32_t id, uint64_t *bhardlimit_out, uint64_t *bsoftlimit_out,
    uint32_t *valid_out) {
    uint8_t block[EXT_QUOTA_BLOCK_SIZE];
    uint64_t quota_size;
    uint32_t data_block = 0;
    int ret;

    if (!bhardlimit_out || !bsoftlimit_out || !valid_out)
        return -EINVAL;

    *bhardlimit_out = 0;
    *bsoftlimit_out = 0;
    *valid_out = QIF_BLIMITS;
    quota_size = ext_inode_size_get(quota_inode);

    ret = ext_quota_find_data_block_locked(fs, quota_ino, quota_inode, id,
                                           &data_block);
    if (ret)
        return ret;

    if (data_block) {
        ret = ext_quota_read_locked(fs, quota_ino, quota_inode, data_block,
                                    block);
        if (ret)
            return ret;

        for (uint32_t i = 0; i < EXT_QUOTA_ENTRIES_PER_BLOCK; i++) {
            ext_quota_disk_entry_t *entry =
                (ext_quota_disk_entry_t *)(block + EXT_QUOTA_BLOCK_HEADER_SIZE +
                                           i * sizeof(ext_quota_disk_entry_t));
            if (entry->dqb_id != id)
                continue;
            if (id == 0 && ext_quota_entry_empty(entry))
                continue;
            *bhardlimit_out = entry->dqb_bhardlimit;
            *bsoftlimit_out = entry->dqb_bsoftlimit;
            return 0;
        }
    }

    for (uint64_t off = EXT_QUOTA_BLOCK_SIZE;
         off + EXT_QUOTA_BLOCK_SIZE <= quota_size;
         off += EXT_QUOTA_BLOCK_SIZE) {
        ext_quota_block_header_t *hdr;

        ret = ext_read_inode_data_locked(fs, quota_ino, quota_inode, block,
                                         (size_t)off, EXT_QUOTA_BLOCK_SIZE);
        if (ret < 0)
            return ret;
        if ((size_t)ret != EXT_QUOTA_BLOCK_SIZE)
            return -EIO;

        hdr = (ext_quota_block_header_t *)block;
        if (hdr->dqdh_entries > EXT_QUOTA_ENTRIES_PER_BLOCK)
            continue;

        for (uint32_t i = 0; i < EXT_QUOTA_ENTRIES_PER_BLOCK; i++) {
            ext_quota_disk_entry_t *entry =
                (ext_quota_disk_entry_t *)(block + EXT_QUOTA_BLOCK_HEADER_SIZE +
                                           i * sizeof(ext_quota_disk_entry_t));
            if (entry->dqb_id != id)
                continue;
            if (id == 0 && ext_quota_entry_empty(entry))
                continue;
            *bhardlimit_out = entry->dqb_bhardlimit;
            *bsoftlimit_out = entry->dqb_bsoftlimit;
            return 0;
        }
    }

    return 0;
}

static int ext_get_quota(struct vfs_super_block *sb, unsigned int type,
                         uint32_t id, uint64_t *bhardlimit,
                         uint64_t *bsoftlimit, uint32_t *valid) {
    ext_mount_ctx_t *fs = ext_sb_info(sb);
    ext_inode_disk_t quota_inode = {0};
    ext_quota_header_t header = {0};
    uint32_t quota_ino;
    int ret;

    if (!fs || !bhardlimit || !bsoftlimit || !valid)
        return -EINVAL;
    if (type != USRQUOTA)
        return -EOPNOTSUPP;

    quota_ino = fs->sb.s_usr_quota_inum;
    if (!quota_ino)
        return -ESRCH;

    spin_lock(&rwlock);
    ret = ext_read_inode(fs, quota_ino, &quota_inode);
    if (ret)
        goto out;

    ret = ext_read_inode_data_locked(fs, quota_ino, &quota_inode, &header, 0,
                                     sizeof(header));
    if (ret < 0)
        goto out;
    if ((size_t)ret != sizeof(header)) {
        ret = -EIO;
        goto out;
    }
    if (header.dqh_magic != EXT_QUOTA_USER_MAGIC) {
        ret = -ESRCH;
        goto out;
    }

    ret = ext_quota_extract_bhardlimit_locked(fs, quota_ino, &quota_inode, id,
                                              bhardlimit, bsoftlimit, valid);

out:
    spin_unlock(&rwlock);
    return ret;
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

static int ext_drop_link_locked(ext_mount_ctx_t *fs, uint32_t ino,
                                ext_inode_disk_t *inode,
                                struct vfs_inode *cached_inode);

static int ext_delete_directory_contents_locked(ext_mount_ctx_t *fs,
                                                uint32_t dir_ino,
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
                    char name[256];
                    size_t name_len = MIN(entry->name_len, 255);
                    memcpy(name, entry->name, name_len);
                    name[name_len] = '\0';

                    ext_inode_disk_t child_inode = {0};
                    ret = ext_read_inode(fs, entry->inode, &child_inode);
                    if (ret) {
                        free(buf);
                        return ret;
                    }

                    if ((child_inode.i_mode & S_IFMT) == EXT2_S_IFDIR) {
                        ret = ext_delete_directory_contents_locked(
                            fs, entry->inode, &child_inode);
                        if (ret) {
                            free(buf);
                            return ret;
                        }
                    }

                    uint32_t child_ino = entry->inode;
                    ret = ext_dir_remove_entry_locked(fs, dir_ino, dir_inode,
                                                      name, NULL);
                    if (ret) {
                        free(buf);
                        return ret;
                    }
                    entry->inode = 0;

                    ret =
                        ext_drop_link_locked(fs, child_ino, &child_inode, NULL);
                    if (ret) {
                        free(buf);
                        return ret;
                    }
                }
            }
            off += entry->rec_len;
        }
    }

    free(buf);
    return 0;
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
                                struct vfs_inode *cached_inode) {
    if (!fs || !inode)
        return -EINVAL;

    if (inode->i_links_count)
        inode->i_links_count--;
    ext_inode_touch(inode, false, false, true);

    if (inode->i_links_count == 0) {
        if (cached_inode && vfs_ref_read(&cached_inode->i_ref) > 1) {
            inode->i_dtime = (uint32_t)ext_now();
            return ext_write_inode(fs, ino, inode);
        }
        return ext_release_inode_locked(fs, ino, inode);
    }

    return ext_write_inode(fs, ino, inode);
}
static int ext_load_inode_locked(struct vfs_inode *inode,
                                 ext_inode_disk_t *disk_inode) {
    ext_inode_info_t *info;
    ext_mount_ctx_t *fs;
    int ret;

    if (!inode || !disk_inode)
        return -EINVAL;

    info = ext_i(inode);
    fs = ext_sb_info(inode->i_sb);
    if (!info || !fs)
        return -EINVAL;

    if (!info->inode_valid) {
        ret = ext_read_inode(fs, (uint32_t)inode->i_ino, &info->inode_cache);
        if (ret)
            return ret;
        info->inode_valid = true;
        ext_sync_vfs_inode(inode, fs, &info->inode_cache);
    }

    *disk_inode = info->inode_cache;
    return 0;
}

static int ext_store_inode_locked(struct vfs_inode *inode,
                                  const ext_inode_disk_t *disk_inode,
                                  bool write_back) {
    ext_inode_info_t *info;
    ext_mount_ctx_t *fs;
    int ret = 0;

    if (!inode || !disk_inode)
        return -EINVAL;

    info = ext_i(inode);
    fs = ext_sb_info(inode->i_sb);
    if (!info || !fs)
        return -EINVAL;

    if (write_back) {
        ret = ext_write_inode(fs, (uint32_t)inode->i_ino, disk_inode);
        if (ret)
            return ret;
    }

    info->inode_cache = *disk_inode;
    info->inode_valid = true;
    ext_sync_vfs_inode(inode, fs, disk_inode);
    return 0;
}

static struct vfs_inode *
ext_find_cached_inode_locked(struct vfs_super_block *sb, uint32_t ino) {
    struct vfs_inode *inode, *tmp;

    if (!sb)
        return NULL;

    spin_lock(&sb->s_inode_lock);
    llist_for_each(inode, tmp, &sb->s_inodes, i_sb_list) {
        if (inode->i_ino == ino) {
            vfs_igrab(inode);
            spin_unlock(&sb->s_inode_lock);
            return inode;
        }
    }
    spin_unlock(&sb->s_inode_lock);
    return NULL;
}

static struct vfs_inode *ext_iget_locked(struct vfs_super_block *sb,
                                         uint32_t ino) {
    ext_mount_ctx_t *fs = ext_sb_info(sb);
    ext_inode_info_t *info;
    struct vfs_inode *inode;
    ext_inode_disk_t disk_inode = {0};
    int ret;

    if (!sb || !fs || !ino)
        return ERR_PTR(-EINVAL);

    inode = ext_find_cached_inode_locked(sb, ino);
    if (inode)
        return inode;

    inode = vfs_alloc_inode(sb);
    if (!inode)
        return ERR_PTR(-ENOMEM);

    ret = ext_read_inode(fs, ino, &disk_inode);
    if (ret) {
        vfs_iput(inode);
        return ERR_PTR(ret);
    }

    inode->i_ino = ino;
    info = ext_i(inode);
    info->inode_cache = disk_inode;
    info->inode_valid = true;
    ext_sync_vfs_inode(inode, fs, &disk_inode);
    return inode;
}

static int ext_create_inode_common_locked(
    ext_mount_ctx_t *fs, struct vfs_inode *parent, struct vfs_dentry *dentry,
    uint16_t mode, uint32_t rdev, const void *payload, size_t payload_size) {
    uint32_t ino = 0;
    struct vfs_inode *vinode = NULL;
    ext_inode_info_t *info = NULL;
    int ret = ext_alloc_inode_locked(fs, mode, &ino);
    if (ret)
        return ret;

    ext_inode_disk_t disk_inode = {0};
    disk_inode.i_mode = mode;
    disk_inode.i_links_count = (mode & S_IFMT) == EXT2_S_IFDIR ? 2 : 1;
    ext_inode_uid_set(&disk_inode, parent ? parent->i_uid : 0);
    ext_inode_gid_set(&disk_inode, parent ? parent->i_gid : 0);
    ext_inode_touch(&disk_inode, true, true, true);
    if ((mode & S_IFMT) == EXT2_S_IFCHR || (mode & S_IFMT) == EXT2_S_IFBLK)
        ext_inode_rdev_set(&disk_inode, rdev);

    if ((mode & S_IFMT) == EXT2_S_IFDIR) {
        uint32_t block = 0;
        uint32_t prefer_group = (ino - 1) / fs->sb.s_inodes_per_group;
        ret = ext_alloc_block_locked(fs, prefer_group, &block);
        if (ret)
            goto rollback_inode;
        disk_inode.i_block[0] = block;
        ext_inode_add_fs_blocks(fs, &disk_inode, 1);
        ext_inode_size_set(&disk_inode, fs->block_size);

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
        dotdot->inode = parent ? (uint32_t)parent->i_ino : ino;
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
        if (payload_size <= sizeof(disk_inode.i_block)) {
            memcpy(disk_inode.i_block, payload, payload_size);
            ext_inode_size_set(&disk_inode, payload_size);
        } else {
            ret = ext_write_inode_data_locked(fs, ino, &disk_inode, payload, 0,
                                              payload_size);
            if (ret < 0)
                goto rollback_inode_release;
        }
    }

    ret = ext_write_inode(fs, ino, &disk_inode);
    if (ret)
        goto rollback_inode_release;

    ext_inode_disk_t parent_inode = {0};
    ret = ext_read_inode(fs, (uint32_t)parent->i_ino, &parent_inode);
    if (ret)
        goto rollback_inode_release;

    ret = ext_dir_add_entry_locked(
        fs, (uint32_t)parent->i_ino, &parent_inode, ino, dentry->d_name.name,
        ext_mode_to_dir_file_type(disk_inode.i_mode));
    if (ret)
        goto rollback_inode_release;

    if ((mode & S_IFMT) == EXT2_S_IFDIR) {
        parent_inode.i_links_count++;
        ext_inode_touch(&parent_inode, false, true, true);
        ret = ext_write_inode(fs, (uint32_t)parent->i_ino, &parent_inode);
        if (ret)
            return ret;
    }

    vinode = ext_iget_locked(parent->i_sb, ino);
    if (IS_ERR(vinode))
        return PTR_ERR(vinode);

    info = ext_i(vinode);
    if ((mode & S_IFMT) == EXT2_S_IFLNK &&
        payload_size <= sizeof(disk_inode.i_block)) {
        info->symlink = calloc(1, payload_size + 1);
        if (info->symlink)
            memcpy(info->symlink, payload, payload_size);
    }

    vfs_d_instantiate(dentry, vinode);
    vfs_iput(vinode);
    return 0;

rollback_inode_release:
    ext_release_inode_locked(fs, ino, &disk_inode);
    return ret;
rollback_inode:
    ext_free_inode_locked(fs, ino, (mode & S_IFMT) == EXT2_S_IFDIR);
    return ret;
}

static int ext_mount_prepare_locked(ext_mount_ctx_t *fs, uint64_t dev);
static int ext_iterate_dir_locked(struct vfs_inode *dir,
                                  struct vfs_dir_context *ctx);
static struct vfs_dentry *ext_lookup(struct vfs_inode *dir,
                                     struct vfs_dentry *dentry,
                                     unsigned int flags);
static int ext_create(struct vfs_inode *dir, struct vfs_dentry *dentry,
                      umode_t mode, bool excl);
static int ext_mkdir(struct vfs_inode *dir, struct vfs_dentry *dentry,
                     umode_t mode);
static int ext_mknod(struct vfs_inode *dir, struct vfs_dentry *dentry,
                     umode_t mode, dev64_t dev);
static int ext_symlink(struct vfs_inode *dir, struct vfs_dentry *dentry,
                       const char *target);
static int ext_link(struct vfs_dentry *old_dentry, struct vfs_inode *dir,
                    struct vfs_dentry *new_dentry);
static int ext_unlink(struct vfs_inode *dir, struct vfs_dentry *dentry);
static int ext_rmdir(struct vfs_inode *dir, struct vfs_dentry *dentry);
static int ext_rename(struct vfs_rename_ctx *ctx);
static const char *ext_get_link(struct vfs_dentry *dentry,
                                struct vfs_inode *inode,
                                struct vfs_nameidata *nd);
static int ext_permission(struct vfs_inode *inode, int mask);
static int ext_getattr(const struct vfs_path *path, struct vfs_kstat *stat,
                       uint32_t request_mask, unsigned int flags);
static int ext_setattr(struct vfs_dentry *dentry, const struct vfs_kstat *stat);
static loff_t ext_llseek(struct vfs_file *file, loff_t offset, int whence);
static ssize_t ext_read(struct vfs_file *file, void *buf, size_t count,
                        loff_t *ppos);
static ssize_t ext_write(struct vfs_file *file, const void *buf, size_t count,
                         loff_t *ppos);
static int ext_iterate_shared(struct vfs_file *file,
                              struct vfs_dir_context *ctx);
static long ext_unlocked_ioctl(struct vfs_file *file, unsigned long cmd,
                               unsigned long arg);
static __poll_t ext_poll(struct vfs_file *file, struct vfs_poll_table *pt);
static int ext_open(struct vfs_inode *inode, struct vfs_file *file);
static int ext_release(struct vfs_inode *inode, struct vfs_file *file);
static int ext_fsync(struct vfs_file *file, loff_t start, loff_t end,
                     int datasync);
static struct vfs_inode *ext_alloc_inode(struct vfs_super_block *sb);
static void ext_destroy_inode(struct vfs_inode *inode);
static void ext_put_super(struct vfs_super_block *sb);
static int ext_statfs(struct vfs_path *path, void *buf);
static int ext_resolve_mount_dev(struct vfs_fs_context *fc, uint64_t *dev_out);
static int ext_init_fs_context(struct vfs_fs_context *fc);
static int ext_get_tree(struct vfs_fs_context *fc);

static int ext_mount_prepare_locked(ext_mount_ctx_t *fs, uint64_t dev) {
    int ret;
    uint64_t gdt_block;
    uint32_t compat_ok;
    uint32_t ro_ok;
    uint32_t incompat_ok;

    if (!fs || !dev)
        return -EINVAL;

    fs->dev = dev;
    ret = ext_dev_read(fs, 1024, &fs->sb, sizeof(fs->sb));
    if (ret)
        return ret;
    if (fs->sb.s_magic != EXT_SUPER_MAGIC)
        return -EINVAL;

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

    compat_ok = EXT2_FEATURE_COMPAT_EXT_ATTR | EXT2_FEATURE_COMPAT_RESIZE_INODE;
    ro_ok = EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER |
            EXT2_FEATURE_RO_COMPAT_LARGE_FILE |
            EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE;
    incompat_ok = EXT2_FEATURE_INCOMPAT_FILETYPE;
    if ((fs->sb.s_feature_compat & ~compat_ok) ||
        (fs->sb.s_feature_ro_compat & ~ro_ok) ||
        (fs->sb.s_feature_incompat & ~incompat_ok))
        return -ENOTSUP;

    ret = ext_map_cache_init(fs);
    if (ret)
        return ret;

    fs->groups = calloc(fs->group_count, sizeof(ext_group_desc_t));
    if (!fs->groups)
        return -ENOMEM;

    gdt_block = fs->block_size == 1024 ? 2 : 1;
    for (uint32_t i = 0; i < fs->group_count; i++) {
        uint64_t offset =
            gdt_block * fs->block_size + (uint64_t)i * fs->desc_size;
        ret =
            ext_dev_read(fs, offset, &fs->groups[i],
                         MIN((size_t)fs->desc_size, sizeof(ext_group_desc_t)));
        if (ret)
            return ret;
    }

    return 0;
}

static int ext_iterate_dir_locked(struct vfs_inode *dir,
                                  struct vfs_dir_context *ctx) {
    ext_mount_ctx_t *fs = ext_sb_info(dir->i_sb);
    ext_inode_disk_t dir_inode = {0};
    uint64_t dir_size;
    uint32_t blocks;
    uint8_t *buf;
    loff_t index = 0;
    int ret;

    ret = ext_load_inode_locked(dir, &dir_inode);
    if (ret)
        return ret;
    if (!S_ISDIR(dir_inode.i_mode))
        return -ENOTDIR;

    dir_size = ext_inode_size_get(&dir_inode);
    blocks = (uint32_t)((dir_size + fs->block_size - 1) / fs->block_size);
    buf = calloc(1, fs->block_size);
    if (!buf)
        return -ENOMEM;

    for (uint32_t lblock = 0; lblock < blocks; lblock++) {
        uint32_t pblock = 0;
        ret = ext_inode_get_block_locked(fs, (uint32_t)dir->i_ino, &dir_inode,
                                         lblock, false, &pblock);
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
                if (index++ >= ctx->pos) {
                    if (ctx->actor(
                            ctx, entry->name, entry->name_len, index,
                            entry->inode,
                            ext_dir_file_type_to_dtype(entry->file_type))) {
                        free(buf);
                        ctx->pos = index;
                        return 0;
                    }
                    ctx->pos = index;
                }
            }
            off += entry->rec_len;
        }
    }

    free(buf);
    return 0;
}

static struct vfs_dentry *ext_lookup(struct vfs_inode *dir,
                                     struct vfs_dentry *dentry,
                                     unsigned int flags) {
    ext_mount_ctx_t *fs = ext_sb_info(dir->i_sb);
    ext_dir_lookup_t lookup = {0};
    struct vfs_inode *inode = NULL;
    int ret;

    (void)flags;
    if (!fs || !dir || !dentry)
        return ERR_PTR(-EINVAL);

    spin_lock(&rwlock);
    ret = ext_lookup_name_locked(fs, (uint32_t)dir->i_ino, dentry->d_name.name,
                                 &lookup);
    if (!ret && lookup.found)
        inode = ext_iget_locked(dir->i_sb, lookup.inode);
    spin_unlock(&rwlock);

    if (ret)
        return ERR_PTR(ret);
    if (inode && IS_ERR(inode))
        return ERR_CAST(inode);

    vfs_d_instantiate(dentry, inode);
    if (inode)
        vfs_iput(inode);
    return dentry;
}

static int ext_create(struct vfs_inode *dir, struct vfs_dentry *dentry,
                      umode_t mode, bool excl) {
    int ret;
    (void)excl;
    spin_lock(&rwlock);
    ret = ext_create_inode_common_locked(ext_sb_info(dir->i_sb), dir, dentry,
                                         (mode & 07777) | S_IFREG, 0, NULL, 0);
    spin_unlock(&rwlock);
    return ret;
}

static int ext_mkdir(struct vfs_inode *dir, struct vfs_dentry *dentry,
                     umode_t mode) {
    int ret;
    spin_lock(&rwlock);
    ret = ext_create_inode_common_locked(ext_sb_info(dir->i_sb), dir, dentry,
                                         (mode & 07777) | S_IFDIR, 0, NULL, 0);
    spin_unlock(&rwlock);
    return ret;
}

static int ext_mknod(struct vfs_inode *dir, struct vfs_dentry *dentry,
                     umode_t mode, dev64_t dev) {
    int ret;
    spin_lock(&rwlock);
    ret = ext_create_inode_common_locked(ext_sb_info(dir->i_sb), dir, dentry,
                                         mode, (uint32_t)dev, NULL, 0);
    spin_unlock(&rwlock);
    return ret;
}

static int ext_symlink(struct vfs_inode *dir, struct vfs_dentry *dentry,
                       const char *target) {
    int ret;
    spin_lock(&rwlock);
    ret = ext_create_inode_common_locked(ext_sb_info(dir->i_sb), dir, dentry,
                                         S_IFLNK | 0777, 0, target,
                                         target ? strlen(target) : 0);
    spin_unlock(&rwlock);
    return ret;
}

static int ext_link(struct vfs_dentry *old_dentry, struct vfs_inode *dir,
                    struct vfs_dentry *new_dentry) {
    ext_mount_ctx_t *fs = ext_sb_info(dir->i_sb);
    ext_inode_disk_t target_inode = {0};
    ext_inode_disk_t parent_inode = {0};
    int ret;

    if (!old_dentry || !old_dentry->d_inode || !dir || !new_dentry)
        return -EINVAL;
    if (old_dentry->d_inode->i_sb != dir->i_sb)
        return -EXDEV;

    spin_lock(&rwlock);
    ret = ext_load_inode_locked(old_dentry->d_inode, &target_inode);
    if (ret)
        goto out;
    if (S_ISDIR(target_inode.i_mode)) {
        ret = -EPERM;
        goto out;
    }

    ret = ext_read_inode(fs, (uint32_t)dir->i_ino, &parent_inode);
    if (ret)
        goto out;

    ret = ext_dir_add_entry_locked(
        fs, (uint32_t)dir->i_ino, &parent_inode,
        (uint32_t)old_dentry->d_inode->i_ino, new_dentry->d_name.name,
        ext_mode_to_dir_file_type(target_inode.i_mode));
    if (ret)
        goto out;

    target_inode.i_links_count++;
    target_inode.i_dtime = 0;
    ext_inode_touch(&target_inode, false, false, true);
    ret = ext_store_inode_locked(old_dentry->d_inode, &target_inode, true);
    if (!ret)
        vfs_d_instantiate(new_dentry, old_dentry->d_inode);

out:
    spin_unlock(&rwlock);
    return ret;
}

static int ext_unlink(struct vfs_inode *dir, struct vfs_dentry *dentry) {
    ext_mount_ctx_t *fs = ext_sb_info(dir->i_sb);
    ext_inode_disk_t parent_inode = {0};
    ext_inode_disk_t disk_inode = {0};
    int ret;

    if (!dentry || !dentry->d_inode)
        return -ENOENT;

    spin_lock(&rwlock);
    ret = ext_read_inode(fs, (uint32_t)dir->i_ino, &parent_inode);
    if (ret)
        goto out;
    ret = ext_load_inode_locked(dentry->d_inode, &disk_inode);
    if (ret)
        goto out;
    if (S_ISDIR(disk_inode.i_mode)) {
        ret = -EISDIR;
        goto out;
    }

    ret = ext_dir_remove_entry_locked(fs, (uint32_t)dir->i_ino, &parent_inode,
                                      dentry->d_name.name, NULL);
    if (ret)
        goto out;

    ret = ext_drop_link_locked(fs, (uint32_t)dentry->d_inode->i_ino,
                               &disk_inode, dentry->d_inode);
    if (!ret && disk_inode.i_links_count)
        ret = ext_store_inode_locked(dentry->d_inode, &disk_inode, false);

out:
    spin_unlock(&rwlock);
    return ret;
}

static int ext_rmdir(struct vfs_inode *dir, struct vfs_dentry *dentry) {
    ext_mount_ctx_t *fs = ext_sb_info(dir->i_sb);
    ext_inode_disk_t parent_inode = {0};
    ext_inode_disk_t disk_inode = {0};
    int ret;

    if (!dentry || !dentry->d_inode)
        return -ENOENT;

    spin_lock(&rwlock);
    ret = ext_read_inode(fs, (uint32_t)dir->i_ino, &parent_inode);
    if (ret)
        goto out;
    ret = ext_load_inode_locked(dentry->d_inode, &disk_inode);
    if (ret)
        goto out;
    if (!S_ISDIR(disk_inode.i_mode)) {
        ret = -ENOTDIR;
        goto out;
    }

    ret = ext_dir_is_empty_locked(fs, (uint32_t)dentry->d_inode->i_ino,
                                  &disk_inode);
    if (ret <= 0) {
        ret = ret < 0 ? ret : -ENOTEMPTY;
        goto out;
    }

    ret = ext_dir_remove_entry_locked(fs, (uint32_t)dir->i_ino, &parent_inode,
                                      dentry->d_name.name, NULL);
    if (ret)
        goto out;

    if (parent_inode.i_links_count)
        parent_inode.i_links_count--;
    ext_inode_touch(&parent_inode, false, true, true);
    ret = ext_write_inode(fs, (uint32_t)dir->i_ino, &parent_inode);
    if (ret)
        goto out;

    ret = ext_drop_link_locked(fs, (uint32_t)dentry->d_inode->i_ino,
                               &disk_inode, dentry->d_inode);
    if (!ret && disk_inode.i_links_count)
        ret = ext_store_inode_locked(dentry->d_inode, &disk_inode, false);

out:
    spin_unlock(&rwlock);
    return ret;
}

static int ext_rename(struct vfs_rename_ctx *ctx) {
    ext_mount_ctx_t *fs;
    ext_inode_disk_t src_inode = {0};
    ext_inode_disk_t old_parent_inode = {0};
    ext_inode_disk_t new_parent_inode = {0};
    ext_inode_disk_t target_inode = {0};
    ext_dir_lookup_t target_lookup = {0};
    struct vfs_inode *cached_target = NULL;
    bool target_exists;
    bool source_is_dir;
    bool target_is_dir = false;
    int ret;

    if (!ctx || !ctx->old_dir || !ctx->new_dir || !ctx->old_dentry ||
        !ctx->old_dentry->d_inode || !ctx->new_dentry)
        return -EINVAL;
    if (ctx->flags & (VFS_RENAME_EXCHANGE | VFS_RENAME_WHITEOUT))
        return -EOPNOTSUPP;
    if (ctx->old_dir->i_sb != ctx->new_dir->i_sb)
        return -EXDEV;

    fs = ext_sb_info(ctx->old_dir->i_sb);
    spin_lock(&rwlock);

    ret = ext_load_inode_locked(ctx->old_dentry->d_inode, &src_inode);
    if (ret)
        goto out;
    ret = ext_read_inode(fs, (uint32_t)ctx->old_dir->i_ino, &old_parent_inode);
    if (ret)
        goto out;
    ret = ext_read_inode(fs, (uint32_t)ctx->new_dir->i_ino, &new_parent_inode);
    if (ret)
        goto out;

    source_is_dir = S_ISDIR(src_inode.i_mode);
    ret = ext_dir_find_locked(fs, (uint32_t)ctx->new_dir->i_ino,
                              &new_parent_inode, ctx->new_dentry->d_name.name,
                              &target_lookup);
    if (ret)
        goto out;
    target_exists = target_lookup.found;

    if ((ctx->old_dir == ctx->new_dir &&
         streq(ctx->old_dentry->d_name.name, ctx->new_dentry->d_name.name)) ||
        (target_exists &&
         target_lookup.inode == (uint32_t)ctx->old_dentry->d_inode->i_ino)) {
        ret = 0;
        goto out;
    }

    if (target_exists) {
        ret = ext_read_inode(fs, target_lookup.inode, &target_inode);
        if (ret)
            goto out;

        target_is_dir = S_ISDIR(target_inode.i_mode);
        if (source_is_dir != target_is_dir) {
            ret = source_is_dir ? -ENOTDIR : -EISDIR;
            goto out;
        }
        if (target_is_dir) {
            ret =
                ext_dir_is_empty_locked(fs, target_lookup.inode, &target_inode);
            if (ret <= 0) {
                ret = ret < 0 ? ret : -ENOTEMPTY;
                goto out;
            }
        }

        ret = ext_dir_replace_entry_locked(
            fs, (uint32_t)ctx->new_dir->i_ino, &new_parent_inode,
            ctx->new_dentry->d_name.name,
            (uint32_t)ctx->old_dentry->d_inode->i_ino,
            ext_mode_to_dir_file_type(src_inode.i_mode));
        if (ret)
            goto out;

        cached_target = ext_find_cached_inode_locked(ctx->new_dir->i_sb,
                                                     target_lookup.inode);
        ret = ext_drop_link_locked(fs, target_lookup.inode, &target_inode,
                                   cached_target);
        if (cached_target) {
            if (!ret && target_inode.i_links_count)
                (void)ext_store_inode_locked(cached_target, &target_inode,
                                             false);
            vfs_iput(cached_target);
            cached_target = NULL;
        }
        if (ret)
            goto out;
    } else {
        ret = ext_dir_add_entry_locked(
            fs, (uint32_t)ctx->new_dir->i_ino, &new_parent_inode,
            (uint32_t)ctx->old_dentry->d_inode->i_ino,
            ctx->new_dentry->d_name.name,
            ext_mode_to_dir_file_type(src_inode.i_mode));
        if (ret)
            goto out;
    }

    ret = ext_dir_remove_entry_locked(fs, (uint32_t)ctx->old_dir->i_ino,
                                      &old_parent_inode,
                                      ctx->old_dentry->d_name.name, NULL);
    if (ret)
        goto out;

    if (source_is_dir && ctx->new_dir != ctx->old_dir) {
        ret = ext_dir_set_dotdot_locked(
            fs, (uint32_t)ctx->old_dentry->d_inode->i_ino, &src_inode,
            (uint32_t)ctx->new_dir->i_ino);
        if (ret)
            goto out;

        if (old_parent_inode.i_links_count)
            old_parent_inode.i_links_count--;
        new_parent_inode.i_links_count++;
        ext_inode_touch(&old_parent_inode, false, true, true);
        ext_inode_touch(&new_parent_inode, false, true, true);
        ret = ext_write_inode(fs, (uint32_t)ctx->old_dir->i_ino,
                              &old_parent_inode);
        if (ret)
            goto out;
        ret = ext_write_inode(fs, (uint32_t)ctx->new_dir->i_ino,
                              &new_parent_inode);
        if (ret)
            goto out;
    }

    ext_inode_touch(&src_inode, false, false, true);
    ret = ext_store_inode_locked(ctx->old_dentry->d_inode, &src_inode, true);

out:
    if (cached_target)
        vfs_iput(cached_target);
    spin_unlock(&rwlock);
    return ret;
}

static const char *ext_get_link(struct vfs_dentry *dentry,
                                struct vfs_inode *inode,
                                struct vfs_nameidata *nd) {
    ext_inode_info_t *info;
    ext_mount_ctx_t *fs;
    ext_inode_disk_t disk_inode = {0};
    size_t link_size;
    int ret;

    (void)dentry;
    (void)nd;
    if (!inode)
        return ERR_PTR(-EINVAL);

    spin_lock(&rwlock);
    info = ext_i(inode);
    fs = ext_sb_info(inode->i_sb);
    ret = ext_load_inode_locked(inode, &disk_inode);
    if (ret) {
        spin_unlock(&rwlock);
        return ERR_PTR(ret);
    }

    link_size = (size_t)ext_inode_size_get(&disk_inode);
    free(info->symlink);
    info->symlink = calloc(1, link_size + 1);
    if (!info->symlink) {
        spin_unlock(&rwlock);
        return ERR_PTR(-ENOMEM);
    }

    if (link_size <= sizeof(disk_inode.i_block)) {
        memcpy(info->symlink, disk_inode.i_block, link_size);
        spin_unlock(&rwlock);
        return info->symlink;
    }

    ret = ext_read_inode_data_locked(fs, (uint32_t)inode->i_ino, &disk_inode,
                                     info->symlink, 0, link_size);
    spin_unlock(&rwlock);
    return ret < 0 ? ERR_PTR(ret) : info->symlink;
}

static int ext_permission(struct vfs_inode *inode, int mask) {
    (void)inode;
    (void)mask;
    return 0;
}

static int ext_getattr(const struct vfs_path *path, struct vfs_kstat *stat,
                       uint32_t request_mask, unsigned int flags) {
    (void)request_mask;
    (void)flags;
    vfs_fill_generic_kstat(path, stat);
    return 0;
}

static int ext_setattr(struct vfs_dentry *dentry,
                       const struct vfs_kstat *stat) {
    struct vfs_inode *inode = dentry ? dentry->d_inode : NULL;
    ext_mount_ctx_t *fs;
    ext_inode_disk_t disk_inode = {0};
    int ret;

    if (!inode || !stat)
        return -EINVAL;

    fs = ext_sb_info(inode->i_sb);
    spin_lock(&rwlock);
    ret = ext_load_inode_locked(inode, &disk_inode);
    if (ret)
        goto out;

    if (stat->mode)
        disk_inode.i_mode = (disk_inode.i_mode & S_IFMT) | (stat->mode & 07777);
    ext_inode_uid_set(&disk_inode, stat->uid);
    ext_inode_gid_set(&disk_inode, stat->gid);

    if (!S_ISDIR(disk_inode.i_mode) &&
        stat->size != ext_inode_size_get(&disk_inode)) {
        ret = ext_inode_truncate_locked(fs, (uint32_t)inode->i_ino, &disk_inode,
                                        stat->size);
        if (ret)
            goto out;
    } else {
        ext_inode_touch(&disk_inode, false, false, true);
        ret = ext_write_inode(fs, (uint32_t)inode->i_ino, &disk_inode);
        if (ret)
            goto out;
    }

    ret = ext_store_inode_locked(inode, &disk_inode, false);
out:
    spin_unlock(&rwlock);
    return ret;
}

static loff_t ext_llseek(struct vfs_file *file, loff_t offset, int whence) {
    loff_t pos;

    if (!file || !file->f_inode)
        return -EBADF;

    mutex_lock(&file->f_pos_lock);
    switch (whence) {
    case SEEK_SET:
        pos = offset;
        break;
    case SEEK_CUR:
        pos = file->f_pos + offset;
        break;
    case SEEK_END:
        pos = (loff_t)file->f_inode->i_size + offset;
        break;
    default:
        mutex_unlock(&file->f_pos_lock);
        return -EINVAL;
    }
    if (pos < 0) {
        mutex_unlock(&file->f_pos_lock);
        return -EINVAL;
    }
    file->f_pos = pos;
    mutex_unlock(&file->f_pos_lock);
    return pos;
}

static ssize_t ext_read(struct vfs_file *file, void *buf, size_t count,
                        loff_t *ppos) {
    ext_mount_ctx_t *fs;
    ext_inode_disk_t disk_inode = {0};
    int ret;

    if (!file || !file->f_inode || !buf || !ppos)
        return -EINVAL;
    if ((file->f_inode->type & file_block) ||
        (file->f_inode->type & file_stream))
        return device_read(file->f_inode->i_rdev, buf, (size_t)*ppos, count,
                           file);
    if (!S_ISREG(file->f_inode->i_mode))
        return -EINVAL;

    fs = ext_sb_info(file->f_inode->i_sb);
    spin_lock(&rwlock);
    ret = ext_load_inode_locked(file->f_inode, &disk_inode);
    if (!ret)
        ret =
            ext_read_inode_data_locked(fs, (uint32_t)file->f_inode->i_ino,
                                       &disk_inode, buf, (size_t)*ppos, count);
    if (ret >= 0)
        *ppos += ret;
    spin_unlock(&rwlock);
    return ret;
}

static ssize_t ext_write(struct vfs_file *file, const void *buf, size_t count,
                         loff_t *ppos) {
    ext_mount_ctx_t *fs;
    ext_inode_disk_t disk_inode = {0};
    int ret;

    if (!file || !file->f_inode || !buf || !ppos)
        return -EINVAL;
    if ((file->f_inode->type & file_block) ||
        (file->f_inode->type & file_stream))
        return device_write(file->f_inode->i_rdev, (void *)buf, (size_t)*ppos,
                            count, file);
    if (!S_ISREG(file->f_inode->i_mode))
        return -EINVAL;

    fs = ext_sb_info(file->f_inode->i_sb);
    spin_lock(&rwlock);
    ret = ext_load_inode_locked(file->f_inode, &disk_inode);
    if (!ret) {
        ret =
            ext_write_inode_data_locked(fs, (uint32_t)file->f_inode->i_ino,
                                        &disk_inode, buf, (size_t)*ppos, count);
        if (ret >= 0) {
            int write_ret =
                ext_store_inode_locked(file->f_inode, &disk_inode, true);
            if (write_ret < 0)
                ret = write_ret;
            else
                *ppos += ret;
        }
    }
    spin_unlock(&rwlock);
    return ret;
}

static int ext_iterate_shared(struct vfs_file *file,
                              struct vfs_dir_context *ctx) {
    int ret;

    if (!file || !file->f_inode || !ctx)
        return -EINVAL;

    spin_lock(&rwlock);
    ret = ext_iterate_dir_locked(file->f_inode, ctx);
    spin_unlock(&rwlock);
    if (!ret)
        file->f_pos = ctx->pos;
    return ret;
}

static long ext_unlocked_ioctl(struct vfs_file *file, unsigned long cmd,
                               unsigned long arg) {
    if (!file || !file->f_inode)
        return -EBADF;
    if ((file->f_inode->type & file_block) ||
        (file->f_inode->type & file_stream))
        return device_ioctl(file->f_inode->i_rdev, (ssize_t)cmd, (void *)arg,
                            file);
    return -ENOSYS;
}

static __poll_t ext_poll(struct vfs_file *file, struct vfs_poll_table *pt) {
    (void)pt;
    if (!file || !file->f_inode)
        return EPOLLNVAL;
    if ((file->f_inode->type & file_block) ||
        (file->f_inode->type & file_stream))
        return device_poll(file->f_inode->i_rdev,
                           EPOLLIN | EPOLLOUT | EPOLLRDNORM | EPOLLWRNORM);
    return EPOLLIN | EPOLLOUT | EPOLLRDNORM | EPOLLWRNORM;
}

static int ext_open(struct vfs_inode *inode, struct vfs_file *file) {
    if (!inode || !file)
        return -EINVAL;
    file->f_op = inode->i_fop;
    if ((inode->type & file_block) || (inode->type & file_stream))
        return device_open(inode->i_rdev, NULL);
    return 0;
}

static int ext_release(struct vfs_inode *inode, struct vfs_file *file) {
    (void)file;
    if (!inode)
        return 0;
    if ((inode->type & file_block) || (inode->type & file_stream))
        device_close(inode->i_rdev);
    return 0;
}

static void *ext_mmap(struct vfs_file *file, void *addr, size_t offset,
                      size_t size, size_t prot, uint64_t flags) {
    if (!file || !file->f_inode)
        return (void *)(int64_t)-EINVAL;
    return general_map(file, (uint64_t)addr, size, prot, flags, offset);
}

static int ext_fsync(struct vfs_file *file, loff_t start, loff_t end,
                     int datasync) {
    (void)file;
    (void)start;
    (void)end;
    (void)datasync;
    return 0;
}

static struct vfs_inode *ext_alloc_inode(struct vfs_super_block *sb) {
    ext_inode_info_t *info = calloc(1, sizeof(*info));
    if (!info)
        return NULL;
    return &info->vfs_inode;
}

static void ext_destroy_inode(struct vfs_inode *inode) {
    ext_inode_info_t *info = ext_i(inode);
    if (!info)
        return;
    free(info->symlink);
    free(info);
}

static void ext_put_super(struct vfs_super_block *sb) {
    ext_mount_ctx_t *fs = ext_sb_info(sb);
    if (!fs)
        return;
    ext_map_cache_destroy(fs);
    free(fs->groups);
    free(fs);
}

static int ext_statfs(struct vfs_path *path, void *buf) {
    struct statfs *st = (struct statfs *)buf;
    struct vfs_super_block *sb;
    ext_mount_ctx_t *fs;
    uint64_t free_blocks = 0;
    uint64_t free_inodes = 0;
    uint64_t reserved_blocks;

    if (!path || !path->dentry || !path->dentry->d_inode || !st)
        return -EINVAL;

    sb = path->dentry->d_inode->i_sb;
    fs = ext_sb_info(sb);
    if (!fs)
        return -EINVAL;

    memset(st, 0, sizeof(*st));

    spin_lock(&rwlock);
    for (uint32_t i = 0; i < fs->group_count; i++) {
        free_blocks += ext_group_free_blocks_count(&fs->groups[i]);
        free_inodes += ext_group_free_inodes_count(&fs->groups[i]);
    }

    reserved_blocks = ext_sb_reserved_blocks_count(&fs->sb);

    st->f_bsize = fs->block_size;
    st->f_frsize = fs->block_size;
    st->f_blocks = fs->blocks_count;
    st->f_bfree = free_blocks;
    st->f_bavail =
        ext_reserved_blocks_available_to_caller(fs)
            ? free_blocks
            : (free_blocks > reserved_blocks ? free_blocks - reserved_blocks
                                             : 0);
    st->f_files = fs->inodes_count;
    st->f_ffree = free_inodes;
    st->f_namelen = VFS_NAME_MAX;
    spin_unlock(&rwlock);

    return 0;
}

static int ext_resolve_mount_dev(struct vfs_fs_context *fc, uint64_t *dev_out) {
    struct vfs_path path = {0};
    char *end = NULL;
    uint64_t dev;
    int ret;

    if (!fc || !dev_out)
        return -EINVAL;

    dev = (uint64_t)(uintptr_t)fc->fs_private;
    if (dev) {
        *dev_out = dev;
        return 0;
    }

    if (!fc->source || !fc->source[0])
        return -EINVAL;

    dev = strtoul(fc->source, &end, 0);
    if (end && *end == '\0' && dev) {
        *dev_out = dev;
        return 0;
    }

    ret = vfs_filename_lookup(AT_FDCWD, fc->source, LOOKUP_FOLLOW, &path);
    if (ret < 0)
        return ret;

    if (!path.dentry || !path.dentry->d_inode) {
        vfs_path_put(&path);
        return -ENOENT;
    }

    dev = path.dentry->d_inode->i_rdev ? path.dentry->d_inode->i_rdev
                                       : path.dentry->d_inode->i_sb->s_dev;
    vfs_path_put(&path);
    if (!dev)
        return -EINVAL;

    *dev_out = dev;
    return 0;
}

static int ext_init_fs_context(struct vfs_fs_context *fc) {
    fc->sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    if (!fc->sb)
        return -ENOMEM;
    return 0;
}

static int ext_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb = fc ? fc->sb : NULL;
    ext_mount_ctx_t *fs = NULL;
    struct vfs_inode *root_inode = NULL;
    struct vfs_dentry *root_dentry = NULL;
    struct vfs_qstr root_name = {.name = "", .len = 0, .hash = 0};
    uint64_t dev = 0;
    int ret;

    if (!sb)
        return -EINVAL;

    ret = ext_resolve_mount_dev(fc, &dev);
    if (ret)
        return ret;

    fs = calloc(1, sizeof(*fs));
    if (!fs)
        return -ENOMEM;

    spin_lock(&rwlock);
    ret = ext_mount_prepare_locked(fs, dev);
    spin_unlock(&rwlock);
    if (ret) {
        ext_map_cache_destroy(fs);
        free(fs->groups);
        free(fs);
        return ret;
    }

    sb->s_fs_info = fs;
    sb->s_op = &ext_super_ops;
    sb->s_type = &ext_fs_type;
    sb->s_magic = EXT_SUPER_MAGIC;
    sb->s_dev = dev;

    spin_lock(&rwlock);
    root_inode = ext_iget_locked(sb, EXT_ROOT_INO);
    spin_unlock(&rwlock);
    if (IS_ERR(root_inode))
        return PTR_ERR(root_inode);

    root_dentry = vfs_d_alloc(sb, NULL, &root_name);
    if (!root_dentry) {
        vfs_iput(root_inode);
        return -ENOMEM;
    }

    vfs_d_instantiate(root_dentry, root_inode);
    sb->s_root = root_dentry;
    vfs_iput(root_inode);
    return 0;
}

static const struct vfs_super_operations ext_super_ops = {
    .alloc_inode = ext_alloc_inode,
    .destroy_inode = ext_destroy_inode,
    .put_super = ext_put_super,
    .statfs = ext_statfs,
    .get_quota = ext_get_quota,
};

static const struct vfs_file_operations ext_dir_ops = {
    .llseek = ext_llseek,
    .iterate_shared = ext_iterate_shared,
    .open = ext_open,
    .release = ext_release,
    .fsync = ext_fsync,
    .poll = ext_poll,
};

static const struct vfs_file_operations ext_file_ops = {
    .llseek = ext_llseek,
    .read = ext_read,
    .write = ext_write,
    .unlocked_ioctl = ext_unlocked_ioctl,
    .open = ext_open,
    .release = ext_release,
    .mmap = ext_mmap,
    .fsync = ext_fsync,
    .poll = ext_poll,
};

static const struct vfs_inode_operations ext_inode_ops = {
    .lookup = ext_lookup,
    .create = ext_create,
    .link = ext_link,
    .unlink = ext_unlink,
    .symlink = ext_symlink,
    .mkdir = ext_mkdir,
    .rmdir = ext_rmdir,
    .mknod = ext_mknod,
    .rename = ext_rename,
    .get_link = ext_get_link,
    .permission = ext_permission,
    .getattr = ext_getattr,
    .setattr = ext_setattr,
};

static struct vfs_file_system_type ext_fs_type = {
    .name = "ext",
    .fs_flags = VFS_FS_REQUIRES_DEV,
    .init_fs_context = ext_init_fs_context,
    .get_tree = ext_get_tree,
};

void ext_init(void) { vfs_register_filesystem(&ext_fs_type); }

int dlmain() {
    ext_init();
    return 0;
}

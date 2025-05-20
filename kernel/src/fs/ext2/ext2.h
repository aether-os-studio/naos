#pragma once

#include <libs/klibc.h>
#include <fs/vfs/vfs.h>

// ext2fs layer

#define EXT2_MAGIC 0xEF53
#define FS_STATE_CLEAN 1
#define FS_STATE_ERROR 2

#define EXT2_OS_LINUX 0
#define EXT2_OS_HURD 1
#define EXT2_OS_MASIX 2
#define EXT2_OS_FREEBSD 3
#define EXT2_OS_LITES 4

typedef struct ext2_superblock
{
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t e_s_first_ino;
    uint16_t e_s_inode_size;
    uint16_t e_s_block_group_nr;
    uint32_t e_s_feature_compat;
    uint32_t e_s_feature_incompat;
    uint32_t e_s_feature_ro_compat;
    uint8_t e_s_uuid[16];
    char e_s_volume_name[16];
    char e_s_last_mounted[64];
    uint32_t e_s_algorithm_usage_bitmap;
    uint8_t e_s_prealloc_blocks;
    uint8_t e_s_prealloc_dir_blocks;
    uint16_t e_s_padding1;
    uint32_t e_s_journal_uuid[4];
    uint32_t e_s_journal_inum;
    uint32_t e_s_journal_dev;
    uint32_t e_s_last_orphan;
    uint32_t e_s_hash_seed[4];
    uint8_t e_s_def_hash_version;
    uint8_t e_s_reserved_char_pad;
    uint16_t e_s_reserved_word_pad;
} __attribute__((packed)) ext2_superblock_t;

typedef struct ext2_block_group_desc
{
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint8_t reserved[12];
} __attribute__((packed)) ext2_block_group_desc_t;

typedef struct ext2_inode
{
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_dir_acl;
    uint32_t i_faddr;
    uint32_t i_osd2[3];
} __attribute__((packed)) ext2_inode_t;

typedef struct ext2_dirent
{
    uint32_t inode_id;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t type;
    char name[0];
} __attribute__((packed)) ext2_dirent_t;

#define EXT2_FT_UNKNOWN 0
#define EXT2_FT_REGULAR 1
#define EXT2_FT_DIRECTORY 2
#define EXT2_FT_CHAR_DEV 3
#define EXT2_FT_BLK_DEV 4
#define EXT2_FT_FIFO 5
#define EXT2_FT_SOCKET 6
#define EXT2_FT_SYMLINK 7

// vfs layer

typedef struct ext2_file
{
    uint32_t block_size;
    uint32_t inode_id;
    uint32_t inode_size;
    uint32_t inodes_per_group;
    uint16_t block_groups_count;
    uint8_t file_type;
    vfs_node_t node;
    vfs_node_t device;
} ext2_file_t;

int ext2_mount(const char *src, vfs_node_t node);
void ext2_unmount(void *root);
void ext2_open(void *parent, const char *name, vfs_node_t node);
void ext2_close(void *current);
ssize_t ext2_write(void *file, const void *addr, size_t offset, size_t size);
ssize_t ext2_read(void *file, void *addr, size_t offset, size_t size);
int ext2_mkfile(void *parent, const char *name, vfs_node_t node);
int ext2_mkdir(void *parent, const char *name, vfs_node_t node);
int ext2_delete(void *current);
int ext2_rename(void *current, const char *new);
int ext2_stat(void *file, vfs_node_t node);
int ext2_ioctl(void *file, ssize_t cmd, ssize_t arg);
int ext2_poll(void *file, size_t events);

#include <fs/ext2/ext2.h>
#include <mm/mm.h>
#include <arch/arch.h>
#include <task/task.h>
#include <fs/fs_syscall.h>

spinlock_t ext2_op_lock = {0};

// 辅助函数

// 将修改后的inode写回磁盘
void ext2_write_inode(ext2_file_t *file, uint32_t inode_id, const ext2_inode_t *inode)
{
    if (!file || !inode || inode_id == 0)
        return;

    uint32_t block_group = (inode_id - 1) / file->inodes_per_group;
    uint32_t inode_index = (inode_id - 1) % file->inodes_per_group;

    uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / file->block_size;
    uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % file->block_size;

    uint8_t *bg_block = malloc(file->block_size);
    vfs_read(file->device, bg_block, bg_desc_block * file->block_size, file->block_size);
    ext2_block_group_desc_t bg_desc;
    fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    uint64_t inode_table_offset = bg_desc.bg_inode_table * file->block_size;
    uint64_t inode_offset = inode_table_offset + inode_index * file->inode_size;

    vfs_write(file->device, inode, inode_offset, sizeof(ext2_inode_t));
}

static uint32_t ext2_find_free_inode(ext2_file_t *parent)
{
    for (uint32_t bg = 0; bg < parent->block_groups_count; bg++)
    {
        uint64_t bg_desc_block = 1 + (bg * sizeof(ext2_block_group_desc_t)) / parent->block_size;
        uint64_t bg_desc_offset = (bg * sizeof(ext2_block_group_desc_t)) % parent->block_size;

        uint8_t *bg_block = malloc(parent->block_size);
        if (!bg_block)
            return 0;

        if (vfs_read(parent->device, bg_block, bg_desc_block * parent->block_size, parent->block_size) <= 0)
        {
            free(bg_block);
            continue;
        }

        ext2_block_group_desc_t bg_desc;
        fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
        free(bg_block);

        if (bg_desc.bg_free_inodes_count == 0)
            continue;

        uint32_t max_inodes_in_group = MIN(parent->inodes_per_group,
                                           parent->block_size * 8);

        uint8_t *inode_bitmap = malloc(parent->block_size);
        if (!inode_bitmap)
            return 0;

        if (vfs_read(parent->device, inode_bitmap, bg_desc.bg_inode_bitmap * parent->block_size, parent->block_size) != (ssize_t)parent->block_size)
        {
            free(inode_bitmap);
            continue;
        }

        for (uint32_t i = 0; i < max_inodes_in_group; i++)
        {
            if (!(inode_bitmap[i / 8] & (1 << (i % 8))))
            {
                inode_bitmap[i / 8] |= (1 << (i % 8));

                if (vfs_write(parent->device, inode_bitmap, bg_desc.bg_inode_bitmap * parent->block_size, parent->block_size) != (ssize_t)parent->block_size)
                {
                    free(inode_bitmap);
                    return 0;
                }

                // 更新块组描述符
                bg_desc.bg_free_inodes_count--;
                uint8_t *new_bg_block = malloc(parent->block_size);
                if (!new_bg_block)
                {
                    free(inode_bitmap);
                    return 0;
                }

                if (vfs_read(parent->device, new_bg_block, bg_desc_block * parent->block_size,
                             parent->block_size) <= 0)
                {
                    free(new_bg_block);
                    free(inode_bitmap);
                    return 0;
                }

                fast_memcpy(new_bg_block + bg_desc_offset, &bg_desc, sizeof(ext2_block_group_desc_t));

                if (vfs_write(parent->device, new_bg_block, bg_desc_block * parent->block_size,
                              parent->block_size) <= 0)
                {
                    free(new_bg_block);
                    free(inode_bitmap);
                    return 0;
                }

                free(new_bg_block);
                free(inode_bitmap);
                return bg * parent->inodes_per_group + i + 1;
            }
        }
        free(inode_bitmap);
    }
    return 0;
}

static uint32_t ext2_find_free_block(ext2_file_t *parent)
{
    for (uint32_t bg = 0; bg < parent->block_groups_count; bg++)
    {
        uint64_t bg_desc_block = 1 + (bg * sizeof(ext2_block_group_desc_t)) / parent->block_size;
        uint64_t bg_desc_offset = (bg * sizeof(ext2_block_group_desc_t)) % parent->block_size;

        uint8_t *bg_block = malloc(parent->block_size);
        if (!bg_block)
            return 0;

        if (vfs_read(parent->device, bg_block, bg_desc_block * parent->block_size, parent->block_size) != (ssize_t)parent->block_size)
        {
            free(bg_block);
            continue;
        }

        ext2_block_group_desc_t bg_desc;
        fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
        free(bg_block);

        if (bg_desc.bg_free_blocks_count == 0)
            continue;

        uint64_t block_bitmap_block = bg_desc.bg_block_bitmap * parent->block_size;
        uint8_t *block_bitmap = malloc(parent->block_size);
        if (!block_bitmap)
            return 0;

        if (vfs_read(parent->device, block_bitmap, block_bitmap_block, parent->block_size) != (ssize_t)parent->block_size)
        {
            free(block_bitmap);
            continue;
        }

        uint32_t max_blocks_in_group = MIN(parent->blocks_per_group, parent->block_size * 8);

        for (uint32_t i = 0; i < max_blocks_in_group; i++)
        {
            if (!(block_bitmap[i / 8] & (1 << (i % 8))))
            {
                block_bitmap[i / 8] |= (1 << (i % 8));

                if (vfs_write(parent->device, block_bitmap, block_bitmap_block, parent->block_size) != (ssize_t)parent->block_size)
                {
                    free(block_bitmap);
                    return 0;
                }

                bg_desc.bg_free_blocks_count--;
                uint8_t *new_bg_block = malloc(parent->block_size);
                if (!new_bg_block)
                {
                    free(block_bitmap);
                    return 0;
                }

                if (vfs_read(parent->device, new_bg_block, bg_desc_block * parent->block_size, parent->block_size) <= 0)
                {
                    free(new_bg_block);
                    free(block_bitmap);
                    return 0;
                }

                fast_memcpy(new_bg_block + bg_desc_offset, &bg_desc, sizeof(ext2_block_group_desc_t));

                if (vfs_write(parent->device, new_bg_block, bg_desc_block * parent->block_size, parent->block_size) <= 0)
                {
                    free(new_bg_block);
                    free(block_bitmap);
                    return 0;
                }

                free(new_bg_block);
                free(block_bitmap);

                // 返回全局块号
                return bg * parent->blocks_per_group + i;
            }
        }
        free(block_bitmap);
    }
    return 0; // 没有找到空闲块
}

static uint32_t ext2_get_physical_block(ext2_file_t *file, struct ext2_inode *inode, uint32_t logical_block)
{
    uint32_t block_size = file->block_size;
    uint32_t blocks_per_indirect = block_size / sizeof(uint32_t);

    if (logical_block < 12)
    {
        return inode->i_block[logical_block];
    }
    logical_block -= 12;

    if (logical_block < blocks_per_indirect)
    {
        uint32_t indirect_block = inode->i_block[12];
        if (indirect_block == 0)
            return 0;

        uint32_t *indirect = malloc(block_size);
        vfs_read(file->device, indirect, indirect_block * block_size, block_size);
        uint32_t result = indirect[logical_block];
        free(indirect);
        return result;
    }
    logical_block -= blocks_per_indirect;

    if (logical_block < blocks_per_indirect * blocks_per_indirect)
    {
        uint32_t double_indirect_block = inode->i_block[13];
        if (double_indirect_block == 0)
            return 0;

        uint32_t *double_indirect = malloc(block_size);
        vfs_read(file->device, double_indirect, double_indirect_block * block_size, block_size);

        uint32_t first_level = logical_block / blocks_per_indirect;
        uint32_t second_level = logical_block % blocks_per_indirect;

        uint32_t indirect_block = double_indirect[first_level];
        if (indirect_block == 0)
        {
            free(double_indirect);
            return 0;
        }

        uint32_t *indirect = malloc(block_size);
        vfs_read(file->device, indirect, indirect_block * block_size, block_size);
        uint32_t result = indirect[second_level];
        free(indirect);
        free(double_indirect);
        return result;
    }

    return 0;
}

static uint32_t ext2_get_or_alloc_block(ext2_file_t *f, ext2_inode_t *inode, uint32_t logical_block)
{
    uint32_t block_size = f->block_size;
    uint32_t blocks_per_indirect = block_size / sizeof(uint32_t);

    // 直接块范围（0~11）
    if (logical_block < 12)
    {
        if (inode->i_block[logical_block] == 0)
        {
            inode->i_block[logical_block] = ext2_find_free_block(f); // 分配直接块
        }
        return inode->i_block[logical_block];
    }
    logical_block -= 12;

    // 一级间接块范围（12~12+blocks_per_indirect-1）
    if (logical_block < blocks_per_indirect)
    {
        if (inode->i_block[12] == 0)
        {
            inode->i_block[12] = ext2_find_free_block(f); // 分配一级间接块
            // 初始化间接块为全0（清空旧数据）
            uint8_t *indirect_block = calloc(1, block_size);
            vfs_write(f->device, indirect_block, inode->i_block[12] * block_size, block_size);
            free(indirect_block);
        }

        uint32_t *indirect = malloc(block_size);
        vfs_read(f->device, indirect, inode->i_block[12] * block_size, block_size);

        if (indirect[logical_block] == 0)
        {
            indirect[logical_block] = ext2_find_free_block(f);                           // 分配间接块中的具体数据块
            vfs_write(f->device, indirect, inode->i_block[12] * block_size, block_size); // 写回间接块
        }

        uint32_t result = indirect[logical_block];
        free(indirect);
        return result;
    }
    logical_block -= blocks_per_indirect;

    if (logical_block < blocks_per_indirect * blocks_per_indirect)
    {
        if (inode->i_block[13] == 0)
        {
            inode->i_block[13] = ext2_find_free_block(f);
            if (inode->i_block[13] == 0)
                return 0;

            uint8_t *double_indirect_block = calloc(1, block_size);
            if (!double_indirect_block)
                return 0;

            vfs_write(f->device, double_indirect_block, inode->i_block[13] * block_size, block_size);
            free(double_indirect_block);
        }

        uint32_t *double_indirect = malloc(block_size);
        if (!double_indirect)
            return 0;

        if (vfs_read(f->device, double_indirect, inode->i_block[13] * block_size, block_size) < 0)
        {
            free(double_indirect);
            return 0;
        }

        uint32_t first_level = logical_block / blocks_per_indirect;
        if (double_indirect[first_level] == 0)
        {
            double_indirect[first_level] = ext2_find_free_block(f);
            if (double_indirect[first_level] == 0)
            {
                free(double_indirect);
                return 0;
            }
            vfs_write(f->device, double_indirect, inode->i_block[13] * block_size, block_size);
        }

        uint32_t *indirect = malloc(block_size);
        if (!indirect)
        {
            free(double_indirect);
            return 0;
        }

        if (vfs_read(f->device, indirect, double_indirect[first_level] * block_size, block_size) < 0)
        {
            free(indirect);
            free(double_indirect);
            return 0;
        }

        uint32_t second_level = logical_block % blocks_per_indirect;
        if (indirect[second_level] == 0)
        {
            indirect[second_level] = ext2_find_free_block(f);
            if (indirect[second_level] == 0)
            {
                free(indirect);
                free(double_indirect);
                return 0;
            }
            vfs_write(f->device, indirect, double_indirect[first_level] * block_size, block_size);
        }

        uint32_t result = indirect[second_level];
        free(indirect);
        free(double_indirect);
        return result;
    }

    return 0; // 超出范围或分配失败
}

static int ext2_add_dir_entry(ext2_file_t *parent, const char *name, uint32_t inode_id, uint8_t type)
{
    uint16_t name_len = strlen(name);
    if (name_len > 255)
        return -ENAMETOOLONG;

    uint16_t entry_size = 8 + name_len + 1;
    uint16_t rec_len = (entry_size + 3) & ~3;

    uint32_t block_group = (parent->inode_id - 1) / parent->inodes_per_group;
    uint32_t inode_index = (parent->inode_id - 1) % parent->inodes_per_group;

    uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / parent->block_size;
    uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % parent->block_size;

    uint8_t *bg_block = malloc(parent->block_size);
    vfs_read(parent->device, bg_block, bg_desc_block * parent->block_size, parent->block_size);
    ext2_block_group_desc_t bg_desc;
    fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    uint64_t inode_table_offset = bg_desc.bg_inode_table * parent->block_size;
    uint64_t inode_offset = inode_table_offset + inode_index * parent->inode_size;
    ext2_inode_t parent_inode;
    vfs_read(parent->device, &parent_inode, inode_offset, sizeof(ext2_inode_t));

    for (int i = 0; i < 12; i++)
    {
        uint32_t block_num = parent_inode.i_block[i];
        if (block_num == 0)
        {
            block_num = ext2_find_free_block(parent);
            if (block_num == 0)
                return -ENOSPC;
            parent_inode.i_block[i] = block_num;
            ext2_write_inode(parent, parent->inode_id, &parent_inode);

            // 初始化新块为全0（或添加默认目录项）
            uint8_t *new_block = calloc(1, parent->block_size);
            vfs_write(parent->device, new_block, block_num * parent->block_size, parent->block_size);
            free(new_block);
        }

        // 读取块数据
        uint8_t *block = malloc(parent->block_size);
        vfs_read(parent->device, block, block_num * parent->block_size, parent->block_size);

        ext2_dirent_t *dirent = (ext2_dirent_t *)block;
        ext2_dirent_t *prev_dirent = NULL;

        while ((uint8_t *)dirent < block + parent->block_size)
        {
            if (dirent->rec_len == 0)
                break; // 无效目录项，结束遍历
            prev_dirent = dirent;
            dirent = (ext2_dirent_t *)((uint8_t *)dirent + dirent->rec_len);
        }

        if (prev_dirent)
        {
            uint16_t prev_used = offsetof(ext2_dirent_t, name) + prev_dirent->name_len;
            prev_used = (prev_used + 3) & ~3;

            uint16_t available = prev_dirent->rec_len - prev_used;

            if (available >= rec_len)
            {
                prev_dirent->rec_len = prev_used;
                ext2_dirent_t *new_dirent = (ext2_dirent_t *)((uint8_t *)prev_dirent + prev_used);
                new_dirent->inode_id = inode_id;
                new_dirent->rec_len = available;
                new_dirent->name_len = name_len;
                new_dirent->type = type;
                fast_memcpy(new_dirent->name, name, name_len);
                new_dirent->name[name_len] = '\0';

                vfs_write(parent->device, block, block_num * parent->block_size, parent->block_size);
                free(block);

                tm time;
                time_read(&time);
                parent_inode.i_mtime = mktime(&time);
                parent_inode.i_size += rec_len;
                ext2_write_inode(parent, parent->inode_id, &parent_inode);

                return 0;
            }
        }
        free(block);
    }

    return -ENOSPC; // 无空间
}

static int ext2_remove_from_block(ext2_file_t *parent_dir, ext2_inode_t *parent_inode, uint32_t block_num, const char *name)
{
    uint32_t block_size = parent_dir->block_size;
    uint8_t *block = malloc(block_size);
    vfs_read(parent_dir->device, block, block_num * block_size, block_size);

    ext2_dirent_t *dirent = (ext2_dirent_t *)block;
    ext2_dirent_t *prev_dirent = NULL;

    while ((uint8_t *)dirent < block + block_size)
    {
        if (dirent->inode_id == 0)
            break; // 空目录项

        char entry_name[256];
        fast_memcpy(entry_name, dirent->name, dirent->name_len);
        entry_name[dirent->name_len] = '\0';

        if (strcmp(entry_name, name) == 0)
        {
            if (prev_dirent)
            {
                prev_dirent->rec_len += dirent->rec_len;
            }
            else
            {
                dirent->rec_len = block_size - ((uint8_t *)dirent - block);
            }

            vfs_write(parent_dir->device, block, block_num * block_size, block_size);
            free(block);
            return 0;
        }

        prev_dirent = dirent;
        dirent = (ext2_dirent_t *)((uint8_t *)dirent + dirent->rec_len);
    }

    free(block);
    return -ENOENT;
}

static int ext2_remove_from_indirect_block(ext2_file_t *parent_dir, ext2_inode_t *parent_inode, uint32_t indirect_block_num, const char *name)
{
    uint32_t block_size = parent_dir->block_size;
    uint32_t blocks_per_indirect = block_size / sizeof(uint32_t);

    uint32_t *indirect_block = malloc(block_size);
    vfs_read(parent_dir->device, indirect_block, indirect_block_num * block_size, block_size);

    for (int i = 0; i < blocks_per_indirect; i++)
    {
        uint32_t data_block_num = indirect_block[i];
        if (data_block_num == 0)
            continue;

        int ret = ext2_remove_from_block(parent_dir, parent_inode, data_block_num, name);
        if (ret == 0)
        {
            free(indirect_block);
            return 0;
        }
    }

    free(indirect_block);
    return -ENOENT;
}

static int ext2_remove_from_double_indirect_block(ext2_file_t *parent_dir, ext2_inode_t *parent_inode, uint32_t double_indirect_block_num, const char *name)
{
    uint32_t block_size = parent_dir->block_size;
    uint32_t blocks_per_indirect = block_size / sizeof(uint32_t);

    uint32_t *double_indirect_block = malloc(block_size);
    vfs_read(parent_dir->device, double_indirect_block, double_indirect_block_num * block_size, block_size);

    for (int i = 0; i < blocks_per_indirect; i++)
    {
        uint32_t indirect_block_num = double_indirect_block[i];
        if (indirect_block_num == 0)
            continue;

        int ret = ext2_remove_from_indirect_block(parent_dir, parent_inode, indirect_block_num, name);
        if (ret == 0)
        {
            free(double_indirect_block);
            return 0;
        }
    }

    free(double_indirect_block);
    return -ENOENT;
}

static int ext2_remove_dir_entry(ext2_file_t *parent_dir, const char *name)
{
    ext2_inode_t parent_inode;
    // 获取父目录 inode（与 ext2_update 逻辑一致）
    uint32_t block_group = (parent_dir->inode_id - 1) / parent_dir->inodes_per_group;
    uint32_t inode_index = (parent_dir->inode_id - 1) % parent_dir->inodes_per_group;
    uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / parent_dir->block_size;
    uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % parent_dir->block_size;
    uint8_t *bg_block = malloc(parent_dir->block_size);
    vfs_read(parent_dir->device, bg_block, bg_desc_block * parent_dir->block_size, parent_dir->block_size);
    ext2_block_group_desc_t bg_desc;
    fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);
    uint64_t inode_table_offset = bg_desc.bg_inode_table * parent_dir->block_size;
    uint64_t inode_offset = inode_table_offset + inode_index * parent_dir->inode_size;
    vfs_read(parent_dir->device, &parent_inode, inode_offset, sizeof(ext2_inode_t));

    // 1. 遍历直接块（i_block[0-11]）
    for (int i = 0; i < 12; i++)
    {
        if (parent_inode.i_block[i] == 0)
            break;
        int ret = ext2_remove_from_block(parent_dir, &parent_inode, parent_inode.i_block[i], name);
        if (ret == 0)
            return 0;
    }

    // 2. 遍历一级间接块（i_block[12]）
    if (parent_inode.i_block[12] != 0)
    {
        int ret = ext2_remove_from_indirect_block(parent_dir, &parent_inode, parent_inode.i_block[12], name);
        if (ret == 0)
            return 0;
    }

    // 3. 遍历二级间接块（i_block[13]）
    if (parent_inode.i_block[13] != 0)
    {
        int ret = ext2_remove_from_double_indirect_block(parent_dir, &parent_inode, parent_inode.i_block[13], name);
        if (ret == 0)
            return 0;
    }

    return -ENOENT; // 未找到目标目录项
}

static void ext2_incr_block_group_free(ext2_file_t *file, uint32_t block_num)
{
    uint32_t block_group = block_num / file->blocks_per_group;

    uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / file->block_size;
    uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % file->block_size;

    uint8_t *bg_block = malloc(file->block_size);
    vfs_read(file->device, bg_block, bg_desc_block * file->block_size, file->block_size);
    ext2_block_group_desc_t bg_desc;
    fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    bg_desc.bg_free_blocks_count++;

    uint8_t *new_bg_block = malloc(file->block_size);
    vfs_read(file->device, new_bg_block, bg_desc_block * file->block_size, file->block_size);
    fast_memcpy(new_bg_block + bg_desc_offset, &bg_desc, sizeof(ext2_block_group_desc_t));
    vfs_write(file->device, new_bg_block, bg_desc_block * file->block_size, file->block_size);
    free(new_bg_block);
}

static void ext2_free_inode_blocks(ext2_file_t *file, ext2_inode_t *inode)
{
    uint32_t block_size = file->block_size;
    uint32_t blocks_per_indirect = block_size / sizeof(uint32_t);

    for (int i = 0; i < 12; i++)
    {
        if (inode->i_block[i] != 0)
        {
            ext2_incr_block_group_free(file, inode->i_block[i]);
            inode->i_block[i] = 0;
        }
    }

    if (inode->i_block[12] != 0)
    {
        uint32_t *indirect = malloc(block_size);
        vfs_read(file->device, indirect, inode->i_block[12] * block_size, block_size);
        for (int i = 0; i < blocks_per_indirect; i++)
        {
            if (indirect[i] != 0)
            {
                ext2_incr_block_group_free(file, indirect[i]);
                indirect[i] = 0;
            }
        }
        vfs_write(file->device, indirect, inode->i_block[12] * block_size, block_size);
        free(indirect);
        inode->i_block[12] = 0;
    }

    if (inode->i_block[13] != 0)
    {
        uint32_t *double_indirect = malloc(block_size);
        vfs_read(file->device, double_indirect, inode->i_block[13] * block_size, block_size);
        for (int i = 0; i < blocks_per_indirect; i++)
        {
            if (double_indirect[i] != 0)
            {
                uint32_t *indirect = malloc(block_size);
                vfs_read(file->device, indirect, double_indirect[i] * block_size, block_size);
                for (int j = 0; j < blocks_per_indirect; j++)
                {
                    if (indirect[j] != 0)
                    {
                        ext2_incr_block_group_free(file, indirect[j]);
                        indirect[j] = 0;
                    }
                }
                vfs_write(file->device, indirect, double_indirect[i] * block_size, block_size);
                free(indirect);
                double_indirect[i] = 0;
            }
        }
        vfs_write(file->device, double_indirect, inode->i_block[13] * block_size, block_size);
        free(double_indirect);
        inode->i_block[13] = 0;
    }
}

static int ext2_read_bg_desc(ext2_file_t *file, uint32_t bg, ext2_block_group_desc_t *bg_desc)
{
    uint64_t bg_desc_block = 1 + (bg * sizeof(ext2_block_group_desc_t)) / file->block_size;
    uint64_t bg_desc_offset = (bg * sizeof(ext2_block_group_desc_t)) % file->block_size;

    size_t bytes_remaining = sizeof(ext2_block_group_desc_t);
    uint8_t *dest = (uint8_t *)bg_desc;

    while (bytes_remaining > 0)
    {
        uint8_t *bg_block = alloc_frames_bytes(file->block_size);
        if (!bg_block)
            return -1;

        if (vfs_read(file->device, bg_block, bg_desc_block * file->block_size, file->block_size) < 0)
        {
            free_frames_bytes(bg_block, file->block_size);
            return -1;
        }

        size_t bytes_to_copy = MIN(bytes_remaining, file->block_size - bg_desc_offset);
        fast_memcpy(dest, bg_block + bg_desc_offset, bytes_to_copy);

        free_frames_bytes(bg_block, file->block_size);

        dest += bytes_to_copy;
        bytes_remaining -= bytes_to_copy;

        bg_desc_block++;
        bg_desc_offset = 0;
    }

    return 0;
}

void ext2_update(vfs_node_t node)
{
    ext2_file_t *file = (ext2_file_t *)node->handle;

    uint32_t block_group = (file->inode_id - 1) / file->inodes_per_group;
    uint32_t inode_index = (file->inode_id - 1) % file->inodes_per_group;

    uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / file->block_size;
    uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % file->block_size;

    uint8_t *bg_block = malloc(file->block_size);
    vfs_read(file->device, bg_block, bg_desc_block * file->block_size, file->block_size);
    ext2_block_group_desc_t bg_desc;
    fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    uint64_t inode_table_offset = bg_desc.bg_inode_table * file->block_size;
    uint64_t inode_offset = inode_table_offset + inode_index * file->inode_size;

    ext2_inode_t file_inode;
    vfs_read(file->device, &file_inode, inode_offset, sizeof(ext2_inode_t));

    node->size = file_inode.i_size;
    node->blksz = file->block_size;
    node->mode = file_inode.i_mode;
    node->readtime = file_inode.i_mtime;
    node->createtime = file_inode.i_ctime;
    node->writetime = file_inode.i_mtime;
}

void ext2_read_linkname(ext2_file_t *file, vfs_node_t node)
{
    uint32_t block_group = (file->inode_id - 1) / file->inodes_per_group;
    uint32_t inode_index = (file->inode_id - 1) % file->inodes_per_group;

    uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / file->block_size;
    uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % file->block_size;

    uint8_t *bg_block = malloc(file->block_size);
    vfs_read(file->device, bg_block, bg_desc_block * file->block_size, file->block_size);
    ext2_block_group_desc_t bg_desc;
    fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    uint64_t inode_table_offset = bg_desc.bg_inode_table * file->block_size;
    uint64_t inode_offset = inode_table_offset + inode_index * file->inode_size;

    ext2_inode_t file_inode;
    vfs_read(file->device, &file_inode, inode_offset, sizeof(ext2_inode_t));

    if (!node->linkname)
    {
        if (node->size <= sizeof(file_inode.i_block))
        {
            const char *link_path = (const char *)file_inode.i_block;
            node->linkname = strdup(link_path);
        }
        else
        {
            char *name = (char *)malloc(node->size);
            ext2_read(file, name, 0, node->size);
            node->linkname = strdup((const char *)name);
            free(name);
        }
    }
}

int ext2_fsid = 0;

static void process_dir_block(ext2_file_t *dir, uint8_t *block, vfs_node_t parent)
{
    ext2_dirent_t *dirent = (ext2_dirent_t *)block;
    while ((uint8_t *)dirent < block + dir->block_size)
    {
        char entry_name[256];
        fast_memcpy(entry_name, (char *)dirent->name, dirent->name_len);
        entry_name[dirent->name_len] = 0;

        if (dirent->inode_id != 0 && strlen(entry_name) != 0)
        {
            if (streq(entry_name, ".") || streq(entry_name, ".."))
                goto next;

            vfs_node_t child = vfs_child_append(parent, entry_name, NULL);
            child->type = (dirent->type == EXT2_FT_SYMLINK) ? file_symlink : (dirent->type == EXT2_FT_DIRECTORY) ? file_dir
                                                                                                                 : file_none;
            child->fsid = ext2_fsid;
        }
    next:
        if (dirent->rec_len == 0)
            break;
        dirent = (ext2_dirent_t *)((uint8_t *)dirent + dirent->rec_len);
    }
}

void ext2_readdir(ext2_file_t *dir, vfs_node_t parent)
{
    uint32_t block_group = (dir->inode_id - 1) / dir->inodes_per_group;

    ext2_block_group_desc_t bg_desc;
    if (ext2_read_bg_desc(dir, block_group, &bg_desc) < 0)
        return;

    uint64_t inode_table_offset = bg_desc.bg_inode_table * dir->block_size;
    uint32_t inode_index = (dir->inode_id - 1) % dir->inodes_per_group;
    uint64_t inode_offset = inode_table_offset + inode_index * dir->inode_size;

    ext2_inode_t dir_inode;
    vfs_read(dir->device, &dir_inode, inode_offset, sizeof(ext2_inode_t));

    for (int i = 0; i < 12; i++)
    {
        if (dir_inode.i_block[i] == 0)
            break;

        uint8_t *block = alloc_frames_bytes(dir->block_size);
        vfs_read(dir->device, block, dir_inode.i_block[i] * dir->block_size, dir->block_size);
        process_dir_block(dir, block, parent);
        free_frames_bytes(block, dir->block_size);
    }

    // 处理一级间接块
    if (dir_inode.i_block[12] != 0)
    {
        uint32_t *indirect = alloc_frames_bytes(dir->block_size);
        vfs_read(dir->device, indirect, dir_inode.i_block[12] * dir->block_size, dir->block_size);

        for (int i = 0; i < dir->block_size / sizeof(uint32_t); i++)
        {
            if (indirect[i] == 0)
                break;

            uint8_t *block = alloc_frames_bytes(dir->block_size);
            vfs_read(dir->device, block, indirect[i] * dir->block_size, dir->block_size);
            process_dir_block(dir, block, parent);
            free_frames_bytes(block, dir->block_size);
        }
        free_frames_bytes(indirect, dir->block_size);
    }

    // 处理二级间接块
    if (dir_inode.i_block[13] != 0)
    {
        uint32_t *double_indirect = alloc_frames_bytes(dir->block_size);
        vfs_read(dir->device, double_indirect, dir_inode.i_block[13] * dir->block_size, dir->block_size);

        for (int i = 0; i < dir->block_size / sizeof(uint32_t); i++)
        {
            if (double_indirect[i] == 0)
                break;

            uint32_t *indirect = alloc_frames_bytes(dir->block_size);
            vfs_read(dir->device, indirect, double_indirect[i] * dir->block_size, dir->block_size);

            for (int j = 0; j < dir->block_size / sizeof(uint32_t); j++)
            {
                if (indirect[j] == 0)
                    break;

                uint8_t *block = alloc_frames_bytes(dir->block_size);
                vfs_read(dir->device, block, indirect[j] * dir->block_size, dir->block_size);
                process_dir_block(dir, block, parent);
                free_frames_bytes(block, dir->block_size);
            }
            free_frames_bytes(indirect, dir->block_size);
        }
        free_frames_bytes(double_indirect, dir->block_size);
    }
}

static bool find_in_dir_block(ext2_file_t *dir, uint8_t *block, const char *name, vfs_node_t node)
{
    ext2_dirent_t *dirent = (ext2_dirent_t *)block;
    while ((uint8_t *)dirent < block + dir->block_size)
    {
        char entry_name[256];
        fast_memcpy(entry_name, (char *)dirent->name, dirent->name_len);
        entry_name[dirent->name_len] = 0;

        if (dirent->inode_id && strcmp(entry_name, name) == 0)
        {
            // found
            node->type = (dirent->type == EXT2_FT_SYMLINK) ? file_symlink : (dirent->type == EXT2_FT_DIRECTORY) ? file_dir
                                                                                                                : file_none;
            ext2_file_t *handle = malloc(sizeof(ext2_file_t));
            handle->device = dir->device;
            handle->inode_id = dirent->inode_id;
            handle->block_size = dir->block_size;
            handle->inode_size = dir->inode_size;
            handle->inodes_per_group = dir->inodes_per_group;
            handle->blocks_per_group = dir->blocks_per_group;
            handle->block_groups_count = dir->block_groups_count;
            handle->file_type = dirent->type;
            handle->node = node;
            node->inode = handle->inode_id;
            node->blksz = handle->block_size;
            node->handle = handle;
            node->fsid = ext2_fsid;
            if (node->type & file_symlink)
            {
                ext2_read_linkname(handle, node);
                vfs_node_t target_node = vfs_open_at(node->parent ? node->parent : rootdir, (const char *)node->linkname, false);
                if (target_node)
                {
                    if (target_node->type == EXT2_FT_DIRECTORY)
                        node->type |= file_dir;
                    else if (target_node->type == EXT2_FT_REGULAR)
                        node->type |= file_none;
                }
            }
            if (node->type & file_dir)
                ext2_readdir(handle, node);
            ext2_update(node);
            return true;
        }
        if (dirent->rec_len == 0)
            break;

        dirent = (ext2_dirent_t *)((uint8_t *)dirent + dirent->rec_len);
    }
    return false;
}

// 真正实现

void ext2_open(void *parent, const char *name, vfs_node_t node)
{
    ext2_file_t *dir = (ext2_file_t *)parent;

    if (!dir || !name || !node)
        return;

    uint32_t block_group = (dir->inode_id - 1) / dir->inodes_per_group;
    ext2_block_group_desc_t bg_desc;

    if (ext2_read_bg_desc(dir, block_group, &bg_desc) < 0)
        return;

    uint64_t inode_table_offset = bg_desc.bg_inode_table * dir->block_size;
    uint32_t inode_index = (dir->inode_id - 1) % dir->inodes_per_group;
    uint64_t inode_offset = inode_table_offset + inode_index * dir->inode_size;

    ext2_inode_t dir_inode;
    vfs_read(dir->device, &dir_inode, inode_offset, sizeof(ext2_inode_t));

    // 处理直接块
    for (int i = 0; i < 12; i++)
    {
        if (dir_inode.i_block[i] == 0)
            break;

        uint8_t *block = malloc(dir->block_size);
        vfs_read(dir->device, block, dir_inode.i_block[i] * dir->block_size, dir->block_size);
        if (find_in_dir_block(dir, block, name, node))
        {
            free(block);
            return;
        }
        free(block);
    }

    // 处理一级间接块
    if (dir_inode.i_block[12] != 0)
    {
        uint32_t *indirect = malloc(dir->block_size);
        vfs_read(dir->device, indirect, dir_inode.i_block[12] * dir->block_size, dir->block_size);

        for (int i = 0; i < dir->block_size / sizeof(uint32_t); i++)
        {
            if (indirect[i] == 0)
                break;

            uint8_t *block = malloc(dir->block_size);
            vfs_read(dir->device, block, indirect[i] * dir->block_size, dir->block_size);
            if (find_in_dir_block(dir, block, name, node))
            {
                free(block);
                free(indirect);
                return;
            }
            free(block);
        }
        free(indirect);
    }

    // 处理二级间接块
    if (dir_inode.i_block[13] != 0)
    {
        uint32_t *double_indirect = malloc(dir->block_size);
        vfs_read(dir->device, double_indirect, dir_inode.i_block[13] * dir->block_size, dir->block_size);

        for (int i = 0; i < dir->block_size / sizeof(uint32_t); i++)
        {
            if (double_indirect[i] == 0)
                break;

            uint32_t *indirect = malloc(dir->block_size);
            vfs_read(dir->device, indirect, double_indirect[i] * dir->block_size, dir->block_size);

            for (int j = 0; j < dir->block_size / sizeof(uint32_t); j++)
            {
                if (indirect[j] == 0)
                    break;

                uint8_t *block = malloc(dir->block_size);
                vfs_read(dir->device, block, indirect[j] * dir->block_size, dir->block_size);
                if (find_in_dir_block(dir, block, name, node))
                {
                    free(block);
                    free(indirect);
                    free(double_indirect);
                    return;
                }
                free(block);
            }
            free(indirect);
        }
        free(double_indirect);
    }
}

bool ext2_close(void *current)
{
    ext2_file_t *f = (ext2_file_t *)current;
    free(f);
    return true;
}

int ext2_mount(const char *src, vfs_node_t node)
{
    vfs_node_t device = vfs_open(src);
    if (!device)
        return -1;

    ext2_file_t *file = malloc(sizeof(ext2_file_t));
    file->device = device;

    ext2_superblock_t sb;
    vfs_read(device, &sb, 1024, sizeof(ext2_superblock_t));

    if (sb.s_magic != EXT2_MAGIC)
    {
        free(file);
        return -1;
    }

    file->inode_id = 2;
    file->block_size = 1024 << sb.s_log_block_size;
    file->inode_size = sb.e_s_inode_size;
    file->inodes_per_group = sb.s_inodes_per_group;
    file->blocks_per_group = sb.s_blocks_per_group;
    file->block_groups_count = (sb.s_blocks_count + sb.s_blocks_per_group - 1) / sb.s_blocks_per_group;
    file->file_type = EXT2_FT_DIRECTORY;
    file->node = node;

    node->inode = file->inode_id;
    node->blksz = file->block_size;
    node->fsid = ext2_fsid;
    node->handle = file;

    ext2_readdir(file, node);

    return 0;
}

void ext2_unmount(void *root)
{
    ext2_file_t *file = (ext2_file_t *)root;
    vfs_close(file->device);
    free(file);
}

ssize_t ext2_write(void *file, const void *addr, size_t offset, size_t size)
{
    ext2_file_t *f = (ext2_file_t *)file;
    if (f->inode_id == 0)
        return -EINVAL;

    spin_lock(&ext2_op_lock);

    ext2_inode_t f_inode;

    uint32_t block_group = (f->inode_id - 1) / f->inodes_per_group;
    ext2_block_group_desc_t bg_desc;

    if (ext2_read_bg_desc(f, block_group, &bg_desc) < 0)
    {
        spin_unlock(&ext2_op_lock);
        return 0;
    }

    uint64_t inode_table_offset = bg_desc.bg_inode_table * f->block_size;
    uint32_t inode_index = (f->inode_id - 1) % f->inodes_per_group;
    uint64_t inode_offset = inode_table_offset + inode_index * f->inode_size;

    vfs_read(f->device, &f_inode, inode_offset, sizeof(ext2_inode_t));

    const uint8_t *data = (const uint8_t *)addr;
    size_t remaining = size;
    size_t current_offset = offset;
    uint32_t block_size = f->block_size;

    while (remaining > 0)
    {
        // 计算逻辑块号和块内偏移
        uint32_t logical_block = current_offset / block_size;
        uint32_t block_offset = current_offset % block_size;

        // 获取或分配物理块
        uint32_t physical_block = ext2_get_or_alloc_block(f, &f_inode, logical_block);
        if (physical_block == 0)
        {
            spin_unlock(&ext2_op_lock);
            return -ENOSPC; // 无空闲块
        }

        // 计算本次写入的字节数（不超过块剩余空间或剩余数据）
        size_t bytes_to_write = block_size - block_offset;
        if (bytes_to_write > remaining)
            bytes_to_write = remaining;

        // 读取现有块数据（若存在）或初始化新块
        uint8_t *block_data = malloc(block_size);
        if (!block_data)
        {
            spin_unlock(&ext2_op_lock);
            return -ENOMEM;
        }
        vfs_read(f->device, block_data, physical_block * block_size, block_size);

        // 复制用户数据到块内指定位置
        fast_memcpy(block_data + block_offset, data, bytes_to_write);

        // 写回修改后的块数据
        vfs_write(f->device, block_data, physical_block * block_size, block_size);
        free(block_data);

        // 更新剩余数据和偏移
        data += bytes_to_write;
        remaining -= bytes_to_write;
        current_offset += bytes_to_write;
    }

    // 更新inode元数据
    if (current_offset > f_inode.i_size)
        f_inode.i_size = current_offset; // 扩展文件大小

    tm time;
    time_read(&time);
    f_inode.i_mtime = mktime(&time);
    ext2_write_inode(f, f->inode_id, &f_inode); // 写回inode

    spin_unlock(&ext2_op_lock);

    return size - remaining;
}

ssize_t ext2_read(void *file, void *addr, size_t offset, size_t size)
{
    ext2_file_t *f = (ext2_file_t *)file;
    if (f->inode_id == 0)
        return -EINVAL;

    spin_lock(&ext2_op_lock);

    ext2_inode_t f_inode;

    uint32_t block_group = (f->inode_id - 1) / f->inodes_per_group;
    ext2_block_group_desc_t bg_desc;

    if (ext2_read_bg_desc(f, block_group, &bg_desc) < 0)
    {
        spin_unlock(&ext2_op_lock);
        return 0;
    }

    uint64_t inode_table_offset = bg_desc.bg_inode_table * f->block_size;
    uint32_t inode_index = (f->inode_id - 1) % f->inodes_per_group;
    uint64_t inode_offset = inode_table_offset + inode_index * f->inode_size;

    vfs_read(f->device, &f_inode, inode_offset, sizeof(ext2_inode_t));

    uint8_t *buffer = (uint8_t *)addr;
    size_t remaining = size;
    size_t current_offset = offset;
    uint32_t block_size = f->block_size;

    size_t file_size = (f->node->type & file_symlink) ? f_inode.i_size : f->node->size;

    while (remaining > 0)
    {
        size_t file_remaining = file_size - current_offset;
        if (file_remaining <= 0)
            break;

        uint32_t logical_block = current_offset / block_size;
        uint32_t block_offset = current_offset % block_size;
        uint32_t physical_block = ext2_get_physical_block(f, &f_inode, logical_block);

        size_t bytes_to_read = block_size - block_offset;
        bytes_to_read = MIN(bytes_to_read, MIN(file_remaining, remaining));

        uint8_t *block_data = malloc(block_size);
        vfs_read(f->device, block_data, physical_block * block_size, block_size);
        fast_memcpy(buffer, block_data + block_offset, bytes_to_read);
        free(block_data);

        buffer += bytes_to_read;
        remaining -= bytes_to_read;
        current_offset += bytes_to_read;
    }

    spin_unlock(&ext2_op_lock);

    return size - remaining;
}

int ext2_mkfile(void *parent, const char *name, vfs_node_t node)
{
    ext2_file_t *parent_dir = (ext2_file_t *)parent;
    if (!parent_dir || !name || !node)
        return -EINVAL;

    // 检查文件是否已存在
    vfs_node_t existing = vfs_open_at(parent_dir->node, name, false);
    if (existing && existing->handle)
    {
        vfs_close(existing);
        return -EEXIST;
    }
    if (existing)
        vfs_close(existing);

    uint32_t new_inode_id = ext2_find_free_inode(parent_dir);
    if (new_inode_id == 0)
        return -ENOSPC;

    tm time;
    time_read(&time);
    uint64_t now_time = mktime(&time);

    ext2_inode_t new_inode;
    memset(&new_inode, 0, sizeof(ext2_inode_t));
    new_inode.i_mode = S_IFREG | 0644;
    new_inode.i_uid = current_task->uid;
    new_inode.i_gid = current_task->gid;
    new_inode.i_atime = new_inode.i_ctime = new_inode.i_mtime = now_time;
    new_inode.i_links_count = 1;
    new_inode.i_blocks = 0;
    new_inode.i_size = 0;

    // 写回新inode
    ext2_write_inode(parent_dir, new_inode_id, &new_inode);

    // 添加目录项
    int ret = ext2_add_dir_entry(parent_dir, name, new_inode_id, EXT2_FT_REGULAR);
    if (ret < 0)
    {
        ext2_inode_t empty_inode;
        memset(&empty_inode, 0, sizeof(ext2_inode_t));
        ext2_write_inode(parent_dir, new_inode_id, &empty_inode);
        return ret;
    }

    ext2_inode_t parent_inode;
    uint32_t parent_block_group = (parent_dir->inode_id - 1) / parent_dir->inodes_per_group;
    uint32_t parent_inode_index = (parent_dir->inode_id - 1) % parent_dir->inodes_per_group;
    uint64_t bg_desc_block = 1 + (parent_block_group * sizeof(ext2_block_group_desc_t)) / parent_dir->block_size;
    uint64_t bg_desc_offset = (parent_block_group * sizeof(ext2_block_group_desc_t)) % parent_dir->block_size;
    uint8_t *bg_block = malloc(parent_dir->block_size);
    vfs_read(parent_dir->device, bg_block, bg_desc_block * parent_dir->block_size, parent_dir->block_size);
    ext2_block_group_desc_t bg_desc;
    fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);
    uint64_t inode_table_offset = bg_desc.bg_inode_table * parent_dir->block_size;
    uint64_t inode_offset = inode_table_offset + parent_inode_index * parent_dir->inode_size;
    vfs_read(parent_dir->device, &parent_inode, inode_offset, sizeof(ext2_inode_t));
    parent_inode.i_mtime = now_time;
    ext2_write_inode(parent_dir, parent_dir->inode_id, &parent_inode);

    node->inode = new_inode_id;
    node->fsid = ext2_fsid;
    node->type = file_none;

    return 0;
}

int ext2_mkdir(void *parent, const char *name, vfs_node_t node)
{
    ext2_file_t *parent_dir = (ext2_file_t *)parent;
    if (!parent_dir || !name)
        return -EFAULT;

    // 检查目录是否已存在
    vfs_node_t existing = vfs_open_at(parent_dir->node, name, false);
    if (existing && existing->handle)
    {
        vfs_close(existing);
        return -EEXIST;
    }
    if (existing)
        vfs_close(existing);

    uint32_t parent_block_group = (parent_dir->inode_id - 1) / parent_dir->inodes_per_group;
    uint32_t parent_inode_index = (parent_dir->inode_id - 1) % parent_dir->inodes_per_group;

    uint64_t bg_desc_block = 1 + (parent_block_group * sizeof(ext2_block_group_desc_t)) / parent_dir->block_size;
    uint64_t bg_desc_offset = (parent_block_group * sizeof(ext2_block_group_desc_t)) % parent_dir->block_size;

    uint8_t *bg_block = malloc(parent_dir->block_size);
    if (!bg_block)
        return -ENOMEM;
    if (vfs_read(parent_dir->device, bg_block, bg_desc_block * parent_dir->block_size, parent_dir->block_size) < 0)
    {
        free(bg_block);
        return -EIO;
    }

    ext2_block_group_desc_t bg_desc;
    fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    uint64_t parent_inode_table_offset = bg_desc.bg_inode_table * parent_dir->block_size;
    uint64_t parent_inode_offset = parent_inode_table_offset + parent_inode_index * parent_dir->inode_size;

    ext2_inode_t parent_inode;
    if (vfs_read(parent_dir->device, &parent_inode, parent_inode_offset, sizeof(ext2_inode_t)) < 0)
        return -EIO;

    uint32_t new_inode_id = ext2_find_free_inode(parent_dir);
    if (new_inode_id == 0)
        return -ENOSPC;

    tm time;
    time_read(&time);
    uint64_t now_time = mktime(&time);

    ext2_inode_t new_inode = {0};
    new_inode.i_mode = S_IFDIR | 0700;
    new_inode.i_uid = current_task->uid;
    new_inode.i_gid = current_task->gid;
    new_inode.i_atime = new_inode.i_ctime = new_inode.i_mtime = now_time;
    new_inode.i_links_count = 2;
    new_inode.i_blocks = 2;
    new_inode.i_size = parent_dir->block_size;

    // 分配新块
    uint32_t new_block = ext2_find_free_block(parent_dir);
    if (new_block == 0)
    {
        return -ENOSPC;
    }

    // 初始化目录块
    uint8_t *dir_block = malloc(parent_dir->block_size);
    if (!dir_block)
        return -ENOMEM;
    memset(dir_block, 0, parent_dir->block_size);

    // 设置.和..目录项
    ext2_dirent_t *dot = (ext2_dirent_t *)dir_block;
    dot->inode_id = new_inode_id;
    dot->rec_len = 24;
    dot->name_len = 1;
    dot->type = EXT2_FT_DIRECTORY;
    fast_memcpy(dot->name, ".", 1);

    ext2_dirent_t *dotdot = (ext2_dirent_t *)(dir_block + dot->rec_len);
    dotdot->inode_id = parent_dir->inode_id;
    dotdot->rec_len = parent_dir->block_size - dot->rec_len;
    dotdot->name_len = 2;
    dotdot->type = EXT2_FT_DIRECTORY;
    fast_memcpy(dotdot->name, "..", 2);

    // 写入新目录块
    if (vfs_write(parent_dir->device, dir_block, new_block * parent_dir->block_size, parent_dir->block_size) < 0)
    {
        free(dir_block);
        return -EIO;
    }
    free(dir_block);

    // 更新新目录inode
    new_inode.i_block[0] = new_block;
    ext2_write_inode(parent_dir, new_inode_id, &new_inode);

    // 在父目录中添加目录项
    int ret = ext2_add_dir_entry(parent_dir, name, new_inode_id, EXT2_FT_DIRECTORY);
    if (ret < 0)
    {
        // 失败时清理已分配的资源
        ext2_inode_t empty_inode = {0};
        ext2_write_inode(parent_dir, new_inode_id, &empty_inode);
        return ret;
    }

    // 更新父目录时间
    parent_inode.i_mtime = now_time;
    ext2_write_inode(parent_dir, parent_dir->inode_id, &parent_inode);

    node->inode = new_inode_id;
    node->type = file_dir;
    node->fsid = ext2_fsid;

    return 0;
}

int ext2_delete(void *parent, vfs_node_t node)
{
    ext2_file_t *parent_dir = (ext2_file_t *)parent;

    ext2_file_t *file = (ext2_file_t *)node->handle;

    uint32_t block_group = (parent_dir->inode_id - 1) / parent_dir->inodes_per_group;
    uint32_t inode_index = (parent_dir->inode_id - 1) % parent_dir->inodes_per_group;

    uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / parent_dir->block_size;
    uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % parent_dir->block_size;

    uint8_t *bg_block = malloc(parent_dir->block_size);
    vfs_read(parent_dir->device, bg_block, bg_desc_block * parent_dir->block_size, parent_dir->block_size);
    ext2_block_group_desc_t bg_desc;
    fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    uint64_t inode_table_offset = bg_desc.bg_inode_table * parent_dir->block_size;
    uint64_t inode_offset = inode_table_offset + inode_index * parent_dir->inode_size;

    ext2_inode_t parent_inode;
    vfs_read(parent_dir->device, &parent_inode, inode_offset, sizeof(ext2_inode_t));

    for (int i = 0; i < 12; i++)
    {
        if (parent_inode.i_block[i] == 0)
            break;

        uint8_t *block = malloc(parent_dir->block_size);
        vfs_read(parent_dir->device, block, parent_inode.i_block[i] * parent_dir->block_size, parent_dir->block_size);

        ext2_dirent_t *dirent = (ext2_dirent_t *)block;
        ext2_dirent_t *prev_dirent = NULL;
        while ((uint8_t *)dirent < block + parent_dir->block_size)
        {
            if (dirent->inode_id == file->inode_id)
            {
                uint32_t block_group = (file->inode_id - 1) / file->inodes_per_group;
                uint32_t inode_index = (file->inode_id - 1) % file->inodes_per_group;

                uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / file->block_size;
                uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % file->block_size;

                uint8_t *bg_block = malloc(file->block_size);
                vfs_read(file->device, bg_block, bg_desc_block * file->block_size, file->block_size);
                ext2_block_group_desc_t bg_desc;
                fast_memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
                free(bg_block);

                uint64_t inode_table_offset = bg_desc.bg_inode_table * file->block_size;
                uint64_t inode_offset = inode_table_offset + inode_index * file->inode_size;

                ext2_inode_t target_inode;
                vfs_read(file->device, &target_inode, inode_offset, sizeof(ext2_inode_t));

                if (node->type & file_dir)
                {
                    if (list_length(node->child) > 0)
                    {
                        return -ENOTEMPTY;
                    }

                    ext2_free_inode_blocks(file, &target_inode);

                    if (prev_dirent)
                    {
                        prev_dirent->rec_len += dirent->rec_len;
                    }
                    else
                    {
                        dirent->rec_len = 0;
                    }

                    vfs_write(parent_dir->device, block, parent_inode.i_block[i] * parent_dir->block_size, parent_dir->block_size);

                    list_delete(parent_dir->node->child, node);

                    free(block);

                    ext2_remove_dir_entry(parent_dir, node->name);

                    return 0;
                }
                else
                {
                    ext2_free_inode_blocks(file, &target_inode);

                    if (prev_dirent)
                    {
                        prev_dirent->rec_len += dirent->rec_len;
                    }
                    else
                    {
                        dirent->rec_len = 0;
                    }

                    vfs_write(parent_dir->device, block, parent_inode.i_block[i] * parent_dir->block_size, parent_dir->block_size);

                    list_delete(parent_dir->node->child, node);

                    free(block);

                    ext2_remove_dir_entry(parent_dir, node->name);

                    return 0;
                }
            }

            prev_dirent = dirent;
            dirent = (ext2_dirent_t *)((uint8_t *)dirent + dirent->rec_len);
        }

        free(block);
    }

    return -ENOENT;
}

int ext2_rename(void *current, const char *new)
{
    return 0;
}

int ext2_stat(void *file, vfs_node_t node)
{
    ext2_file_t *f = file;
    if (node->type & file_symlink)
        ext2_read_linkname(file, node);
    if (node->type & file_none)
        ext2_update(node);
    f->node = node;
    return 0;
}

int ext2_ioctl(void *file, ssize_t cmd, ssize_t arg)
{
    return -ENOSYS;
}

int ext2_poll(void *file, size_t events)
{
    return -EOPNOTSUPP;
}

vfs_node_t ext2_dup(vfs_node_t node)
{
    if (!node)
        return NULL;

    // 创建新的vfs节点
    vfs_node_t new_node = vfs_node_alloc(node->parent, node->name);
    if (!new_node)
        return NULL;

    // 复制节点属性
    memcpy(new_node, node, sizeof(struct vfs_node));

    return new_node;
}

static struct vfs_callback callbacks = {
    .mount = ext2_mount,
    .unmount = ext2_unmount,
    .open = ext2_open,
    .close = ext2_close,
    .read = ext2_read,
    .write = ext2_write,
    .mkdir = ext2_mkdir,
    .mkfile = ext2_mkfile,
    .delete = ext2_delete,
    .rename = ext2_rename,
    .stat = ext2_stat,
    .ioctl = ext2_ioctl,
    .poll = ext2_poll,
    .dup = ext2_dup,
};

void ext2_init()
{
    ext2_fsid = vfs_regist("ext2", &callbacks);
}

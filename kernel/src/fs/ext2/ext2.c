#include <fs/ext2/ext2.h>

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
    memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    uint64_t inode_table_offset = bg_desc.bg_inode_table * file->block_size;
    uint64_t inode_offset = inode_table_offset + inode_index * file->inode_size;

    ext2_inode_t file_inode;
    vfs_read(file->device, &file_inode, inode_offset, sizeof(ext2_inode_t));

    node->size = file_inode.i_size;
    node->mode = file_inode.i_mode;
    node->readtime = file_inode.i_atime;
    node->createtime = file_inode.i_ctime;
    node->writetime = file_inode.i_atime;
}

int ext2_fsid = 0;

void ext2_readdir(ext2_file_t *dir, vfs_node_t parent)
{
    uint32_t block_group = (dir->inode_id - 1) / dir->inodes_per_group;
    uint32_t inode_index = (dir->inode_id - 1) % dir->inodes_per_group;

    uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / dir->block_size;
    uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % dir->block_size;

    uint8_t *bg_block = malloc(dir->block_size);
    vfs_read(dir->device, bg_block, bg_desc_block * dir->block_size, dir->block_size);
    ext2_block_group_desc_t bg_desc;
    memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    uint64_t inode_table_offset = bg_desc.bg_inode_table * dir->block_size;
    uint64_t inode_offset = inode_table_offset + inode_index * dir->inode_size;

    ext2_inode_t dir_inode;
    vfs_read(dir->device, &dir_inode, inode_offset, sizeof(ext2_inode_t));

    for (int i = 0; i < 12; i++)
    {
        if (dir_inode.i_block[i] == 0)
            break;

        uint8_t *block = malloc(dir->block_size);
        uint64_t block_offset = dir_inode.i_block[i] * dir->block_size;
        vfs_read(dir->device, block, block_offset, dir->block_size);

        ext2_dirent_t *dirent = (ext2_dirent_t *)block;
        while ((uint8_t *)dirent < block + dir->block_size)
        {
            char entry_name[256];
            memcpy(entry_name, (char *)dirent->name, dirent->name_len);
            entry_name[dirent->name_len] = 0;

            if (dirent->inode_id != 0 && strlen(entry_name) != 0)
            {
                if (streq(entry_name, ".") || streq(entry_name, ".."))
                    goto next;

                vfs_node_t child = vfs_child_append(parent, entry_name, NULL);
                child->type = (dirent->type == EXT2_FT_DIRECTORY) ? file_dir : file_none;
                child->fsid = ext2_fsid;
            }
            if (dirent->rec_len == 0)
                break;

        next:
            dirent = (ext2_dirent_t *)((uint8_t *)dirent + dirent->rec_len);
        }

        free(block);
    }
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
    memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    uint64_t inode_table_offset = bg_desc.bg_inode_table * file->block_size;
    uint64_t inode_offset = inode_table_offset + inode_index * file->inode_size;

    ext2_inode_t file_inode;
    vfs_read(file->device, &file_inode, inode_offset, sizeof(ext2_inode_t));

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

void ext2_open(void *parent, const char *name, vfs_node_t node)
{
    ext2_file_t *dir = (ext2_file_t *)parent;

    uint32_t block_group = (dir->inode_id - 1) / dir->inodes_per_group;
    uint32_t inode_index = (dir->inode_id - 1) % dir->inodes_per_group;

    uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / dir->block_size;
    uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % dir->block_size;

    uint8_t *bg_block = malloc(dir->block_size);
    vfs_read(dir->device, bg_block, bg_desc_block * dir->block_size, dir->block_size);
    ext2_block_group_desc_t bg_desc;
    memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
    free(bg_block);

    uint64_t inode_table_offset = bg_desc.bg_inode_table * dir->block_size;
    uint64_t inode_offset = inode_table_offset + inode_index * dir->inode_size;

    ext2_inode_t dir_inode;
    vfs_read(dir->device, &dir_inode, inode_offset, sizeof(ext2_inode_t));

    for (int i = 0; i < 12; i++)
    {
        if (dir_inode.i_block[i] == 0)
            break;

        uint8_t *block = malloc(dir->block_size);
        uint64_t block_offset = dir_inode.i_block[i] * dir->block_size;
        vfs_read(dir->device, block, block_offset, dir->block_size);

        ext2_dirent_t *dirent = (ext2_dirent_t *)block;
        while ((uint8_t *)dirent < block + dir->block_size)
        {
            char entry_name[256];
            memcpy(entry_name, (char *)dirent->name, dirent->name_len);
            entry_name[dirent->name_len] = 0;

            if (dirent->inode_id)
            {
                if (streq(entry_name, ".") || streq(entry_name, ".."))
                    goto next;

                if (strcmp(entry_name, name) == 0)
                {
                    // found
                    node->type = (dirent->type == EXT2_FT_DIRECTORY) ? file_dir : (dirent->type == EXT2_FT_SYMLINK) ? file_symlink
                                                                                                                    : file_none;
                    ext2_file_t *handle = malloc(sizeof(ext2_file_t));
                    handle->device = dir->device;
                    handle->inode_id = dirent->inode_id;
                    handle->block_size = dir->block_size;
                    handle->inode_size = dir->inode_size;
                    handle->inodes_per_group = dir->inodes_per_group;
                    handle->file_type = dirent->type;
                    handle->node = node;
                    node->inode = handle->inode_id;
                    node->handle = handle;
                    node->fsid = ext2_fsid;
                    if (node->type == file_dir)
                        ext2_readdir(handle, node);
                    else if (node->type == file_symlink)
                        ext2_read_linkname(handle, node);
                    ext2_update(node);
                    free(block);
                    return;
                }
            }
            if (dirent->rec_len == 0)
                break;

        next:
            dirent = (ext2_dirent_t *)((uint8_t *)dirent + dirent->rec_len);
        }

        free(block);
    }

    node->handle = NULL;
}

void ext2_close(void *current)
{
    free(current);
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
        return -1;
    }

    file->inode_id = 2;
    file->block_size = 1024 << sb.s_log_block_size;
    file->inode_size = sb.e_s_inode_size;
    file->inodes_per_group = sb.s_inodes_per_group;
    file->file_type = EXT2_FT_REGULAR;
    file->node = node;

    node->inode = file->inode_id;
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

ssize_t ext2_write(void *file, const void *addr, size_t offset, size_t size)
{
    ext2_file_t *f = (ext2_file_t *)file;
    if (f->inode_id == 0)
        return -EINVAL;

    ext2_inode_t f_inode;

    if (f->node->type == file_symlink)
    {
        vfs_node_t node = vfs_open_at(f->node->parent, (const char *)f->node->linkname);
        if (!node)
            return -ENOENT;

        ext2_file_t *link_f = node->handle;

        uint32_t block_group = (link_f->inode_id - 1) / link_f->inodes_per_group;
        uint32_t inode_index = (link_f->inode_id - 1) % link_f->inodes_per_group;

        uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / link_f->block_size;
        uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % link_f->block_size;

        uint8_t *bg_block = malloc(link_f->block_size);
        vfs_read(link_f->device, bg_block, bg_desc_block * link_f->block_size, link_f->block_size);
        ext2_block_group_desc_t bg_desc;
        memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
        free(bg_block);

        uint64_t inode_table_offset = bg_desc.bg_inode_table * link_f->block_size;
        uint64_t inode_offset = inode_table_offset + inode_index * link_f->inode_size;

        vfs_read(link_f->device, &f_inode, inode_offset, sizeof(ext2_inode_t));

        vfs_close(node);
    }
    else
    {
        uint32_t block_group = (f->inode_id - 1) / f->inodes_per_group;
        uint32_t inode_index = (f->inode_id - 1) % f->inodes_per_group;

        uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / f->block_size;
        uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % f->block_size;

        uint8_t *bg_block = malloc(f->block_size);
        vfs_read(f->device, bg_block, bg_desc_block * f->block_size, f->block_size);
        ext2_block_group_desc_t bg_desc;
        memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
        free(bg_block);

        uint64_t inode_table_offset = bg_desc.bg_inode_table * f->block_size;
        uint64_t inode_offset = inode_table_offset + inode_index * f->inode_size;

        vfs_read(f->device, &f_inode, inode_offset, sizeof(ext2_inode_t));
    }

    return 0;
}

ssize_t ext2_read(void *file, void *addr, size_t offset, size_t size)
{
    ext2_file_t *f = (ext2_file_t *)file;
    if (f->inode_id == 0)
        return -EINVAL;

    ext2_inode_t f_inode;

    if (f->node->type == file_symlink)
    {
        vfs_node_t node = vfs_open_at(f->node->parent, (const char *)f->node->linkname);
        if (!node)
            return -ENOENT;

        ext2_file_t *link_f = node->handle;

        uint32_t block_group = (link_f->inode_id - 1) / link_f->inodes_per_group;
        uint32_t inode_index = (link_f->inode_id - 1) % link_f->inodes_per_group;

        uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / link_f->block_size;
        uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % link_f->block_size;

        uint8_t *bg_block = malloc(link_f->block_size);
        vfs_read(link_f->device, bg_block, bg_desc_block * link_f->block_size, link_f->block_size);
        ext2_block_group_desc_t bg_desc;
        memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
        free(bg_block);

        uint64_t inode_table_offset = bg_desc.bg_inode_table * link_f->block_size;
        uint64_t inode_offset = inode_table_offset + inode_index * link_f->inode_size;

        vfs_read(link_f->device, &f_inode, inode_offset, sizeof(ext2_inode_t));

        vfs_close(node);
    }
    else
    {
        uint32_t block_group = (f->inode_id - 1) / f->inodes_per_group;
        uint32_t inode_index = (f->inode_id - 1) % f->inodes_per_group;

        uint64_t bg_desc_block = 1 + (block_group * sizeof(ext2_block_group_desc_t)) / f->block_size;
        uint64_t bg_desc_offset = (block_group * sizeof(ext2_block_group_desc_t)) % f->block_size;

        uint8_t *bg_block = malloc(f->block_size);
        vfs_read(f->device, bg_block, bg_desc_block * f->block_size, f->block_size);
        ext2_block_group_desc_t bg_desc;
        memcpy(&bg_desc, bg_block + bg_desc_offset, sizeof(ext2_block_group_desc_t));
        free(bg_block);

        uint64_t inode_table_offset = bg_desc.bg_inode_table * f->block_size;
        uint64_t inode_offset = inode_table_offset + inode_index * f->inode_size;

        vfs_read(f->device, &f_inode, inode_offset, sizeof(ext2_inode_t));
    }

    uint8_t *buffer = (uint8_t *)addr;
    size_t remaining = size;
    size_t current_offset = offset;
    uint32_t block_size = f->block_size;

    while (remaining > 0)
    {
        uint32_t logical_block = current_offset / block_size;
        uint32_t block_offset = current_offset % block_size;
        uint32_t physical_block = ext2_get_physical_block(f, &f_inode, logical_block);

        if (physical_block == 0)
            break;

        size_t bytes_to_read = block_size - block_offset;
        if (bytes_to_read > remaining)
            bytes_to_read = remaining;

        uint8_t *block_data = malloc(block_size);
        vfs_read(f->device, block_data, physical_block * block_size, block_size);

        memcpy(buffer, block_data + block_offset, bytes_to_read);
        free(block_data);

        buffer += bytes_to_read;
        remaining -= bytes_to_read;
        current_offset += bytes_to_read;
    }

    return size - remaining;
}

int ext2_mkfile(void *parent, const char *name, vfs_node_t node)
{
    return 0;
}

int ext2_mkdir(void *parent, const char *name, vfs_node_t node)
{
    return 0;
}

int ext2_delete(void *current)
{
    return 0;
}

int ext2_rename(void *current, const char *new)
{
    return 0;
}

int ext2_stat(void *file, vfs_node_t node)
{
    (void)file;

    ext2_update(node);

    return 0;
}

int ext2_ioctl(void *file, ssize_t cmd, ssize_t arg)
{
    return -ENOSYS;
}

int ext2_poll(void *file, size_t events)
{
    return -ENOSYS;
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
};

void ext2_init()
{
    ext2_fsid = vfs_regist("ext2", &callbacks);
}

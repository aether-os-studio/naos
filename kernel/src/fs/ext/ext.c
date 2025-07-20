#include <fs/ext/ext.h>
#include <mm/mm_syscall.h>

static int ext_fsid = 0;

spinlock_t rwlock = {0};

int ext_mount(const char *src, vfs_node_t node)
{
    ext4_device_register(vfs_dev_get(), src);

    vfs_dev_name_set(src);

    char *fullpath = vfs_get_fullpath(node);
    int ret = ext4_mount(src, (const char *)fullpath, false);

    if (ret != 0)
    {
        ext4_device_unregister(src);
        free(fullpath);
        return -1;
    }

    ext4_dir *dir = malloc(sizeof(ext4_dir));
    ext4_dir_open(dir, (const char *)fullpath);

    free(fullpath);

    ext4_direntry *entry;
    while ((entry = ext4_dir_entry_next(dir)))
    {
        if (!strcmp((const char *)entry->name, ".") || !strcmp((const char *)entry->name, ".."))
            continue;
        if (vfs_child_find(node, (const char *)entry->name))
            continue;
        vfs_node_t child = vfs_child_append(node, (const char *)entry->name, NULL);
        child->inode = (uint64_t)entry->inode;
        child->fsid = ext_fsid;
        if (entry->inode_type == EXT4_DE_SYMLINK)
            child->type = file_symlink;
        else if (entry->inode_type == EXT4_DE_DIR)
            child->type = file_dir;
        else
            child->type = file_none;
    }

    ext4_dir_close(dir);

    ext_handle_t *handle = malloc(sizeof(ext_handle_t));
    handle->dir = dir;
    handle->node = node;

    node->inode = EXT4_ROOT_INO;
    node->handle = handle;

    return ret;
}

void ext_unmount(void *root)
{
    // TODO
}

void ext_open(void *parent, const char *name, vfs_node_t node)
{
    spin_lock(&rwlock);

    ext_handle_t *handle = malloc(sizeof(ext4_file));
    handle->node = node;
    char *path = vfs_get_fullpath(node);
    if (node->type & file_dir)
    {
        handle->dir = malloc(sizeof(ext4_dir));
        ext4_dir_open(handle->dir, (const char *)path);

        ext4_direntry *entry;

        while ((entry = ext4_dir_entry_next(handle->dir)))
        {
            if (!strcmp((const char *)entry->name, ".") || !strcmp((const char *)entry->name, ".."))
                continue;
            if (vfs_child_find(node, (const char *)entry->name))
                continue;
            vfs_node_t child = vfs_child_append(node, (const char *)entry->name, NULL);
            child->fsid = ext_fsid;
            child->inode = (uint64_t)entry->inode;
            if (entry->inode_type == EXT4_DE_SYMLINK)
                child->type = file_symlink;
            else if (entry->inode_type == EXT4_DE_DIR)
                child->type = file_dir;
            else
                child->type = file_none;
        }

        ext4_dir_entry_rewind(handle->dir);
    }
    else if (node->type & file_symlink)
    {
        char *path = vfs_get_fullpath(node);
        char *buf = malloc(1024);
        size_t rcnt = 0;
        ext4_readlink((const char *)path, buf, 1024, &rcnt);
        free(path);
        buf[rcnt] = '\0';
        node->linkname = buf;

        ext4_file *lfile = malloc(sizeof(ext4_file));
        path = vfs_get_fullpath(handle->node->parent);
        char buffer[1024];
        if (!strcmp(path, "/"))
            sprintf(buffer, "/%s", node->linkname);
        else
            sprintf(buffer, "%s/%s", path, node->linkname);
        free(path);
        ext4_fopen(lfile, (const char *)buffer, "r+b");
        node->size = ext4_fsize(lfile);
        ext4_fclose(lfile);

        handle->file = lfile;
    }
    else
    {
        handle->file = malloc(sizeof(ext4_file));
        ext4_fopen(handle->file, (const char *)path, "r+b");
        node->size = ext4_fsize(handle->file);
    }

    free(path);

    char buf[1024];

    ext_handle_t *parent_handle = parent;
    char *parent_path = vfs_get_fullpath(parent_handle->node);
    if (!strcmp(parent_path, "/"))
        sprintf(buf, "/%s", name);
    else
        sprintf(buf, "%s/%s", parent_path, name);
    free(parent_path);

    uint32_t mode = 0;
    ext4_mode_get((const char *)buf, &mode);
    node->mode = mode;
    node->handle = handle;

    spin_unlock(&rwlock);
}

bool ext_close(void *current)
{
    spin_lock(&rwlock);
    ext_handle_t *handle = current;
    ext4_fclose(handle->file);
    free(current);
    spin_unlock(&rwlock);
    return true;
}

ssize_t ext_write(void *file, const void *addr, size_t offset, size_t size)
{
    spin_lock(&rwlock);

    ssize_t ret = 0;
    ext_handle_t *handle = file;
    if (handle->node->size < offset)
    {
        char *zero_buf = malloc(offset - handle->node->size);
        memset(zero_buf, 0, offset - handle->node->size);
        ext4_fseek(handle->file, (int64_t)handle->node->size, (uint32_t)SEEK_SET);
        ext4_fwrite(handle->file, zero_buf, offset - handle->node->size, NULL);
        free(zero_buf);
    }
    ext4_fseek(handle->file, (int64_t)offset, (uint32_t)SEEK_SET);
    ext4_fwrite(handle->file, addr, size, (size_t *)&ret);
    handle->node->size = ext4_fsize(handle->file);

    spin_unlock(&rwlock);

    return ret;
}

ssize_t ext_read(void *file, void *addr, size_t offset, size_t size)
{
    spin_lock(&rwlock);
    ssize_t ret = 0;
    ext_handle_t *handle = file;
    if (handle->node->type & file_symlink)
    {
        ext4_file lfile;
        char *path = vfs_get_fullpath(handle->node->parent);
        char buf[1024];
        if (!strcmp(path, "/"))
            sprintf(buf, "/%s", handle->node->linkname);
        else
            sprintf(buf, "%s/%s", path, handle->node->linkname);
        free(path);
        ext4_fopen(&lfile, (const char *)buf, "r+b");
        ext4_fseek(&lfile, offset, (uint32_t)SEEK_SET);
        ext4_fread(&lfile, addr, size, (size_t *)&ret);
        ext4_fclose(&lfile);
    }
    else
    {
        ext4_fseek(handle->file, (int64_t)offset, (uint32_t)SEEK_SET);
        ext4_fread(handle->file, addr, size, (size_t *)&ret);
    }
    spin_unlock(&rwlock);
    return ret;
}

ssize_t ext_readlink(void *file, void *addr, size_t offset, size_t size)
{
    ext_handle_t *handle = file;

    vfs_node_t node = handle->node;

    vfs_node_t original_node = node;
    while (original_node->link_by)
    {
        original_node = original_node->link_by;
    }

    vfs_node_t target_node = vfs_open_at(original_node->parent, original_node->linkname, false);
    if (!target_node)
    {
        return -1;
    }

    char *node_path = vfs_get_fullpath(target_node);
    vfs_close(target_node);
    char *original_node_path = vfs_get_fullpath(original_node);

    char relative_path[1024];
    memset(relative_path, 0, sizeof(relative_path));
    rel_status status = calculate_relative_path(relative_path, original_node_path, node_path, size);
    memcpy(addr, relative_path, size);

    free(node_path);
    free(original_node_path);

    return size;
}

int ext_mkfile(void *parent, const char *name, vfs_node_t node)
{
    spin_lock(&rwlock);
    char buf[1024];

    ext_handle_t *parent_handle = parent;
    char *parent_path = vfs_get_fullpath(parent_handle->node);
    if (!strcmp(parent_path, "/"))
        sprintf(buf, "/%s", name);
    else
        sprintf(buf, "%s/%s", parent_path, name);
    free(parent_path);

    ext4_file f;
    int ret = ext4_fopen2(&f, (const char *)buf, O_CREAT);
    ext4_fclose(&f);
    spin_unlock(&rwlock);

    return ret;
}

int ext_link(void *parent, const char *name, vfs_node_t node)
{
    spin_lock(&rwlock);
    char buf[1024];

    ext_handle_t *parent_handle = parent;
    char *parent_path = vfs_get_fullpath(parent_handle->node);
    if (!strcmp(parent_path, "/"))
        sprintf(buf, "/%s", name);
    else
        sprintf(buf, "%s/%s", parent_path, name);
    free(parent_path);

    ext4_file f;
    int ret = ext4_flink((const char *)buf, (const char *)node->linkname);
    ext4_fclose(&f);
    spin_unlock(&rwlock);

    return ret;
}

int ext_symlink(void *parent, const char *name, vfs_node_t node)
{
    spin_lock(&rwlock);
    char buf[1024];

    ext_handle_t *parent_handle = parent;
    char *parent_path = vfs_get_fullpath(parent_handle->node);
    if (!strcmp(parent_path, "/"))
        sprintf(buf, "/%s", name);
    else
        sprintf(buf, "%s/%s", parent_path, name);
    free(parent_path);

    int ret = ext4_fsymlink((const char *)node->linkname, (const char *)buf);
    spin_unlock(&rwlock);

    return ret;
}

int ext_mkdir(void *parent, const char *name, vfs_node_t node)
{
    spin_lock(&rwlock);
    char buf[1024];

    ext_handle_t *parent_handle = parent;
    char *parent_path = vfs_get_fullpath(parent_handle->node);
    if (!strcmp(parent_path, "/"))
        sprintf(buf, "/%s", name);
    else
        sprintf(buf, "%s/%s", parent_path, name);
    free(parent_path);

    int ret = ext4_dir_mk((const char *)buf);
    spin_unlock(&rwlock);

    return ret;
}

int ext_delete(void *parent, vfs_node_t node)
{
    spin_lock(&rwlock);
    char *path = vfs_get_fullpath(node);
    int ret = ext4_fremove((const char *)path);
    free(path);
    spin_unlock(&rwlock);
    return ret;
}

int ext_rename(void *current, const char *new)
{
    spin_lock(&rwlock);
    ext_handle_t *handle = current;
    char *path = vfs_get_fullpath(handle->node);
    int ret = ext4_frename((const char *)path, new);
    free(path);
    spin_unlock(&rwlock);
    return ret;
}

int ext_stat(void *file, vfs_node_t node)
{
    ext_handle_t *handle = file;
    if (handle->node->type & file_none)
    {
        handle->node->size = ext4_fsize(handle->file);
    }

    return 0;
}

int ext_ioctl(void *file, ssize_t cmd, ssize_t arg)
{
    return 0;
}

int ext_poll(void *file, size_t events)
{
    return 0;
}

void ext_resize(void *current, uint64_t size)
{
    spin_lock(&rwlock);
    ext_handle_t *handle = current;
    if (handle->node->type & file_none)
    {
        handle->node->size = ext4_ftruncate(handle->file, size);
    }
    spin_unlock(&rwlock);
}

void *ext_map(void *file, void *addr, size_t offset, size_t size, size_t prot, size_t flags)
{
    return general_map((vfs_read_t)ext_read, file, (uint64_t)addr, size, prot, flags, offset);
}

vfs_node_t ext_dup(vfs_node_t node)
{
    return node;
}

static struct vfs_callback callbacks = {
    .mount = ext_mount,
    .unmount = ext_unmount,
    .open = ext_open,
    .close = (vfs_close_t)ext_close,
    .read = (vfs_read_t)ext_read,
    .write = (vfs_write_t)ext_write,
    .readlink = (vfs_read_t)ext_readlink,
    .mkdir = ext_mkdir,
    .mkfile = ext_mkfile,
    .link = ext_link,
    .symlink = ext_symlink,
    .delete = (vfs_del_t)ext_delete,
    .rename = (vfs_rename_t)ext_rename,
    .map = (vfs_mapfile_t)ext_map,
    .stat = ext_stat,
    .ioctl = ext_ioctl,
    .poll = ext_poll,
    .resize = (vfs_resize_t)ext_resize,
    .dup = (vfs_dup_t)ext_dup,
};

void ext_init()
{
    ext_fsid = vfs_regist("ext", &callbacks);
}

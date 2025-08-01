// This code is released under the MIT License

#include "fs/fatfs/ff.h"
#include <drivers/kernel_logger.h>
#include <mm/mm_syscall.h>

static FATFS volume[10];
static int fatfs_id = 0;
typedef struct file
{
    char *path;
    void *handle;
} *file_t;

vfs_node_t drive_number_mapping[10] = {NULL};

static int alloc_number()
{
    for (int i = 0; i < 10; i++)
        if (drive_number_mapping[i] == NULL)
            return i;
    printk("No available drive number");
    return -1;
}

vfs_node_t fatfs_get_node_by_number(int number)
{
    if (number < 0 || number >= 10)
        return NULL;
    return drive_number_mapping[number];
}

int fatfs_mkdir(void *parent, const char *name, vfs_node_t node)
{
    file_t p = parent;
    char *new_path = malloc(strlen(p->path) + strlen((char *)name) + 1 + 1);
    sprintf(new_path, "%s/%s", p->path, name);
    FRESULT res = f_mkdir(new_path);
    free(new_path);
    if (res != FR_OK)
    {
        return -1;
    }
    return 0;
}

int fatfs_mkfile(void *parent, const char *name, vfs_node_t node)
{
    file_t p = parent;
    char *new_path = malloc(strlen(p->path) + strlen((char *)name) + 1 + 1);
    sprintf(new_path, "%s/%s", p->path, name);
    FIL fp;
    FRESULT res = f_open(&fp, new_path, FA_CREATE_NEW);
    f_close(&fp);
    free(new_path);
    if (res != FR_OK)
    {
        return -1;
    }
    return 0;
}

int fatfs_link(void *parent, const char *name, vfs_node_t node)
{
    return -ENOSYS;
}

int fatfs_symlink(void *parent, const char *name, vfs_node_t node)
{
    return -ENOSYS;
}

size_t fatfs_readfile(fd_t *fd, void *addr, size_t offset, size_t size)
{
    file_t file = fd->node->handle;

    if (file == NULL || addr == NULL)
        return -1;
    FRESULT res;
    res = f_lseek(file->handle, offset);
    if (res != FR_OK)
        return -1;
    uint32_t n;
    res = f_read(file->handle, addr, size, &n);
    if (res != FR_OK)
        return -1;
    return n;
}

size_t fatfs_writefile(fd_t *fd, const void *addr, size_t offset, size_t size)
{
    file_t file = fd->node->handle;

    if (file == NULL || addr == NULL)
        return -1;
    FRESULT res;
    res = f_lseek(file->handle, offset);
    if (res != FR_OK)
        return -1;
    uint32_t n;
    res = f_write(file->handle, addr, size, &n);
    if (res != FR_OK)
        return -1;
    return n;
}

static uint64_t ino = 1;

void fatfs_open(void *parent, const char *name, vfs_node_t node)
{
    file_t p = parent;
    char *new_path = malloc(strlen(p->path) + strlen((char *)name) + 1 + 1);
    file_t new = malloc(sizeof(struct file));
    sprintf(new_path, "%s/%s", p->path, name);
    void *fp = NULL;
    FILINFO fno;
    FRESULT res = f_stat(new_path, &fno);
    if (fno.fattrib & AM_DIR)
    {
        // node.
        node->type = file_dir;
        fp = malloc(sizeof(DIR));
        res = f_opendir(fp, new_path);
        for (;;)
        {
            // 读取目录下的内容，再读会自动读下一个文件
            res = f_readdir(fp, &fno);
            // 为空时表示所有项目读取完毕，跳出
            if (res != FR_OK || fno.fname[0] == 0)
                break;
            vfs_node_t child_node = vfs_child_append(node, fno.fname, NULL);
            child_node->type = ((fno.fattrib & AM_DIR) != 0) ? file_dir : file_none;
        }
        node->inode = ino++;
        node->blksz = DEFAULT_PAGE_SIZE;
    }
    else
    {
        node->type = file_none;
        fp = malloc(sizeof(FIL));
        res = f_open(fp, new_path, FA_READ | FA_WRITE);
        node->inode = ino++;
        node->size = f_size((FIL *)fp);
        node->blksz = DEFAULT_PAGE_SIZE;
    }

    new->handle = fp;
    new->path = new_path;
    node->handle = new;
}

bool fatfs_close(file_t handle)
{
    FILINFO fno;
    FRESULT res = f_stat(handle->path, &fno);
    if (fno.fattrib & AM_DIR)
    {
        res = f_closedir(handle->handle);
    }
    else
    {
        res = f_close(handle->handle);
    }
    if (res != FR_OK)
        return false;
    free(handle->path);
    free(handle->handle);
    free(handle);

    return true;
}

int fatfs_mount(const char *src, vfs_node_t node)
{
    if (node == rootdir)
        return -1; // 不支持fatfs作为rootfs
    if (!src)
        return -1;
    int drive = alloc_number();
    drive_number_mapping[drive] = vfs_open(src);
    char *path = malloc(3);
    sprintf(path, "%d:", drive);
    FRESULT r = f_mount(&volume[drive], path, 1);
    if (r != FR_OK)
    {
        vfs_close(drive_number_mapping[drive]);
        drive_number_mapping[drive] = NULL;
        free(path);
        return -1;
    }
    file_t f = malloc(sizeof(struct file));
    f->path = path;
    DIR *h = malloc(sizeof(DIR));
    f_opendir(h, path);
    f->handle = h;
    node->fsid = fatfs_id;

    FILINFO fno;
    FRESULT res;
    for (;;)
    {
        // 读取目录下的内容，再读会自动读下一个文件
        res = f_readdir(h, &fno);
        // 为空时表示所有项目读取完毕，跳出
        if (res != FR_OK || fno.fname[0] == 0)
            break;
        vfs_node_t child_node = vfs_child_append(node, (const char *)fno.fname, NULL);
        child_node->type = ((fno.fattrib & AM_DIR) != 0) ? file_dir : file_none;
    }
    node->inode = ino++;
    node->handle = f;
    node->blksz = DEFAULT_PAGE_SIZE;
    return 0;
}

void fatfs_unmount(void *root)
{
    file_t f = root;
    int number = f->path[0] - '0';
    drive_number_mapping[number] = NULL;
    f_closedir(f->handle);
    f_unmount(f->path);
    free(f->path);
    free(f->handle);
    free(f);
}

int fatfs_stat(void *handle, vfs_node_t node)
{
    file_t f = handle;
    FILINFO fno;
    FRESULT res = f_stat(f->path, &fno);
    if (res != FR_OK)
        return -1;
    if (fno.fattrib & AM_DIR)
    {
        node->type = file_dir;
    }
    else
    {
        node->type = file_none;
        node->size = fno.fsize;
        // node->createtime = fno.ftime
    }

    return 0;
}

int fatfs_delete(file_t parent, vfs_node_t node)
{
    file_t file = node->handle;

    FRESULT res = f_unlink(file->path);
    if (res != FR_OK)
        return -1;
    return 0;
}

int fatfs_rename(file_t file, const char *new)
{
    FRESULT res = f_rename((const char *)file->path, new);
    if (res != FR_OK)
        return -1;
    return 0;
}

int fatfs_ioctl(void *file, ssize_t cmd, ssize_t arg)
{
    return 0;
}

int fatfs_poll(void *file, size_t events)
{
    return -EOPNOTSUPP;
}

void *fatfs_map(void *file, void *addr, size_t offset, size_t size, size_t prot, size_t flags)
{
    return general_map((vfs_read_t)fatfs_readfile, file, (uint64_t)addr, size, prot, flags, offset);
}

static int dummy()
{
    return 0;
}

static struct vfs_callback callbacks = {
    .mount = fatfs_mount,
    .unmount = fatfs_unmount,
    .open = fatfs_open,
    .close = (vfs_close_t)fatfs_close,
    .read = (vfs_read_t)fatfs_readfile,
    .write = (vfs_write_t)fatfs_writefile,
    .readlink = (vfs_readlink_t)dummy,
    .mkdir = fatfs_mkdir,
    .mkfile = fatfs_mkfile,
    .link = fatfs_link,
    .symlink = fatfs_symlink,
    .delete = (vfs_del_t)fatfs_delete,
    .rename = (vfs_rename_t)fatfs_rename,
    .map = (vfs_mapfile_t)fatfs_map,
    .stat = fatfs_stat,
    .ioctl = fatfs_ioctl,
    .poll = fatfs_poll,
    .resize = (vfs_resize_t)dummy,
    .dup = vfs_generic_dup,
};

void fatfs_init()
{
    fatfs_id = vfs_regist("fatfs", &callbacks);
}

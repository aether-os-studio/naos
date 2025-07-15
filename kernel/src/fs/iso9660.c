#include <fs/vfs/vfs.h>
#include <mm/mm_syscall.h>

static inline const char *strchrnul(const char *_s, int _c)
{
    for (; *_s != '\0'; _s++)
    {
        if (*_s == _c)
            return (char *)_s;
    }
    return (char *)_s;
}

typedef enum
{
    L9660_OK = 0,
    L9660_EIO,
    L9660_EBADFS,
    L9660_ENOENT,
    L9660_ENOTFILE,
    L9660_ENOTDIR,
} l9660_status;

typedef struct
{
    uint8_t le[2];
} l9660_luint16;
typedef struct
{
    uint8_t be[2];
} l9660_buint16;
typedef struct
{
    uint8_t le[2], be[2];
} l9660_duint16;
typedef struct
{
    uint8_t le[4];
} l9660_luint32;
typedef struct
{
    uint8_t be[4];
} l9660_buint32;
typedef struct
{
    uint8_t le[4], be[4];
} l9660_duint32;

/* Descriptor time format */
typedef struct
{
    char d[17];
} l9660_desctime;

/* File time format */
typedef struct
{
    char d[7];
} l9660_filetime;

/* Directory entry */
typedef struct
{
    uint8_t length;
    uint8_t xattr_length;
    l9660_duint32 sector;
    l9660_duint32 size;
    l9660_filetime time;
    uint8_t flags;
    uint8_t unit_size;
    uint8_t gap_size;
    l9660_duint16 vol_seq_number;
    uint8_t name_len;
    char name[];
} l9660_dirent;

/* Volume descriptor header */
typedef struct
{
    uint8_t type;
    char magic[5];
    uint8_t version;
} l9660_vdesc_header;

/* Primary volume descriptor */
typedef struct
{
    l9660_vdesc_header hdr;
    char pad0[1];
    char system_id[32];
    char volume_id[32];
    char pad1[8];
    l9660_duint32 volume_space_size;
    char pad2[32];
    l9660_duint16 volume_set_size;
    l9660_duint16 volume_seq_number;
    l9660_duint16 logical_block_size;
    l9660_duint32 path_table_size;
    l9660_luint32 path_table_le;
    l9660_luint32 path_table_opt_le;
    l9660_buint32 path_table_be;
    l9660_buint32 path_table_opt_be;
    union
    {
        l9660_dirent root_dir_ent;
        char pad3[34];
    };
    char volume_set_id[128];
    char data_preparer_id[128];
    char app_id[128];
    char copyright_file[38];
    char abstract_file[36];
    char bibliography_file[37];
    l9660_desctime volume_created, volume_modified, volume_expires, volume_effective;
    uint8_t file_structure_version;
    char pad4[1];
    char app_reserved[512];
    char reserved[653];
} l9660_vdesc_primary;

/* A generic volume descriptor (i.e. 2048 bytes) */
typedef union
{
    l9660_vdesc_header hdr;
    char _bits[2048];
} l9660_vdesc;

typedef struct l9660_fs
{
#ifdef L9660_SINGLEBUFFER
    union
    {
        l9660_dirent root_dir_ent;
        char root_dir_pad[34];
    };
#else
    /* Sector buffer to hold the PVD */
    l9660_vdesc pvd;
#endif

    /* read_sector func */
    bool (*read_sector)(struct l9660_fs *fs, void *buf, uint32_t sector);
    vfs_node_t device;
} l9660_fs;

typedef struct
{
#ifndef L9660_SINGLEBUFFER
    /* single sector buffer */
    char buf[2048];
#endif
    l9660_fs *fs;
    uint32_t first_sector;
    uint32_t position;
    uint32_t length;
} l9660_file;

typedef struct
{
    /* directories are mostly just files with special accessors, but we like type safetey */
    l9660_file file;
} l9660_dir;

typedef struct l9660_fs_status
{
    l9660_fs *fs;
    l9660_dir root_dir;
    l9660_dir now_dir;

} l9660_fs_status_t;

typedef struct file
{
    int type;
    void *handle; // file or dir handle
} *file_t;

uint32_t l9660_tell(l9660_file *f);
l9660_status l9660_read(l9660_file *f, void *buf, size_t size, size_t *read);
l9660_status l9660_seek(l9660_file *f, int whence, int32_t offset);
l9660_status l9660_openat(l9660_file *child, l9660_dir *parent, const char *name);
l9660_status l9660_readdir(l9660_dir *dir, l9660_dirent **pdirent);
l9660_status l9660_opendirat(l9660_dir *dir, l9660_dir *parent, const char *path);
l9660_status l9660_fs_open_root(l9660_dir *dir, l9660_fs *fs);
l9660_status l9660_openfs(l9660_fs *fs,
                          bool (*read_sector)(l9660_fs *fs, void *buf, uint32_t sector),
                          vfs_node_t device);

bool read_sector(l9660_fs *fs, void *buf, uint32_t sector);
#define l9660_seekdir(dir, pos) (l9660_seek(&(dir)->file, SEEK_SET, (pos)))
#define l9660_telldir(dir) (l9660_tell(&(dir)->file))
#define get_root_dir(vfs) ((l9660_fs_status_t *)(vfs->cache))->root_dir

#define DENT_EXISTS (1 << 0)
#define DENT_ISDIR (1 << 1)
#define DENT_ASSOCIATED (1 << 2)
#define DENT_RECORD (1 << 3)
#define DENT_PROTECTION (1 << 4)
#define DENT_MULTIEXTENT (1 << 5)

#define PVD(vdesc) ((l9660_vdesc_primary *)(vdesc))

#ifdef L9660_BIG_ENDIAN
#define READ16(v) (((v).be[1]) | ((v).be[0] << 8))
#define READ32(v) (((v).be[3]) | ((v).be[2] << 8) | ((v).be[1]) << 16 | ((v).be[0] << 24))
#else
#define READ16(v) (((v).le[0]) | ((v).le[1] << 8))
#define READ32(v) (((v).le[0]) | ((v).le[1] << 8) | ((v).le[2]) << 16 | ((v).le[3] << 24))
#endif

#ifndef L9660_SINGLEBUFFER
#define HAVEBUFFER(f) (true)
#define BUF(f) ((f)->buf)
#else
#define HAVEBUFFER(f) ((f) == last_file)
#define BUF(f) (gbuf)
static l9660_file *last_file;
static char gbuf[2048];
#endif

#define get_now_dir(vfs) ((l9660_fs_status_t *)(vfs->cache))->now_dir

static inline int iso_namelen(char *name, int len)
{
    if (len > 1 && name[len - 2] == ';')
        len -= 2;
    if (len > 0 && name[len - 1] == '.')
        len--;
    return len;
}

static inline uint16_t fsectoff(l9660_file *f)
{
    return f->position % 2048;
}

static inline uint32_t fsector(l9660_file *f)
{
    return f->position / 2048;
}

static inline uint32_t fnextsectpos(l9660_file *f)
{
    return (f->position + 2047) & ~2047;
}

l9660_status l9660_openfs(l9660_fs *fs,
                          bool (*read_sector)(l9660_fs *fs, void *buf, uint32_t sector),
                          vfs_node_t device)
{
    fs->read_sector = read_sector;
    fs->device = device;
#ifndef L9660_SINGLEBUFFER
    l9660_vdesc_primary *pvd = PVD(&fs->pvd);
#else
    last_file = NULL;
    l9660_vdesc_primary *pvd = PVD(gbuf);
#endif
    uint32_t idx = 0x10;
    for (;;)
    {
        // Read next sector
        if (!read_sector(fs, pvd, idx))
            return L9660_EIO;

        // Validate magic
        if (memcmp(pvd->hdr.magic, "CD001", 5) != 0)
            return L9660_EBADFS;

        if (pvd->hdr.type == 1)
            break; // Found PVD
        else if (pvd->hdr.type == 255)
            return L9660_EBADFS;
    }

#ifdef L9660_SINGLEBUFFER
    memcpy(&fs->root_dir_ent, &pvd->root_dir_ent, pvd->root_dir_ent.length);
#endif

    return L9660_OK;
}

l9660_status l9660_fs_open_root(l9660_dir *dir, l9660_fs *fs)
{
    l9660_file *f = &dir->file;
#ifndef L9660_SINGLEBUFFER
    l9660_dirent *dirent = &PVD(&fs->pvd)->root_dir_ent;
#else
    l9660_dirent *dirent = &fs->root_dir_ent;
#endif

    f->fs = fs;
    f->first_sector = READ32(dirent->sector);
    f->length = READ32(dirent->size);
    f->position = 0;

    return L9660_OK;
}

static l9660_status buffer(l9660_file *f)
{
#ifdef L9660_SINGLEBUFFER
    last_file = f;
#endif

    if (!f->fs->read_sector(f->fs, BUF(f), f->first_sector + f->position / 2048))
        return L9660_EIO;
    else
        return L9660_OK;
}

static l9660_status prebuffer(l9660_file *f)
{
    if (!HAVEBUFFER(f) || (f->position % 2048) == 0)
        return buffer(f);
    else
        return L9660_OK;
}

static l9660_status openat_raw(l9660_file *child, l9660_dir *parent, const char *name, bool isdir)
{
    l9660_status rv;
    l9660_dirent *dent = NULL;
    if ((rv = l9660_seekdir(parent, 0)))
        return rv;

    do
    {
        const char *seg = name;
        name = strchrnul(name, '/');
        size_t seglen = name - seg;

        /* ISO9660 stores '.' as '\0' */
        if (seglen == 1 && *seg == '.')
            seg = "\0";

        /* ISO9660 stores ".." as '\1' */
        if (seglen == 2 && seg[0] == '.' && seg[1] == '.')
        {
            seg = "\1";
            seglen = 1;
        }

        for (;;)
        {
            if ((rv = l9660_readdir(parent, &dent)))
                return rv;

            /* EOD */
            if (!dent)
                return L9660_ENOENT;

#ifdef DEBUG
            print_dirent(dent);
#endif

            /* wrong length */
            if (seglen > dent->name_len)
                continue;

            /* check name */
            char *su_field = (char *)&dent->name + dent->name_len;
            size_t su_offset = 33 + dent->name_len;
            size_t su_length = (size_t)(dent->length - su_offset);

            char dent_name[255];
            memset(dent_name, 0, 255);
            bool use_lfn = false;

            int namelen = iso_namelen(dent->name, dent->name_len);

        retry:
            switch (*su_field)
            {
            case 'P':
                su_field += su_field[2];
                goto retry;
            case 'T':
                su_field += su_field[2];
                goto retry;
            case 'N':
                memcpy(dent_name, &su_field[5], namelen);
                dent_name[namelen] = '\0';
                su_field += su_field[2];
                use_lfn = true;
                goto retry;
            case 'S':
                su_field += su_field[2];
                goto retry;
            default:
                break;
            }

            if (!use_lfn)
                strncpy(dent_name, dent->name, iso_namelen(dent->name, dent->name_len));

            if (!streqn(seg, dent_name, iso_namelen(dent->name, dent->name_len)))
                continue;

            /* all tests pass */
            break;
        }

        child->fs = parent->file.fs;
        child->first_sector = READ32(dent->sector) + dent->xattr_length;
        child->length = READ32(dent->size);
        child->position = 0;
        parent->file.position = 0;
        if (*name && (dent->flags & DENT_ISDIR) != 0)
            return L9660_ENOTDIR;

        parent = (l9660_dir *)child;
    } while (*name);

    if (isdir)
    {
        if ((dent->flags & DENT_ISDIR) == 0)
            return L9660_ENOTDIR;
    }
    else
    {
        if ((dent->flags & DENT_ISDIR) != 0)
            return L9660_ENOTFILE;
    }

    return L9660_OK;
}

l9660_status l9660_opendirat(l9660_dir *dir, l9660_dir *parent, const char *path)
{
    return openat_raw(&dir->file, parent, path, true);
}

static inline unsigned aligneven(unsigned v)
{
    return v + (v & 1);
}

l9660_status l9660_readdir(l9660_dir *dir, l9660_dirent **pdirent)
{
    l9660_status rv;
    l9660_file *f = &dir->file;

rebuffer:
    if (f->position >= f->length)
    {
        *pdirent = NULL;
        f->position = 0;
        return L9660_OK;
    }

    if ((rv = prebuffer(f)))
        return rv;
    char *off = BUF(f) + fsectoff(f);
    if (*off == 0)
    {
        // Padded end of sector
        f->position = fnextsectpos(f);
        goto rebuffer;
    }

    l9660_dirent *dirent = (l9660_dirent *)off;
    f->position += aligneven(dirent->length);

    *pdirent = dirent;
    return L9660_OK;
}

l9660_status l9660_openat(l9660_file *child, l9660_dir *parent, const char *name)
{
    return openat_raw(child, parent, name, false);
}

/*! Seek the file to \p offset from \p whence */
l9660_status l9660_seek(l9660_file *f, int whence, int32_t offset)
{
    l9660_status rv;
    uint32_t cursect = fsector(f);

    switch (whence)
    {
    case SEEK_SET:
        f->position = offset;
        break;

    case SEEK_CUR:
        f->position = f->position + offset;
        break;

    case SEEK_END:
        f->position = f->length - offset;
        break;
    }

    if (fsector(f) != cursect && fsectoff(f) != 0)
    {
        if ((rv = buffer(f)))
            return rv;
    }

    return L9660_OK;
}

uint32_t l9660_tell(l9660_file *f)
{
    return f->position;
}

l9660_status l9660_read(l9660_file *f, void *buf, size_t size, size_t *read)
{
    l9660_status rv;

    if ((rv = prebuffer(f)))
        return rv;

    uint16_t rem = 2048 - fsectoff(f);
    if (rem > f->length - f->position)
        rem = f->length - f->position;
    if (rem < size)
        size = rem;

    memcpy(buf, BUF(f) + fsectoff(f), size);

    *read = size;
    f->position += size;

    return L9660_OK;
}

bool read_sector(l9660_fs *fs, void *buf, uint32_t sector)
{
    return vfs_read(fs->device, buf, sector * 2048, 2048) == -1 ? false : true;
}

int iso9660_id = -1;
int iso9660_mkdir(void *parent, const char *name, vfs_node_t node)
{
    return -1;
}

int iso9660_mkfile(void *parent, const char *name, vfs_node_t node)
{
    return -1;
}

size_t iso9660_readfile(file_t file, void *addr, size_t offset, size_t size)
{
    if (file->type & file_dir)
        return -1;
    l9660_file *fp = file->handle;
    l9660_status st;
    st = l9660_seek(fp, SEEK_SET, offset);
    if (st != L9660_OK)
        return -1;
    size_t read = 0;
    size_t total_read = 0;
    while (total_read < size)
    {
        st = l9660_read(fp, (char *)addr + total_read, size - total_read, &read);
        if (st != L9660_OK)
            return -1;
        total_read += read;
        if (read == 0)
            break;
    }
    if (st != L9660_OK)
        return -1;
    return total_read;
}

size_t iso9660_writefile(file_t file, const void *addr, size_t offset, size_t size)
{
    // normally, iso9660 is read-only
    // so we don't need to implement this function
    return -1;
}

static void iso9660_process_dir(l9660_dir *dir, vfs_node_t parent)
{
    for (;;)
    {
        l9660_dirent *dent;
        l9660_readdir(dir, &dent);

        if (dent == 0)
            break;
        int j = 0;
        if (memcmp("\0", dent->name, dent->name_len) == 0)
        {
            continue;
        }
        else if (memcmp("\1", dent->name, dent->name_len) == 0)
        {
            continue;
        }
        else
        {
            char *su_field = (char *)&dent->name + dent->name_len;
            size_t su_offset = 33 + dent->name_len;
            size_t su_length = (size_t)(dent->length - su_offset);

            char name[255];
            memset(name, 0, 255);
            bool use_lfn = false;

            int namelen = iso_namelen(dent->name, dent->name_len);

        retry:
            switch (*su_field)
            {
            case 'P':
                su_field += su_field[2];
                goto retry;
            case 'T':
                su_field += su_field[2];
                goto retry;
            case 'N':
                memcpy(name, &su_field[5], namelen);
                name[namelen] = '\0';
                su_field += su_field[2];
                use_lfn = true;
                goto retry;
            case 'S':
                su_field += su_field[2];
                goto retry;
            default:
                break;
            }

            if (use_lfn)
            {
                vfs_child_append(parent, name, NULL);
                continue;
            }

            for (j = 0; j < namelen; j++)
            {
                name[j] = dent->name[j];
            }
            vfs_child_append(parent, name, NULL);
        }
    }
}
void iso9660_open(void *parent, const char *name, vfs_node_t node)
{
    file_t p = parent;
    l9660_dir *p_dir = (l9660_dir *)p->handle;
    l9660_dir *c_dir = (l9660_dir *)malloc(sizeof(l9660_dir));
    l9660_file *c_file = (l9660_file *)malloc(sizeof(l9660_file));
    l9660_status status;
    file_t new = (file_t)malloc(sizeof(struct file));
    status = l9660_openat(c_file, p_dir, name);

    if (status != L9660_OK)
    {
        status = l9660_opendirat(c_dir, p_dir, name);
        if (status != L9660_OK)
        {
            free(c_dir);
            free(c_file);
            return;
        }
        node->fsid = iso9660_id;
        iso9660_process_dir(c_dir, node);
        free(c_file);
        new->type = file_dir;
        new->handle = (void *)c_dir;
        node->type = file_dir;
        node->handle = (void *)new;
        return;
    }
    node->fsid = iso9660_id;
    node->type = file_none;
    new->type = file_none;
    new->handle = (void *)c_file;
    node->handle = (void *)new;
    node->size = c_file->length;
    free(c_dir);
    return;
}

bool iso9660_close(file_t handle)
{
    free(handle->handle);
    free(handle);

    return true;
}

int iso9660_mount(const char *src, vfs_node_t node)
{
    vfs_node_t device = vfs_open(src);
    if (device == NULL || (device->type & file_dir))
    {
        return -1;
    }
    l9660_fs *fs = (l9660_fs *)malloc(sizeof(l9660_fs));
    l9660_status status = l9660_openfs(fs, read_sector, device);
    if (status != L9660_OK)
        return -1;
    l9660_dir *root_dir = (l9660_dir *)malloc(sizeof(l9660_dir));
    l9660_fs_open_root(root_dir, fs);
    file_t handle = (file_t)malloc(sizeof(struct file));
    handle->type = file_dir;
    handle->handle = (void *)root_dir;
    node->fsid = iso9660_id;
    iso9660_process_dir(root_dir, node);
    node->handle = handle;
    return 0;
}

void iso9660_unmount(void *root)
{
    file_t f = root;
    free(f->handle);
    free(f);
}

int iso9660_stat(void *handle, vfs_node_t node)
{
    file_t f = handle;
    if (f->type & file_dir)
    {
        node->type = file_dir;
        return 0;
    }
    else
    {
        node->type = file_none;
        l9660_file *file = (l9660_file *)f->handle;
        node->size = file->length;
    }
    return 0;
}

int iso9660_delete(void *current)
{
    return -1;
}

int iso9660_rename(void *current, const char *new)
{
    return -1;
}

int iso9660_ioctl(void *file, ssize_t cmd, ssize_t arg)
{
    return -ENOSYS;
}

int iso9660_poll(void *file, size_t events)
{
    return -EOPNOTSUPP;
}

void *iso9660_map(void *file, void *addr, size_t offset, size_t size, size_t prot, size_t flags)
{
    return general_map((vfs_read_t)iso9660_readfile, file, (uint64_t)addr, size, prot, flags, offset);
}

static int dummy()
{
    return 0;
}

static struct vfs_callback callbacks = {
    .mount = iso9660_mount,
    .unmount = iso9660_unmount,
    .open = iso9660_open,
    .close = (vfs_close_t)iso9660_close,
    .read = (vfs_read_t)iso9660_readfile,
    .write = (vfs_write_t)iso9660_writefile,
    .readlink = (vfs_read_t)dummy,
    .mkdir = iso9660_mkdir,
    .mkfile = iso9660_mkfile,
    .link = (vfs_mk_t)dummy,
    .symlink = (vfs_mk_t)dummy,
    .delete = (vfs_del_t)iso9660_delete,
    .rename = (vfs_rename_t)iso9660_rename,
    .map = (vfs_mapfile_t)iso9660_map,
    .stat = iso9660_stat,
    .ioctl = iso9660_ioctl,
    .poll = iso9660_poll,
    .resize = (vfs_resize_t)dummy,
};

void iso9660_init()
{
    iso9660_id = vfs_regist("iso9660", &callbacks);
}

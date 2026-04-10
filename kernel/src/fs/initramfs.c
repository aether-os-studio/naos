#include <fs/initramfs.h>
#include <fs/fs_syscall.h>
#include <boot/boot.h>
#include <drivers/logger.h>
#include <mm/mm.h>

static char *initramfs_make_abspath(const char *name) {
    size_t len;
    char *path;

    if (!name)
        return NULL;
    if (name[0] == '/')
        return strdup(name);

    len = strlen(name);
    path = malloc(len + 2);
    if (!path)
        return NULL;
    path[0] = '/';
    memcpy(path + 1, name, len + 1);
    return path;
}

static int initramfs_set_mode(const char *path, uint32_t mode) {
    struct vfs_path lookup = {0};
    int ret = vfs_filename_lookup(AT_FDCWD, path, LOOKUP_FOLLOW, &lookup);
    if (ret < 0)
        return ret;

    if (lookup.dentry && lookup.dentry->d_inode) {
        umode_t type = lookup.dentry->d_inode->i_mode & S_IFMT;
        lookup.dentry->d_inode->i_mode = type | (mode & 07777);
    }
    vfs_path_put(&lookup);
    return 0;
}

uint32_t parse_hex(const char *c, int n) {
    uint32_t v = 0;
    for (int i = 0; i < n; i++) {
        uint32_t d;
        if (*c >= 'a' && *c <= 'f') {
            d = *c++ - 'a' + 10;
        } else if (*c >= 'A' && *c <= 'F') {
            d = *c++ - 'A' + 10;
        } else if (*c >= '0' && *c <= '9') {
            d = *c++ - '0';
        } else {
            ASSERT(!"Unexpected character in CPIO header");
        }
        v = (v << 4) | d;
    }
    return v;
}

void initramfs_init() {
    struct vfs_mount *root_mnt = NULL;
    boot_module_t *boot_modules[MAX_MODULES_NUM];
    size_t modules_count = 0;
    boot_get_modules(boot_modules, &modules_count);

    boot_module_t *initramfs_module = NULL;

    for (uint64_t i = 0; i < modules_count; i++) {
        if (strstr(boot_modules[i]->path, ".img")) {
            initramfs_module = boot_modules[i];
            break;
        }
    }

    if (!initramfs_module)
        return;

    int ret = vfs_kern_mount("tmpfs", 0, NULL, NULL, &root_mnt);
    if (ret < 0) {
        printk("Failed mount tmpfs as init root\n");
        return;
    }
    if (!vfs_root_path.mnt) {
        vfs_root_path.mnt = vfs_mntget(root_mnt);
        vfs_root_path.dentry = vfs_dget(root_mnt->mnt_root);
        vfs_init_mnt_ns.root = vfs_mntget(root_mnt);
        (void)vfs_mount_set_propagation(root_mnt, MS_SHARED, true);
    }

    struct header {
        char magic[6];
        char inode[8];
        char mode[8];
        char uid[8];
        char gid[8];
        char numLinks[8];
        char mtime[8];
        char fileSize[8];
        char devMajor[8];
        char devMinor[8];
        char rdevMajor[8];
        char rdevMinor[8];
        char nameSize[8];
        char check[8];
    };

    const uint32_t type_mask = 0170000;
    const uint32_t regular_type = 0100000;
    const uint32_t directory_type = 0040000;

    void *p = initramfs_module->data;
    uint64_t limit = initramfs_module->size;
    while (true) {
        struct header h;
        memcpy(&h, p, sizeof(struct header));

        uint32_t magic = parse_hex(h.magic, 6);
        ASSERT(magic == 0x070701 || magic == 0x070702);

        uint32_t mode = parse_hex(h.mode, 8);
        uint32_t name_size = parse_hex(h.nameSize, 8);
        uint32_t file_size = parse_hex(h.fileSize, 8);
        void *data = p + ((sizeof(struct header) + name_size + 3) & ~3);

        char name[name_size];
        memset(name, 0, name_size);
        memcpy(name, p + sizeof(struct header), name_size - 1);
        if (!strcmp(name, "TRAILER!!!"))
            break;
        if (!strcmp(name, "."))
            goto next;
        char *path = initramfs_make_abspath(name);
        if (!path)
            goto next;

        struct vfs_path existing = {0};
        if (vfs_filename_lookup(AT_FDCWD, path, LOOKUP_FOLLOW, &existing) ==
            0) {
            vfs_path_put(&existing);
            free(path);
            goto next;
        }

        if ((mode & type_mask) == directory_type) {
            vfs_mkdirat(AT_FDCWD, path, mode & 0777);
            initramfs_set_mode(path, mode);
        } else if ((mode & 0120000) == 0120000) {
            char target_name[file_size + 1];
            memcpy(target_name, data, file_size);
            target_name[file_size] = '\0';
            vfs_symlinkat(target_name, AT_FDCWD, path);
            initramfs_set_mode(path, mode);
        } else {
            struct vfs_file *file = NULL;
            struct vfs_open_how how = {
                .flags = O_CREAT | O_WRONLY | O_TRUNC,
                .mode = mode & 0777,
            };

            ret = vfs_openat(AT_FDCWD, path, &how, &file);
            if (ret == 0 && file) {
                loff_t pos = 0;
                vfs_write_file(file, data, file_size, &pos);
                vfs_close_file(file);
            }
            initramfs_set_mode(path, mode);
        }
        free(path);

    next:
        p = data + ((file_size + 3) & ~3);
    }

    if (root_mnt)
        vfs_mntput(root_mnt);
}

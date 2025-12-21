#include <fs/initramfs.h>
#include <boot/boot.h>

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

    int ret = vfs_mount(0, rootdir, "tmpfs");
    if (ret < 0) {
        printk("Failed mount tmpfs as init root\n");
        return;
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

        if ((mode & type_mask) == directory_type) {
            vfs_mkdir(name);
            vfs_chmod(name, mode & 0777);
        } else if ((mode & 0120000) == 0120000) {
            char target_name[file_size + 1];
            memcpy(target_name, data, file_size);
            target_name[file_size] = '\0';
            vfs_symlink(name, target_name);
            vfs_chmod(name, mode & 0777);
        } else {
            vfs_mkfile(name);
            vfs_chmod(name, mode & 0777);
            vfs_node_t node = vfs_open(name, 0);
            vfs_write(node, data, 0, file_size);
        }

    next:
        p = data + ((file_size + 3) & ~3);
    }
}

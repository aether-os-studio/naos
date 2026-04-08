#include "fs/vfs/vfs_internal.h"
#include "task/task.h"

struct vfs_mount_namespace vfs_init_mnt_ns = {0};
struct vfs_path vfs_root_path = {0};

static struct llist_header vfs_filesystems;
static mutex_t vfs_filesystems_lock;

static uint32_t vfs_qstr_hash_bytes(const char *name, uint32_t len) {
    uint32_t hash = 2166136261u;
    uint32_t i = 0;

    while (name && i < len) {
        hash ^= (uint8_t)name[i++];
        hash *= 16777619u;
    }

    return hash ? hash : 1;
}

void vfs_qstr_make(struct vfs_qstr *qstr, const char *name) {
    if (!qstr)
        return;
    memset(qstr, 0, sizeof(*qstr));
    if (!name)
        return;
    qstr->name = name;
    qstr->len = (uint32_t)strlen(name);
    qstr->hash = vfs_qstr_hash_bytes(name, qstr->len);
}

void vfs_qstr_dup(struct vfs_qstr *qstr, const char *name) {
    if (!qstr)
        return;
    memset(qstr, 0, sizeof(*qstr));
    if (!name)
        return;
    qstr->name = strdup(name);
    if (!qstr->name)
        return;
    qstr->len = (uint32_t)strlen(qstr->name);
    qstr->hash = vfs_qstr_hash_bytes(qstr->name, qstr->len);
}

void vfs_qstr_destroy(struct vfs_qstr *qstr) {
    if (!qstr)
        return;
    if (qstr->name)
        free((void *)qstr->name);
    memset(qstr, 0, sizeof(*qstr));
}

int vfs_init(void) {
    llist_init_head(&vfs_filesystems);
    mutex_init(&vfs_filesystems_lock);
    mutex_init(&vfs_init_mnt_ns.lock);

    vfs_dcache_init();
    vfs_mount_subsys_init();
    vfs_ops_init();

    memset(&vfs_root_path, 0, sizeof(vfs_root_path));
    return 0;
}

int vfs_register_filesystem(struct vfs_file_system_type *fs) {
    struct vfs_file_system_type *pos, *tmp;

    if (!fs || !fs->name || !fs->get_tree)
        return -EINVAL;
    if (!fs->fs_list.next && !fs->fs_list.prev)
        llist_init_head(&fs->fs_list);

    mutex_lock(&vfs_filesystems_lock);
    llist_for_each(pos, tmp, &vfs_filesystems, fs_list) {
        if (streq(pos->name, fs->name)) {
            mutex_unlock(&vfs_filesystems_lock);
            return -EEXIST;
        }
    }
    if (llist_empty(&fs->fs_list))
        llist_append(&vfs_filesystems, &fs->fs_list);
    mutex_unlock(&vfs_filesystems_lock);
    return 0;
}

void vfs_unregister_filesystem(struct vfs_file_system_type *fs) {
    if (!fs)
        return;
    if (!fs->fs_list.next || !fs->fs_list.prev)
        return;
    mutex_lock(&vfs_filesystems_lock);
    if (!llist_empty(&fs->fs_list))
        llist_delete(&fs->fs_list);
    mutex_unlock(&vfs_filesystems_lock);
}

struct vfs_file_system_type *vfs_get_fs_type(const char *name) {
    struct vfs_file_system_type *pos, *tmp;

    if (!name)
        return NULL;
    mutex_lock(&vfs_filesystems_lock);
    llist_for_each(pos, tmp, &vfs_filesystems, fs_list) {
        if (streq(pos->name, name)) {
            mutex_unlock(&vfs_filesystems_lock);
            return pos;
        }
    }
    mutex_unlock(&vfs_filesystems_lock);
    return NULL;
}

#pragma once

#include <drivers/bus/usb.h>
#include <fs/vfs/vfs.h>

typedef struct sysfs_node {
    vfs_node_t *node;
    // for file type
    char *content;
    int size;
    int capability;
} sysfs_node_t;

void sysfs_init();
void sysfs_init_umount();

int alloc_seq_num();

vfs_node_t *sysfs_regist_dev(char t, int major, int minor,
                             const char *real_device_path, const char *dev_name,
                             const char *other_uevent_content);
vfs_node_t *sysfs_ensure_symlink_at(vfs_node_t *start, const char *path,
                                    const char *target);
vfs_node_t *sysfs_ensure_symlink(const char *path, const char *target);
vfs_node_t *sysfs_ensure_file_at(vfs_node_t *start, const char *path);
vfs_node_t *sysfs_ensure_file(const char *path);
vfs_node_t *sysfs_ensure_dir_at(vfs_node_t *start, const char *path);
vfs_node_t *sysfs_ensure_dir(const char *path);
vfs_node_t *sysfs_child_append(vfs_node_t *parent, const char *name,
                               bool is_dir);
vfs_node_t *sysfs_child_append_symlink(vfs_node_t *parent, const char *name,
                                       const char *target_path);

void sysfs_register_device(bus_device_t *device);
void sysfs_unregister_device(bus_device_t *device);

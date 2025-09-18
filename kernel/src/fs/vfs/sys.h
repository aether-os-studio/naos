#pragma once

#include <fs/vfs/vfs.h>

int alloc_seq_num();

vfs_node_t sysfs_regist_dev(char t, int major, int minor,
                            const char *real_device_path, const char *dev_name,
                            const char *other_uevent_content);
vfs_node_t sysfs_child_append(vfs_node_t parent, const char *name, bool is_dir);
vfs_node_t sysfs_child_append_symlink(vfs_node_t parent, const char *name,
                                      const char *target_path);

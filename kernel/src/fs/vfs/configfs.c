#include <fs/vfs/configfs.h>

static int configfs_fsid = 0;

static vfs_operations_t callbacks = {
    .free_handle = vfs_generic_free_handle,
};

fs_t configfs = {
    .name = "configfs",
    .magic = 0x62656570,
    .ops = &callbacks,
    .flags = FS_FLAGS_VIRTUAL,
};

void configfs_init() { configfs_fsid = vfs_regist(&configfs); }

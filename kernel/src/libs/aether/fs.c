#include <mod/dlinker.h>
#include <libs/aether/fs.h>

EXPORT_SYMBOL(vfs_regist);

EXPORT_SYMBOL(vfs_update);
EXPORT_SYMBOL(vfs_read);
EXPORT_SYMBOL(vfs_write);
EXPORT_SYMBOL(vfs_poll);

EXPORT_SYMBOL(vfs_node_alloc);
EXPORT_SYMBOL(vfs_child_append);
EXPORT_SYMBOL(vfs_child_find);

EXPORT_SYMBOL(vfs_open);
EXPORT_SYMBOL(vfs_open_at);
EXPORT_SYMBOL(vfs_close);

EXPORT_SYMBOL(vfs_get_fullpath);

EXPORT_SYMBOL(calculate_relative_path);

EXPORT_SYMBOL(poll_to_epoll_comp);
EXPORT_SYMBOL(epoll_to_poll_comp);

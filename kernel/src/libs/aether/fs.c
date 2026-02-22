#include <mod/dlinker.h>
#include <libs/aether/fs.h>

EXPORT_SYMBOL(vfs_regist);

EXPORT_SYMBOL(vfs_update);
EXPORT_SYMBOL(vfs_free);
EXPORT_SYMBOL(vfs_read);
EXPORT_SYMBOL(vfs_write);
EXPORT_SYMBOL(vfs_poll);

EXPORT_SYMBOL(vfs_on_new_event);
EXPORT_SYMBOL(vfs_mark_dirty);
EXPORT_SYMBOL(vfs_poll_wait_init);
EXPORT_SYMBOL(vfs_poll_wait_arm);
EXPORT_SYMBOL(vfs_poll_wait_disarm);
EXPORT_SYMBOL(vfs_poll_wait_sleep);
EXPORT_SYMBOL(vfs_poll_notify);

EXPORT_SYMBOL(vfs_node_alloc);
EXPORT_SYMBOL(vfs_child_append);
EXPORT_SYMBOL(vfs_child_find);
EXPORT_SYMBOL(vfs_merge_nodes_to);

EXPORT_SYMBOL(vfs_open);
EXPORT_SYMBOL(vfs_open_at);
EXPORT_SYMBOL(vfs_close);

EXPORT_SYMBOL(vfs_get_fullpath);

EXPORT_SYMBOL(calculate_relative_path);

EXPORT_SYMBOL(poll_to_epoll_comp);
EXPORT_SYMBOL(epoll_to_poll_comp);

#include <fs/vfs/cgroup/cgroupfs.h>
#include <fs/fs_syscall.h>
#include <fs/vfs/vfs.h>
#include <libs/string_builder.h>
#include <task/task.h>

typedef enum cgroupfs_controller_mask {
    CGROUPFS_CTRL_CPU = 1U << 0,
    CGROUPFS_CTRL_IO = 1U << 1,
    CGROUPFS_CTRL_MEMORY = 1U << 2,
    CGROUPFS_CTRL_PIDS = 1U << 3,
} cgroupfs_controller_mask_t;

#define CGROUPFS_ALL_CONTROLLERS                                               \
    (CGROUPFS_CTRL_CPU | CGROUPFS_CTRL_IO | CGROUPFS_CTRL_MEMORY |             \
     CGROUPFS_CTRL_PIDS)

typedef enum cgroupfs_inode_kind {
    CGROUPFS_INODE_DIR = 0,
    CGROUPFS_INODE_CGROUP_PROCS,
    CGROUPFS_INODE_CGROUP_THREADS,
    CGROUPFS_INODE_CGROUP_CONTROLLERS,
    CGROUPFS_INODE_CGROUP_EVENTS,
    CGROUPFS_INODE_CGROUP_TYPE,
    CGROUPFS_INODE_CGROUP_FREEZE,
    CGROUPFS_INODE_CGROUP_SUBTREE_CONTROL,
    CGROUPFS_INODE_CGROUP_MAX_DEPTH,
    CGROUPFS_INODE_CGROUP_MAX_DESCENDANTS,
    CGROUPFS_INODE_CGROUP_STAT,
} cgroupfs_inode_kind_t;

typedef struct cgroupfs_cgroup {
    struct llist_header sibling;
    struct llist_header children;
    struct cgroupfs_cgroup *parent;
    char *name;
    uint32_t subtree_control;
    bool frozen;
    volatile int ref_count;
} cgroupfs_cgroup_t;

typedef struct cgroupfs_assignment {
    struct llist_header node;
    uint64_t pid;
    cgroupfs_cgroup_t *cgroup;
} cgroupfs_assignment_t;

typedef struct cgroupfs_dirent {
    struct llist_header node;
    char *name;
    struct vfs_inode *inode;
} cgroupfs_dirent_t;

typedef struct cgroupfs_inode_info {
    struct vfs_inode vfs_inode;
    struct llist_header children;
    cgroupfs_cgroup_t *cgroup;
    cgroupfs_inode_kind_t kind;
} cgroupfs_inode_info_t;

static struct vfs_file_system_type cgroupfs_fs_type;
static const struct vfs_super_operations cgroupfs_super_ops;
static const struct vfs_inode_operations cgroupfs_inode_ops;
static const struct vfs_file_operations cgroupfs_dir_file_ops;
static const struct vfs_file_operations cgroupfs_file_ops;

static mutex_t cgroupfs_lock;
static cgroupfs_cgroup_t *cgroupfs_root;
DEFINE_LLIST(cgroupfs_assignments);

static inline cgroupfs_inode_info_t *cgroupfs_i(struct vfs_inode *inode) {
    return inode ? container_of(inode, cgroupfs_inode_info_t, vfs_inode) : NULL;
}

static cgroupfs_cgroup_t *cgroupfs_cgroup_get(cgroupfs_cgroup_t *cgroup) {
    if (!cgroup)
        return NULL;
    __atomic_add_fetch(&cgroup->ref_count, 1, __ATOMIC_ACQ_REL);
    return cgroup;
}

static void cgroupfs_cgroup_put(cgroupfs_cgroup_t *cgroup) {
    if (!cgroup)
        return;
    if (__atomic_sub_fetch(&cgroup->ref_count, 1, __ATOMIC_ACQ_REL) != 0)
        return;
    free(cgroup->name);
    free(cgroup);
}

static struct vfs_inode *cgroupfs_alloc_inode(struct vfs_super_block *sb) {
    cgroupfs_inode_info_t *info = calloc(1, sizeof(*info));
    (void)sb;
    return info ? &info->vfs_inode : NULL;
}

static void cgroupfs_destroy_inode(struct vfs_inode *inode) {
    free(cgroupfs_i(inode));
}

static void cgroupfs_evict_inode(struct vfs_inode *inode) {
    cgroupfs_inode_info_t *info = cgroupfs_i(inode);
    cgroupfs_dirent_t *de, *tmp;

    if (!info)
        return;

    if (info->kind == CGROUPFS_INODE_DIR) {
        llist_for_each(de, tmp, &info->children, node) {
            llist_delete(&de->node);
            if (de->inode)
                vfs_iput(de->inode);
            free(de->name);
            free(de);
        }
    }

    if (info->cgroup) {
        cgroupfs_cgroup_put(info->cgroup);
        info->cgroup = NULL;
    }
}

static cgroupfs_cgroup_t *cgroupfs_create_cgroup(cgroupfs_cgroup_t *parent,
                                                 const char *name) {
    cgroupfs_cgroup_t *cgroup = calloc(1, sizeof(*cgroup));

    if (!cgroup)
        return NULL;

    cgroup->parent = parent;
    cgroup->name = name ? strdup(name) : strdup("");
    if (!cgroup->name) {
        free(cgroup);
        return NULL;
    }

    llist_init_head(&cgroup->sibling);
    llist_init_head(&cgroup->children);
    cgroup->ref_count = 1;
    return cgroup;
}

static int cgroupfs_statfs(struct vfs_path *path, void *buf) {
    struct statfs *st = (struct statfs *)buf;

    (void)path;
    if (!st)
        return -EINVAL;

    memset(st, 0, sizeof(*st));
    st->f_type = 0x63677270ULL;
    st->f_bsize = PAGE_SIZE;
    st->f_frsize = PAGE_SIZE;
    st->f_namelen = 255;
    return 0;
}

static struct vfs_inode *cgroupfs_new_inode(struct vfs_super_block *sb,
                                            cgroupfs_cgroup_t *cgroup,
                                            cgroupfs_inode_kind_t kind,
                                            umode_t mode) {
    struct vfs_inode *inode = vfs_alloc_inode(sb);
    cgroupfs_inode_info_t *info = cgroupfs_i(inode);

    if (!inode)
        return NULL;

    llist_init_head(&info->children);
    info->kind = kind;
    info->cgroup = cgroupfs_cgroup_get(cgroup);

    inode->i_op = &cgroupfs_inode_ops;
    inode->i_fop = kind == CGROUPFS_INODE_DIR ? &cgroupfs_dir_file_ops
                                              : &cgroupfs_file_ops;
    inode->i_mode = mode;
    inode->i_uid = 0;
    inode->i_gid = 0;
    inode->i_nlink = kind == CGROUPFS_INODE_DIR ? 2 : 1;
    inode->type = kind == CGROUPFS_INODE_DIR ? file_dir : file_none;
    inode->i_ino = (ino64_t)(uintptr_t)inode;
    inode->inode = inode->i_ino;
    inode->i_blkbits = 12;
    return inode;
}

static cgroupfs_dirent_t *cgroupfs_find_dirent(struct vfs_inode *dir,
                                               const char *name) {
    cgroupfs_dirent_t *de, *tmp;

    llist_for_each(de, tmp, &cgroupfs_i(dir)->children, node) {
        if (de->name && streq(de->name, name))
            return de;
    }
    return NULL;
}

static int cgroupfs_add_dirent(struct vfs_inode *dir, const char *name,
                               struct vfs_inode *inode) {
    cgroupfs_dirent_t *de = calloc(1, sizeof(*de));

    if (!de)
        return -ENOMEM;

    de->name = strdup(name);
    if (!de->name) {
        free(de);
        return -ENOMEM;
    }

    de->inode = vfs_igrab(inode);
    llist_init_head(&de->node);
    llist_append(&cgroupfs_i(dir)->children, &de->node);
    return 0;
}

static cgroupfs_dirent_t *cgroupfs_detach_dirent(struct vfs_inode *dir,
                                                 const char *name) {
    cgroupfs_dirent_t *de = cgroupfs_find_dirent(dir, name);

    if (!de)
        return NULL;

    llist_delete(&de->node);
    return de;
}

static uint32_t cgroupfs_available_controllers(cgroupfs_cgroup_t *cgroup) {
    if (!cgroup || !cgroup->parent)
        return CGROUPFS_ALL_CONTROLLERS;
    return cgroup->parent->subtree_control;
}

static void cgroupfs_append_controllers(string_builder_t *builder,
                                        uint32_t mask) {
    bool first = true;

    if (mask & CGROUPFS_CTRL_CPU) {
        string_builder_append(builder, "%scpu", first ? "" : " ");
        first = false;
    }
    if (mask & CGROUPFS_CTRL_IO) {
        string_builder_append(builder, "%sio", first ? "" : " ");
        first = false;
    }
    if (mask & CGROUPFS_CTRL_MEMORY) {
        string_builder_append(builder, "%smemory", first ? "" : " ");
        first = false;
    }
    if (mask & CGROUPFS_CTRL_PIDS) {
        string_builder_append(builder, "%spids", first ? "" : " ");
    }
}

static int cgroupfs_parse_controller(const char *name, uint32_t *mask) {
    if (!name || !mask)
        return -EINVAL;
    if (!strcmp(name, "cpu"))
        *mask = CGROUPFS_CTRL_CPU;
    else if (!strcmp(name, "io"))
        *mask = CGROUPFS_CTRL_IO;
    else if (!strcmp(name, "memory"))
        *mask = CGROUPFS_CTRL_MEMORY;
    else if (!strcmp(name, "pids"))
        *mask = CGROUPFS_CTRL_PIDS;
    else
        return -EINVAL;
    return 0;
}

static cgroupfs_assignment_t *cgroupfs_find_assignment_locked(uint64_t pid) {
    cgroupfs_assignment_t *entry, *tmp;

    llist_for_each(entry, tmp, &cgroupfs_assignments, node) {
        if (entry->pid == pid)
            return entry;
    }
    return NULL;
}

static cgroupfs_cgroup_t *cgroupfs_task_cgroup_locked(uint64_t pid) {
    cgroupfs_assignment_t *entry = cgroupfs_find_assignment_locked(pid);
    return entry ? entry->cgroup : cgroupfs_root;
}

static bool cgroupfs_is_descendant_of(cgroupfs_cgroup_t *cgroup,
                                      cgroupfs_cgroup_t *ancestor) {
    while (cgroup) {
        if (cgroup == ancestor)
            return true;
        cgroup = cgroup->parent;
    }
    return false;
}

static int cgroupfs_set_task_cgroup_locked(uint64_t pid,
                                           cgroupfs_cgroup_t *cgroup) {
    cgroupfs_assignment_t *entry = cgroupfs_find_assignment_locked(pid);

    if (!cgroup || cgroup == cgroupfs_root) {
        if (!entry)
            return 0;
        llist_delete(&entry->node);
        free(entry);
        return 0;
    }

    if (entry) {
        entry->cgroup = cgroup;
        return 0;
    }

    entry = calloc(1, sizeof(*entry));
    if (!entry)
        return -ENOMEM;

    entry->pid = pid;
    entry->cgroup = cgroup;
    llist_init_head(&entry->node);
    llist_append(&cgroupfs_assignments, &entry->node);
    return 0;
}

static int cgroupfs_target_cgroup_from_fd(int fd,
                                          cgroupfs_cgroup_t **ret_cgroup) {
    struct vfs_file *file = NULL;
    struct vfs_inode *inode = NULL;
    cgroupfs_inode_info_t *info = NULL;
    cgroupfs_cgroup_t *cgroup = NULL;

    if (!ret_cgroup)
        return -EINVAL;
    *ret_cgroup = NULL;

    if (!current_task || fd < 0 || fd >= MAX_FD_NUM)
        return -EBADF;

    file = task_get_file(current_task, fd);
    if (!file)
        return -EBADF;

    inode = file->f_inode;
    if (!inode || !inode->i_sb || inode->i_sb->s_type != &cgroupfs_fs_type) {
        vfs_file_put(file);
        return -EBADF;
    }

    info = cgroupfs_i(inode);
    if (!info || info->kind != CGROUPFS_INODE_DIR || !info->cgroup) {
        vfs_file_put(file);
        return -EINVAL;
    }

    cgroup = cgroupfs_cgroup_get(info->cgroup);
    vfs_file_put(file);
    if (!cgroup)
        return -EINVAL;

    *ret_cgroup = cgroup;
    return 0;
}

int cgroupfs_set_task_cgroup_by_fd(task_t *task, int fd) {
    cgroupfs_cgroup_t *cgroup = NULL;
    int ret;

    if (!task)
        return -ESRCH;

    ret = cgroupfs_target_cgroup_from_fd(fd, &cgroup);
    if (ret < 0)
        return ret;

    mutex_lock(&cgroupfs_lock);
    ret = cgroupfs_set_task_cgroup_locked(task->pid, cgroup);
    mutex_unlock(&cgroupfs_lock);

    cgroupfs_cgroup_put(cgroup);
    return ret;
}

void cgroupfs_on_new_task(task_t *task) {
    cgroupfs_cgroup_t *parent_cgroup;

    if (!task || !task_has_parent(task))
        return;

    mutex_lock(&cgroupfs_lock);

    if (cgroupfs_find_assignment_locked(task->pid)) {
        mutex_unlock(&cgroupfs_lock);
        return;
    }

    parent_cgroup = cgroupfs_task_cgroup_locked(task->parent->pid);
    if (parent_cgroup && parent_cgroup != cgroupfs_root)
        (void)cgroupfs_set_task_cgroup_locked(task->pid, parent_cgroup);

    mutex_unlock(&cgroupfs_lock);
}

void cgroupfs_on_exit_task(task_t *task) {
    if (!task)
        return;

    mutex_lock(&cgroupfs_lock);
    (void)cgroupfs_set_task_cgroup_locked(task->pid, cgroupfs_root);
    mutex_unlock(&cgroupfs_lock);
}

static size_t cgroupfs_collect_members(cgroupfs_cgroup_t *cgroup, bool threads,
                                       uint64_t *ids, size_t capacity) {
    size_t count = 0;

    mutex_lock(&cgroupfs_lock);
    spin_lock(&task_queue_lock);

    if (task_pid_map.buckets) {
        for (size_t i = 0; i < task_pid_map.bucket_count; ++i) {
            hashmap_entry_t *entry = &task_pid_map.buckets[i];
            task_t *task;
            uint64_t id;
            bool duplicate = false;

            if (!hashmap_entry_is_occupied(entry))
                continue;

            task = (task_t *)entry->value;
            if (!task || task->state == TASK_DIED)
                continue;
            if (cgroupfs_task_cgroup_locked(task->pid) != cgroup)
                continue;

            id = threads ? task->pid : task_effective_tgid(task);
            for (size_t j = 0; j < count; ++j) {
                if (ids[j] == id) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate && count < capacity)
                ids[count++] = id;
        }
    }

    spin_unlock(&task_queue_lock);
    mutex_unlock(&cgroupfs_lock);
    return count;
}

static bool cgroupfs_cgroup_populated(cgroupfs_cgroup_t *cgroup) {
    bool populated = false;

    mutex_lock(&cgroupfs_lock);
    spin_lock(&task_queue_lock);

    if (task_pid_map.buckets) {
        for (size_t i = 0; i < task_pid_map.bucket_count; ++i) {
            hashmap_entry_t *entry = &task_pid_map.buckets[i];
            task_t *task;
            cgroupfs_cgroup_t *task_cgroup;

            if (!hashmap_entry_is_occupied(entry))
                continue;

            task = (task_t *)entry->value;
            if (!task || task->state == TASK_DIED)
                continue;

            task_cgroup = cgroupfs_task_cgroup_locked(task->pid);
            if (cgroupfs_is_descendant_of(task_cgroup, cgroup)) {
                populated = true;
                break;
            }
        }
    }

    spin_unlock(&task_queue_lock);
    mutex_unlock(&cgroupfs_lock);
    return populated;
}

static bool cgroupfs_cgroup_has_live_members(cgroupfs_cgroup_t *cgroup) {
    bool has_members = false;

    mutex_lock(&cgroupfs_lock);
    spin_lock(&task_queue_lock);

    if (task_pid_map.buckets) {
        for (size_t i = 0; i < task_pid_map.bucket_count; ++i) {
            hashmap_entry_t *entry = &task_pid_map.buckets[i];
            task_t *task;

            if (!hashmap_entry_is_occupied(entry))
                continue;
            task = (task_t *)entry->value;
            if (!task || task->state == TASK_DIED)
                continue;
            if (cgroupfs_task_cgroup_locked(task->pid) == cgroup) {
                has_members = true;
                break;
            }
        }
    }

    spin_unlock(&task_queue_lock);
    mutex_unlock(&cgroupfs_lock);
    return has_members;
}

static size_t cgroupfs_descendant_count(cgroupfs_cgroup_t *cgroup) {
    size_t count = 0;
    cgroupfs_cgroup_t *child, *tmp;

    if (!cgroup)
        return 0;

    llist_for_each(child, tmp, &cgroup->children, sibling) {
        count += 1 + cgroupfs_descendant_count(child);
    }
    return count;
}

static char *cgroupfs_build_members_file(cgroupfs_cgroup_t *cgroup,
                                         bool threads, size_t *content_len) {
    size_t max_ids = MAX((size_t)1, hashmap_size(&task_pid_map));
    uint64_t *ids = calloc(max_ids, sizeof(*ids));
    string_builder_t *builder = NULL;
    size_t count;

    if (!ids) {
        *content_len = 0;
        return NULL;
    }

    count = cgroupfs_collect_members(cgroup, threads, ids, max_ids);
    builder = create_string_builder(MAX((size_t)32, count * 24 + 1));
    if (!builder) {
        free(ids);
        *content_len = 0;
        return NULL;
    }

    for (size_t i = 0; i < count; ++i) {
        string_builder_append(builder, "%llu\n", (unsigned long long)ids[i]);
    }

    free(ids);
    *content_len = builder->size;
    char *data = builder->data;
    free(builder);
    return data;
}

static char *cgroupfs_build_file(cgroupfs_inode_info_t *info,
                                 size_t *content_len) {
    string_builder_t *builder;
    uint32_t mask;

    if (!info || !info->cgroup || !content_len)
        return NULL;

    switch (info->kind) {
    case CGROUPFS_INODE_CGROUP_PROCS:
        return cgroupfs_build_members_file(info->cgroup, false, content_len);
    case CGROUPFS_INODE_CGROUP_THREADS:
        return cgroupfs_build_members_file(info->cgroup, true, content_len);
    default:
        break;
    }

    builder = create_string_builder(128);
    if (!builder) {
        *content_len = 0;
        return NULL;
    }

    switch (info->kind) {
    case CGROUPFS_INODE_CGROUP_CONTROLLERS:
        cgroupfs_append_controllers(
            builder, cgroupfs_available_controllers(info->cgroup));
        string_builder_append(builder, "\n");
        break;
    case CGROUPFS_INODE_CGROUP_EVENTS:
        string_builder_append(builder, "populated %d\nfrozen %d\n",
                              cgroupfs_cgroup_populated(info->cgroup) ? 1 : 0,
                              info->cgroup->frozen ? 1 : 0);
        break;
    case CGROUPFS_INODE_CGROUP_TYPE:
        string_builder_append(builder, "domain\n");
        break;
    case CGROUPFS_INODE_CGROUP_FREEZE:
        string_builder_append(builder, "%d\n", info->cgroup->frozen ? 1 : 0);
        break;
    case CGROUPFS_INODE_CGROUP_SUBTREE_CONTROL:
        mask = info->cgroup->subtree_control;
        cgroupfs_append_controllers(builder, mask);
        string_builder_append(builder, "\n");
        break;
    case CGROUPFS_INODE_CGROUP_MAX_DEPTH:
    case CGROUPFS_INODE_CGROUP_MAX_DESCENDANTS:
        string_builder_append(builder, "max\n");
        break;
    case CGROUPFS_INODE_CGROUP_STAT:
        string_builder_append(
            builder,
            "nr_descendants %llu\n"
            "nr_dying_descendants 0\n",
            (unsigned long long)cgroupfs_descendant_count(info->cgroup));
        break;
    default:
        string_builder_append(builder, "\n");
        break;
    }

    *content_len = builder->size;
    char *data = builder->data;
    free(builder);
    return data;
}

static int cgroupfs_parse_u64(const char *buf, uint64_t *value) {
    uint64_t parsed = 0;

    if (!buf || !buf[0] || !value)
        return -EINVAL;

    while (*buf == ' ' || *buf == '\t' || *buf == '\n')
        buf++;
    if (!*buf)
        return -EINVAL;

    while (*buf >= '0' && *buf <= '9') {
        parsed = parsed * 10 + (uint64_t)(*buf - '0');
        buf++;
    }

    while (*buf == ' ' || *buf == '\t' || *buf == '\n')
        buf++;
    if (*buf)
        return -EINVAL;

    *value = parsed;
    return 0;
}

static int cgroupfs_write_procs(cgroupfs_cgroup_t *cgroup, uint64_t pid,
                                bool threads) {
    task_t *task = NULL;
    uint64_t *pids = NULL;
    size_t max_pids = MAX((size_t)1, hashmap_size(&task_pid_map));
    size_t count = 0;
    int ret = 0;

    task = task_find_by_pid(pid);
    if (!task || task->state == TASK_DIED)
        return -ESRCH;

    pids = calloc(max_pids, sizeof(*pids));
    if (!pids)
        return -ENOMEM;

    spin_lock(&task_queue_lock);
    if (threads) {
        pids[count++] = pid;
    } else if (task_pid_map.buckets) {
        uint64_t tgid = task_effective_tgid(task);
        for (size_t i = 0; i < task_pid_map.bucket_count; ++i) {
            hashmap_entry_t *entry = &task_pid_map.buckets[i];
            task_t *peer;

            if (!hashmap_entry_is_occupied(entry))
                continue;
            peer = (task_t *)entry->value;
            if (!peer || peer->state == TASK_DIED)
                continue;
            if (task_effective_tgid(peer) != tgid)
                continue;
            if (count < max_pids)
                pids[count++] = peer->pid;
        }
    }
    spin_unlock(&task_queue_lock);

    mutex_lock(&cgroupfs_lock);
    for (size_t i = 0; i < count; ++i) {
        ret = cgroupfs_set_task_cgroup_locked(pids[i], cgroup);
        if (ret < 0)
            break;
    }
    mutex_unlock(&cgroupfs_lock);

    free(pids);
    return ret;
}

static int cgroupfs_write_subtree_control(cgroupfs_cgroup_t *cgroup,
                                          const char *buf) {
    char *copy = strdup(buf ? buf : "");
    char *cursor = copy;
    int ret = 0;

    if (!copy)
        return -ENOMEM;

    mutex_lock(&cgroupfs_lock);
    while (*cursor) {
        char *token;
        char op;
        uint32_t mask;

        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n')
            cursor++;
        if (!*cursor)
            break;

        token = cursor;
        while (*cursor && *cursor != ' ' && *cursor != '\t' && *cursor != '\n')
            cursor++;
        if (*cursor)
            *cursor++ = '\0';

        op = token[0];
        if ((op != '+' && op != '-') || !token[1]) {
            ret = -EINVAL;
            break;
        }

        ret = cgroupfs_parse_controller(token + 1, &mask);
        if (ret < 0)
            break;
        if (!(cgroupfs_available_controllers(cgroup) & mask)) {
            ret = -EINVAL;
            break;
        }

        if (op == '+')
            cgroup->subtree_control |= mask;
        else
            cgroup->subtree_control &= ~mask;
    }
    mutex_unlock(&cgroupfs_lock);

    free(copy);
    return ret;
}

static int cgroupfs_write_freeze(cgroupfs_cgroup_t *cgroup, const char *buf) {
    uint64_t value = 0;
    int ret = cgroupfs_parse_u64(buf, &value);

    if (ret < 0)
        return ret;
    if (value > 1)
        return -EINVAL;

    mutex_lock(&cgroupfs_lock);
    cgroup->frozen = value != 0;
    mutex_unlock(&cgroupfs_lock);
    return 0;
}

static int cgroupfs_setattr(struct vfs_dentry *dentry,
                            const struct vfs_kstat *stat) {
    struct vfs_inode *inode;

    if (!dentry || !dentry->d_inode || !stat)
        return -EINVAL;

    inode = dentry->d_inode;

    if (!S_ISDIR(inode->i_mode) && stat->size != inode->i_size) {
        if (stat->size != 0)
            return -EOPNOTSUPP;
        inode->i_size = 0;
    }

    if (stat->mode)
        inode->i_mode = stat->mode;
    inode->i_uid = stat->uid;
    inode->i_gid = stat->gid;
    inode->inode = inode->i_ino;
    inode->type = S_ISDIR(inode->i_mode) ? file_dir : file_none;
    return 0;
}

static struct vfs_dentry *cgroupfs_lookup(struct vfs_inode *dir,
                                          struct vfs_dentry *dentry,
                                          unsigned int flags) {
    cgroupfs_dirent_t *de;

    (void)flags;
    de = cgroupfs_find_dirent(dir, dentry->d_name.name);
    vfs_d_instantiate(dentry, de ? de->inode : NULL);
    return dentry;
}

static int cgroupfs_create_control_file(struct vfs_inode *dir, const char *name,
                                        cgroupfs_inode_kind_t kind,
                                        umode_t mode) {
    struct vfs_inode *inode = cgroupfs_new_inode(
        dir->i_sb, cgroupfs_i(dir)->cgroup, kind, S_IFREG | mode);
    int ret;

    if (!inode)
        return -ENOMEM;

    ret = cgroupfs_add_dirent(dir, name, inode);
    vfs_iput(inode);
    return ret;
}

static int cgroupfs_populate_dir(struct vfs_inode *dir) {
    if (cgroupfs_create_control_file(dir, "cgroup.procs",
                                     CGROUPFS_INODE_CGROUP_PROCS, 0644) < 0)
        return -ENOMEM;
    if (cgroupfs_create_control_file(dir, "cgroup.threads",
                                     CGROUPFS_INODE_CGROUP_THREADS, 0644) < 0)
        return -ENOMEM;
    if (cgroupfs_create_control_file(dir, "cgroup.controllers",
                                     CGROUPFS_INODE_CGROUP_CONTROLLERS,
                                     0444) < 0)
        return -ENOMEM;
    if (cgroupfs_create_control_file(dir, "cgroup.events",
                                     CGROUPFS_INODE_CGROUP_EVENTS, 0444) < 0)
        return -ENOMEM;
    if (cgroupfs_create_control_file(dir, "cgroup.type",
                                     CGROUPFS_INODE_CGROUP_TYPE, 0444) < 0)
        return -ENOMEM;
    if (cgroupfs_create_control_file(dir, "cgroup.freeze",
                                     CGROUPFS_INODE_CGROUP_FREEZE, 0644) < 0)
        return -ENOMEM;
    if (cgroupfs_create_control_file(dir, "cgroup.subtree_control",
                                     CGROUPFS_INODE_CGROUP_SUBTREE_CONTROL,
                                     0644) < 0)
        return -ENOMEM;
    if (cgroupfs_create_control_file(dir, "cgroup.max.depth",
                                     CGROUPFS_INODE_CGROUP_MAX_DEPTH, 0444) < 0)
        return -ENOMEM;
    if (cgroupfs_create_control_file(dir, "cgroup.max.descendants",
                                     CGROUPFS_INODE_CGROUP_MAX_DESCENDANTS,
                                     0444) < 0)
        return -ENOMEM;
    if (cgroupfs_create_control_file(dir, "cgroup.stat",
                                     CGROUPFS_INODE_CGROUP_STAT, 0444) < 0)
        return -ENOMEM;
    return 0;
}

static int cgroupfs_mkdir(struct vfs_inode *dir, struct vfs_dentry *dentry,
                          umode_t mode) {
    struct vfs_inode *inode = NULL;
    cgroupfs_cgroup_t *parent = cgroupfs_i(dir)->cgroup;
    cgroupfs_cgroup_t *child = NULL;
    int ret = 0;

    if (cgroupfs_find_dirent(dir, dentry->d_name.name))
        return -EEXIST;

    child = cgroupfs_create_cgroup(parent, dentry->d_name.name);
    if (!child)
        return -ENOMEM;

    mutex_lock(&cgroupfs_lock);
    llist_append(&parent->children, &child->sibling);
    mutex_unlock(&cgroupfs_lock);

    inode = cgroupfs_new_inode(dir->i_sb, child, CGROUPFS_INODE_DIR,
                               (mode & 07777) | S_IFDIR);
    if (!inode) {
        ret = -ENOMEM;
        goto fail;
    }

    ret = cgroupfs_populate_dir(inode);
    if (ret < 0)
        goto fail;

    ret = cgroupfs_add_dirent(dir, dentry->d_name.name, inode);
    if (ret < 0)
        goto fail;

    dir->i_nlink++;
    vfs_d_instantiate(dentry, inode);
    vfs_iput(inode);
    cgroupfs_cgroup_put(child);
    return 0;

fail:
    mutex_lock(&cgroupfs_lock);
    if (!llist_empty(&child->sibling))
        llist_delete(&child->sibling);
    mutex_unlock(&cgroupfs_lock);
    if (inode)
        vfs_iput(inode);
    cgroupfs_cgroup_put(child);
    return ret;
}

static int cgroupfs_rmdir(struct vfs_inode *dir, struct vfs_dentry *dentry) {
    cgroupfs_dirent_t *de;
    cgroupfs_cgroup_t *child;

    if (!dir || !dentry || !dentry->d_inode ||
        !S_ISDIR(dentry->d_inode->i_mode))
        return -ENOTDIR;

    child = cgroupfs_i(dentry->d_inode)->cgroup;
    if (!llist_empty(&child->children))
        return -ENOTEMPTY;
    if (cgroupfs_cgroup_has_live_members(child))
        return -EBUSY;

    de = cgroupfs_detach_dirent(dir, dentry->d_name.name);
    if (!de)
        return -ENOENT;

    mutex_lock(&cgroupfs_lock);
    if (!llist_empty(&child->sibling))
        llist_delete(&child->sibling);
    mutex_unlock(&cgroupfs_lock);

    if (dir->i_nlink)
        dir->i_nlink--;
    if (de->inode->i_nlink >= 2)
        de->inode->i_nlink -= 2;
    vfs_iput(de->inode);
    free(de->name);
    free(de);
    return 0;
}

static int cgroupfs_iterate_shared(struct vfs_file *file,
                                   struct vfs_dir_context *ctx) {
    cgroupfs_dirent_t *de, *tmp;
    loff_t index = 0;

    llist_for_each(de, tmp, &cgroupfs_i(file->f_inode)->children, node) {
        if (index++ < ctx->pos)
            continue;
        if (ctx->actor(ctx, de->name, (int)strlen(de->name), index,
                       de->inode->i_ino,
                       S_ISDIR(de->inode->i_mode) ? DT_DIR : DT_REG)) {
            break;
        }
        ctx->pos = index;
    }
    file->f_pos = ctx->pos;
    return 0;
}

static ssize_t cgroupfs_read(struct vfs_file *file, void *buf, size_t count,
                             loff_t *ppos) {
    cgroupfs_inode_info_t *info = cgroupfs_i(file->f_inode);
    char *content;
    size_t size = 0;
    size_t pos;
    size_t to_copy;

    if (!info || !ppos)
        return -EINVAL;

    content = cgroupfs_build_file(info, &size);
    if (!content)
        return -ENOMEM;

    file->f_inode->i_size = size;
    pos = (size_t)*ppos;
    if (pos >= size) {
        free(content);
        return 0;
    }

    to_copy = MIN(count, size - pos);
    memcpy(buf, content + pos, to_copy);
    *ppos += (loff_t)to_copy;
    free(content);
    return (ssize_t)to_copy;
}

static ssize_t cgroupfs_write(struct vfs_file *file, const void *buf,
                              size_t count, loff_t *ppos) {
    cgroupfs_inode_info_t *info = cgroupfs_i(file->f_inode);
    char *copy;
    uint64_t pid = 0;
    int ret = -EOPNOTSUPP;

    (void)ppos;
    if (!info || !info->cgroup)
        return -EINVAL;

    copy = calloc(1, count + 1);
    if (!copy)
        return -ENOMEM;
    memcpy(copy, buf, count);

    switch (info->kind) {
    case CGROUPFS_INODE_CGROUP_PROCS:
        ret = cgroupfs_parse_u64(copy, &pid);
        if (ret == 0)
            ret = cgroupfs_write_procs(info->cgroup, pid, false);
        break;
    case CGROUPFS_INODE_CGROUP_THREADS:
        ret = cgroupfs_parse_u64(copy, &pid);
        if (ret == 0)
            ret = cgroupfs_write_procs(info->cgroup, pid, true);
        break;
    case CGROUPFS_INODE_CGROUP_SUBTREE_CONTROL:
        ret = cgroupfs_write_subtree_control(info->cgroup, copy);
        break;
    case CGROUPFS_INODE_CGROUP_FREEZE:
        ret = cgroupfs_write_freeze(info->cgroup, copy);
        break;
    default:
        ret = -EOPNOTSUPP;
        break;
    }

    free(copy);
    return ret < 0 ? ret : (ssize_t)count;
}

static int cgroupfs_open(struct vfs_inode *inode, struct vfs_file *file) {
    file->f_op = inode->i_fop;
    return 0;
}

static int cgroupfs_init_fs_context(struct vfs_fs_context *fc) {
    (void)fc;
    return 0;
}

static int cgroupfs_get_tree(struct vfs_fs_context *fc) {
    struct vfs_super_block *sb = vfs_alloc_super(fc->fs_type, fc->sb_flags);
    struct vfs_inode *root_inode;
    struct vfs_dentry *root_dentry;
    struct vfs_qstr root_name = {.name = "", .len = 0, .hash = 0};
    int ret;

    if (!sb)
        return -ENOMEM;

    sb->s_op = &cgroupfs_super_ops;
    sb->s_magic = 0x63677270;
    sb->s_type = &cgroupfs_fs_type;

    mutex_lock(&cgroupfs_lock);
    if (!cgroupfs_root) {
        cgroupfs_root = cgroupfs_create_cgroup(NULL, "");
        if (!cgroupfs_root) {
            mutex_unlock(&cgroupfs_lock);
            vfs_put_super(sb);
            return -ENOMEM;
        }
    }
    mutex_unlock(&cgroupfs_lock);

    root_inode = cgroupfs_new_inode(sb, cgroupfs_root, CGROUPFS_INODE_DIR,
                                    S_IFDIR | 0755);
    if (!root_inode) {
        vfs_put_super(sb);
        return -ENOMEM;
    }

    ret = cgroupfs_populate_dir(root_inode);
    if (ret < 0) {
        vfs_iput(root_inode);
        vfs_put_super(sb);
        return ret;
    }

    root_dentry = vfs_d_alloc(sb, NULL, &root_name);
    if (!root_dentry) {
        vfs_iput(root_inode);
        vfs_put_super(sb);
        return -ENOMEM;
    }

    vfs_d_instantiate(root_dentry, root_inode);
    sb->s_root = root_dentry;
    fc->sb = sb;
    vfs_iput(root_inode);
    return 0;
}

static const struct vfs_super_operations cgroupfs_super_ops = {
    .alloc_inode = cgroupfs_alloc_inode,
    .destroy_inode = cgroupfs_destroy_inode,
    .evict_inode = cgroupfs_evict_inode,
    .statfs = cgroupfs_statfs,
};

static const struct vfs_inode_operations cgroupfs_inode_ops = {
    .lookup = cgroupfs_lookup,
    .mkdir = cgroupfs_mkdir,
    .rmdir = cgroupfs_rmdir,
    .setattr = cgroupfs_setattr,
};

static const struct vfs_file_operations cgroupfs_dir_file_ops = {
    .iterate_shared = cgroupfs_iterate_shared,
    .open = cgroupfs_open,
};

static const struct vfs_file_operations cgroupfs_file_ops = {
    .read = cgroupfs_read,
    .write = cgroupfs_write,
    .open = cgroupfs_open,
};

static struct vfs_file_system_type cgroupfs_fs_type = {
    .name = "cgroup2",
    .fs_flags = VFS_FS_VIRTUAL,
    .init_fs_context = cgroupfs_init_fs_context,
    .get_tree = cgroupfs_get_tree,
};

char *cgroupfs_task_path(task_t *task) {
    char buf[VFS_PATH_MAX];
    size_t pos = sizeof(buf) - 1;
    cgroupfs_cgroup_t *cgroup = NULL;

    buf[pos] = '\0';

    mutex_lock(&cgroupfs_lock);
    cgroup = task ? cgroupfs_task_cgroup_locked(task->pid) : cgroupfs_root;
    if (!cgroup || cgroup == cgroupfs_root) {
        mutex_unlock(&cgroupfs_lock);
        return strdup("/");
    }

    while (cgroup && cgroup != cgroupfs_root) {
        size_t len = strlen(cgroup->name);

        if (pos <= len + 1)
            break;
        pos -= len;
        memcpy(buf + pos, cgroup->name, len);
        buf[--pos] = '/';
        cgroup = cgroup->parent;
    }
    mutex_unlock(&cgroupfs_lock);

    if (pos == sizeof(buf) - 1)
        buf[--pos] = '/';
    return strdup(buf + pos);
}

void cgroupfs_init(void) {
    mutex_init(&cgroupfs_lock);
    vfs_register_filesystem(&cgroupfs_fs_type);
}

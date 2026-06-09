#include <fs/fs_syscall.h>
#include <task/task.h>

static char *join_pathname(const char *base, const char *pathname) {
    if (!base)
        return NULL;

    size_t base_len = strlen(base);
    size_t path_len = pathname ? strlen(pathname) : 0;
    bool need_sep = path_len && base_len && strcmp(base, "/");
    size_t need = base_len + (need_sep ? 1 : 0) + path_len + 1;

    char *out = malloc(need);
    if (!out)
        return NULL;

    size_t cursor = 0;
    if (base_len) {
        memcpy(out, base, base_len);
        cursor = base_len;
    }
    if (need_sep)
        out[cursor++] = '/';
    if (path_len) {
        memcpy(out + cursor, pathname, path_len);
        cursor += path_len;
    }
    out[cursor] = '\0';

    return out;
}

char *at_resolve_pathname(int dirfd, char *pathname) {
    if (pathname[0] == '/') { // by absolute pathname
        return strdup(pathname);
    } else if (pathname[0] != '/') {
        if (dirfd == (int)AT_FDCWD) { // relative to cwd
            char *cwd =
                current_task
                    ? vfs_path_to_string(task_fs_pwd_path(current_task),
                                         task_fs_root_path(current_task))
                    : strdup("/");
            if (!cwd)
                return NULL;

            char *ret = join_pathname(cwd, pathname);
            free(cwd);
            return ret;
        } else { // relative to dirfd, resolve accordingly
            struct vfs_file *file;
            struct vfs_path path = {0};
            char *dirname;
            char *out;
            int ret;

            if (dirfd < 0 || dirfd >= MAX_FD_NUM)
                return NULL;
            file = task_get_file(current_task, dirfd);
            if (!file)
                return NULL;

            ret = mountfd_get_path(file, &path);
            if (ret == -EINVAL)
                ret = fsfd_mount_get_path(file, &path);
            if (ret == -EINVAL) {
                if (!file->f_path.dentry) {
                    vfs_file_put(file);
                    return NULL;
                }
                ret = vfs_path_copy(&path, &file->f_path) ? 0 : -ENOENT;
            }
            vfs_file_put(file);
            if (ret < 0)
                return NULL;

            dirname =
                vfs_path_to_string(&path, task_fs_root_path(current_task));
            vfs_path_put(&path);
            if (!dirname)
                return NULL;

            out = join_pathname(dirname, pathname);
            free(dirname);

            return out;
        }
    }

    return NULL;
}

char *at_resolve_pathname_fullpath(int dirfd, char *pathname) {
    return at_resolve_pathname(dirfd, pathname);
}

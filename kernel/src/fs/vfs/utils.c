#include <fs/vfs/vfs.h>

#define IS_SLASH(c) ((c) == '/')
#define PATH_SEPARATOR '/'

static void normalize_slashes(char *path) {
    char *p;
    for (p = path; *p; p++) {
        if (*p == '\\')
            *p = PATH_SEPARATOR;
    }
}

static size_t get_root_length(const char *path) {
    if (!path || !*path)
        return 0;

    // Unix root
    return IS_SLASH(path[0]) ? 1 : 0;
}

static const char *find_next_separator(const char *path) {
    while (*path && !IS_SLASH(*path))
        path++;
    return path;
}

static size_t find_common_prefix(const char *path1, const char *path2) {
    const char *p1 = path1;
    const char *p2 = path2;
    const char *last_slash = NULL;

    // Skip root if present (must be identical)
    size_t root1 = get_root_length(path1);
    size_t root2 = get_root_length(path2);

    if (root1 != root2 || strncmp(path1, path2, root1) != 0)
        return 0;

    p1 += root1;
    p2 += root2;

    // Find last matching separator
    while (*p1 && *p2) {
        if (IS_SLASH(*p1) && IS_SLASH(*p2)) {
            if (strncmp(path1, path2, p1 - path1) == 0)
                last_slash = p1;
        } else if (*p1 != *p2)
            break;
        p1++;
        p2++;
    }

    return last_slash ? (last_slash - path1) + 1 : root1;
}

static size_t count_path_segments(const char *path) {
    size_t count = 0;
    const char *p = path;

    while (*p) {
        if (!IS_SLASH(*p) && (p == path || IS_SLASH(*(p - 1))))
            count++;
        p++;
    }
    return count;
}

rel_status calculate_relative_path(char *relative, const char *from,
                                   const char *to, size_t size) {
    char from_normalized[1024];
    char to_normalized[1024];
    size_t common_len, from_len, to_len;
    size_t pos = 0;
    const char *from_ptr, *to_ptr;
    size_t segments_up;

    if (!relative || !from || !to || size == 0)
        return REL_ERROR_INVALID;

    // Check if paths are absolute
    if (get_root_length(from) == 0 || get_root_length(to) == 0)
        return REL_ERROR_NOT_ABSOLUTE;

    // Normalize paths (handle slashes)
    strncpy(from_normalized, from, sizeof(from_normalized) - 1);
    strncpy(to_normalized, to, sizeof(to_normalized) - 1);
    from_normalized[sizeof(from_normalized) - 1] = '\0';
    to_normalized[sizeof(to_normalized) - 1] = '\0';

    normalize_slashes(from_normalized);
    normalize_slashes(to_normalized);

    // Find common prefix
    common_len = find_common_prefix(from_normalized, to_normalized);
    if (common_len == 0)
        return REL_ERROR_NO_COMMON_PREFIX;

    from_ptr = from_normalized + common_len;
    to_ptr = to_normalized + common_len;

    // Count how many levels we need to go up
    segments_up = count_path_segments(from_ptr);

    // Build the relative path
    relative[0] = '\0';

    // Add "../" for each segment we need to go up
    for (size_t i = 0; i < segments_up - 1; i++) {
        if (pos + 3 >= size)
            return REL_ERROR_MEMORY;
        strcpy(relative + pos, "../");
        pos += 3;
    }

    // Add the path to the target
    while (*to_ptr == PATH_SEPARATOR)
        to_ptr++;

    if (*to_ptr) {
        if (pos + strlen(to_ptr) >= size)
            return REL_ERROR_MEMORY;
        strcpy(relative + pos, to_ptr);
        pos += strlen(to_ptr);
    } else if (pos > 0) {
        // Remove trailing slash if target is empty
        relative[pos - 1] = '\0';
    } else {
        // If we're in the same directory, return "."
        strcpy(relative, ".");
    }

    return REL_SUCCESS;
}

/**
 * 获取路径的目录名
 * @param path 输入路径
 * @param result 结果缓冲区
 * @param size 缓冲区大小
 * @return 成功返回result指针，失败返回NULL
 */
char *vfs_dirname(const char *path, char *result, size_t size) {
    if (!path || !result || size == 0) {
        return NULL;
    }

    // 处理空字符串或NULL
    if (path[0] == '\0') {
        snprintf(result, size, ".");
        return result;
    }

    // 复制路径以便处理
    size_t len = strlen(path);
    char *temp = (char *)malloc(len + 1);
    if (!temp)
        return NULL;
    strcpy(temp, path);

    // 去除尾部的斜杠（除非是根目录）
    while (len > 1 && temp[len - 1] == '/') {
        temp[--len] = '\0';
    }

    // 如果只剩下斜杠，说明是根目录
    if (temp[0] == '/' && len == 1) {
        int str_len = snprintf(result, size, "/");
        result[str_len] = '\0';
        free(temp);
        return result;
    }

    // 查找最后一个斜杠
    char *last_slash = strrchr(temp, '/');

    if (last_slash == NULL) {
        // 没有斜杠，返回当前目录
        int str_len = snprintf(result, size, ".");
        result[str_len] = '\0';
    } else if (last_slash == temp) {
        // 斜杠在第一个字符，说明是根目录下的文件
        int str_len = snprintf(result, size, "/");
        result[str_len] = '\0';
    } else {
        // 截断到最后一个斜杠之前
        *last_slash = '\0';
        int str_len = snprintf(result, size, "%s", temp);
        result[str_len] = '\0';
    }

    free(temp);
    return result;
}

#pragma once

#include <libs/klibc.h>
#include <mm/mm.h>

static inline char toupper(char ch) {
    if (ch >= 'a' && ch <= 'z')
        ch -= 0x20;
    return ch;
}

static inline char tolower(char ch) {
    if (ch >= 'A' && ch <= 'Z')
        ch += 0x20;
    return ch;
}

size_t strspn(const char *s, const char *accept);
size_t strcspn(const char *s, const char *reject);

static inline bool streq(const char *str1, const char *str2) {
    int ret = 0;
    while (!(ret = *(unsigned char *)str1 - *(unsigned char *)str2) && *str1) {
        str1++;
        str2++;
    }
    if (ret < 0) {
        return false;
    } else if (ret > 0) {
        return false;
    }
    return true;
}

static inline bool streqn(const char *str1, const char *str2, size_t max_size) {
    if (max_size == 0) {
        return true;
    }

    while (max_size-- > 0) {
        int c1 = tolower((unsigned char)*str1);
        int c2 = tolower((unsigned char)*str2);

        if (c1 != c2) {
            return false;
        }

        if (*str1 == '\0') {
            return true;
        }

        str1++;
        str2++;
    }

    return true;
}

// 从字符串中提取路径
static inline char *pathtok(char **sp) {
    char *s = *sp;
    char *e = *sp;

    // 跳过所有连续的斜杠
    while (*e == '/') {
        e++;
    }

    // 如果已经到达字符串末尾，返回 NULL
    if (*e == '\0') {
        *sp = e; // 更新指针到字符串末尾
        return NULL;
    }

    s = e; // 设置令牌起始位置（第一个非斜杠字符）

    // 查找下一个斜杠或字符串结尾
    while (*e != '\0' && *e != '/') {
        e++;
    }

    // 保存下一个令牌的起始位置
    char *next = e;
    if (*e == '/') {
        next++; // 跳过斜杠指向下一个字符
    }

    // 终止当前令牌
    if (*e != '\0') {
        *e = '\0';
    }

    *sp = next; // 更新指针到下一个令牌位置
    return s;   // 返回当前令牌
}

/**
 * Status codes for relative path calculation
 */
typedef enum {
    REL_SUCCESS = 0,
    REL_ERROR_INVALID = -1,
    REL_ERROR_NO_COMMON_PREFIX = -2,
    REL_ERROR_MEMORY = -3,
    REL_ERROR_NOT_ABSOLUTE = -4
} rel_status;

/**
 * Calculate relative path from one absolute path to another
 * @param relative Output buffer for relative path
 * @param from Source absolute path
 * @param to Target absolute path
 * @param size Size of output buffer
 * @return rel_status code indicating success or specific error
 */
rel_status calculate_relative_path(char *relative, const char *from,
                                   const char *to, size_t size);

char *vfs_dirname(const char *path, char *result, size_t size);

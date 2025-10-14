#include <mm/vma.h>

void *malloc(size_t size);
void free(void *ptr);

// VMA分配
vma_t *vma_alloc(void) {
    vma_t *vma = (vma_t *)malloc(sizeof(vma_t));
    if (!vma)
        return NULL;

    memset(vma, 0, sizeof(vma_t));
    vma->vm_fd = -1;
    vma->shm_id = -1;
    return vma;
}

// VMA释放
void vma_free(vma_t *vma) {
    if (vma) {
        if (vma->vm_name)
            free(vma->vm_name);
        free(vma);
    }
}

// 查找包含指定地址的VMA
vma_t *vma_find(vma_manager_t *mgr, unsigned long addr) {
    vma_t *vma = mgr->vma_list;

    while (vma) {
        if (addr >= vma->vm_start && addr < vma->vm_end) {
            return vma;
        }
        vma = vma->vm_next;
    }
    return NULL;
}

// 查找与指定范围有交集的VMA
vma_t *vma_find_intersection(vma_manager_t *mgr, unsigned long start,
                             unsigned long end) {
    vma_t *vma = mgr->vma_list;

    while (vma) {
        if (!(end <= vma->vm_start || start >= vma->vm_end)) {
            return vma;
        }
        vma = vma->vm_next;
    }
    return NULL;
}

// 插入VMA到链表（保持地址排序）
int vma_insert(vma_manager_t *mgr, vma_t *new_vma) {
    if (!new_vma)
        return -1;

    // 检查是否有重叠
    if (vma_find_intersection(mgr, new_vma->vm_start, new_vma->vm_end)) {
        return -1;
    }

    vma_t *vma = mgr->vma_list;
    vma_t *prev = NULL;

    // 找到正确的插入位置
    while (vma && vma->vm_start < new_vma->vm_start) {
        prev = vma;
        vma = vma->vm_next;
    }

    // 插入VMA
    new_vma->vm_next = vma;
    new_vma->vm_prev = prev;

    if (prev) {
        prev->vm_next = new_vma;
    } else {
        mgr->vma_list = new_vma;
    }

    if (vma) {
        vma->vm_prev = new_vma;
    }

    mgr->vm_used += new_vma->vm_end - new_vma->vm_start;
    return 0;
}

// 从链表中移除VMA
int vma_remove(vma_manager_t *mgr, vma_t *vma) {
    if (!vma)
        return -1;

    if (vma->vm_prev) {
        vma->vm_prev->vm_next = vma->vm_next;
    } else {
        mgr->vma_list = vma->vm_next;
    }

    if (vma->vm_next) {
        vma->vm_next->vm_prev = vma->vm_prev;
    }

    mgr->vm_used -= vma->vm_end - vma->vm_start;
    return 0;
}

// VMA分割
int vma_split(vma_t *vma, unsigned long addr) {
    if (!vma || addr <= vma->vm_start || addr >= vma->vm_end) {
        return -1;
    }

    // 创建新的VMA
    vma_t *new_vma = vma_alloc();
    if (!new_vma)
        return -1;

    // 复制属性
    *new_vma = *vma;
    new_vma->vm_start = addr;
    new_vma->vm_next = vma->vm_next;
    new_vma->vm_prev = vma;

    // 调整文件偏移量
    if (vma->vm_type == VMA_TYPE_FILE) {
        new_vma->vm_offset += addr - vma->vm_start;
    }

    // 更新原VMA
    vma->vm_end = addr;
    vma->vm_next = new_vma;

    // 更新链表
    if (new_vma->vm_next) {
        new_vma->vm_next->vm_prev = new_vma;
    }

    return 0;
}

// VMA合并
int vma_merge(vma_t *vma1, vma_t *vma2) {
    if (!vma1 || !vma2 || vma1->vm_end != vma2->vm_start) {
        return -1;
    }

    // 检查是否可以合并（相同属性）
    if (vma1->vm_flags != vma2->vm_flags || vma1->vm_type != vma2->vm_type ||
        vma1->vm_fd != vma2->vm_fd) {
        return -1;
    }

    // 合并VMA
    vma1->vm_end = vma2->vm_end;
    vma1->vm_next = vma2->vm_next;

    if (vma2->vm_next) {
        vma2->vm_next->vm_prev = vma1;
    }

    vma_free(vma2);
    return 0;
}

int vma_unmap_range(vma_manager_t *mgr, uintptr_t start, uintptr_t end) {
    vma_t *vma = mgr->vma_list;
    vma_t *next;

    while (vma) {
        next = vma->vm_next;

        // 完全包含在要取消映射的范围内
        if (vma->vm_start >= start && vma->vm_end <= end) {
            vma_remove(mgr, vma);
            vma_free(vma);
        }
        // 部分重叠 - 需要分割
        else if (!(vma->vm_end <= start || vma->vm_start >= end)) {
            if (vma->vm_start < start && vma->vm_end > end) {
                // VMA跨越整个取消映射范围 - 分割成两部分
                vma_split(vma, end);
                vma_split(vma, start);
                // 移除中间部分
                vma_t *middle = vma->vm_next;
                vma_remove(mgr, middle);
                vma_free(middle);
            } else if (vma->vm_start < start) {
                // 截断VMA的末尾
                mgr->vm_used -= vma->vm_end - start;
                vma->vm_end = start;
            } else if (vma->vm_end > end) {
                // 截断VMA的开头
                mgr->vm_used -= end - vma->vm_start;
                if (vma->vm_type == VMA_TYPE_FILE) {
                    vma->vm_offset += end - vma->vm_start;
                }
                vma->vm_start = end;
            }
        }

        vma = next;
    }

    return 0;
}

void vma_manager_exit_cleanup(vma_manager_t *mgr) {
    if (!mgr)
        return;

    vma_t *vma = mgr->vma_list;
    vma_t *next;
    int cleaned_count = 0;

    // 遍历并清理所有VMA
    while (vma) {
        next = vma->vm_next;

        // 从链表中移除
        if (vma->vm_prev) {
            vma->vm_prev->vm_next = vma->vm_next;
        } else {
            mgr->vma_list = vma->vm_next;
        }

        if (vma->vm_next) {
            vma->vm_next->vm_prev = vma->vm_prev;
        }

        // 更新统计信息
        mgr->vm_used -= vma->vm_end - vma->vm_start;

        // 释放VMA结构体
        vma_free(vma);
        cleaned_count++;

        vma = next;
    }

    // 重置管理器状态
    mgr->vma_list = NULL;
    mgr->vm_total = 0;
    mgr->vm_used = 0;
}

// 深度拷贝单个VMA节点（不包括链表指针）
vma_t *vma_copy(vma_t *src) {
    if (!src)
        return NULL;

    // 分配新的VMA结构体
    vma_t *dst = vma_alloc();
    if (!dst)
        return NULL;

    // 拷贝所有基本字段
    dst->vm_start = src->vm_start;
    dst->vm_end = src->vm_end;
    dst->vm_flags = src->vm_flags;
    dst->vm_type = src->vm_type;
    dst->vm_fd = src->vm_fd;
    dst->vm_offset = src->vm_offset;
    dst->shm_id = src->shm_id;

    // 深度拷贝vm_name字符串
    if (src->vm_name) {
        size_t name_len = strlen(src->vm_name);
        dst->vm_name = (char *)malloc(name_len + 1);
        if (!dst->vm_name) {
            free(dst); // 注意这里直接用free，因为vm_name为NULL
            return NULL;
        }
        memcpy(dst->vm_name, src->vm_name, name_len + 1);
    } else {
        dst->vm_name = NULL;
    }

    // 链表指针初始化为NULL
    dst->vm_next = NULL;
    dst->vm_prev = NULL;

    return dst;
}

// 深度拷贝VMA链表（辅助函数，用于只拷贝链表不拷贝管理器）
vma_t *vma_list_copy(vma_t *src_list) {
    if (!src_list)
        return NULL;

    vma_t *dst_head = NULL;
    vma_t *dst_prev = NULL;
    vma_t *src_vma = src_list;

    while (src_vma) {
        // 拷贝当前节点
        vma_t *dst_vma = vma_copy(src_vma);
        if (!dst_vma) {
            // 失败时清理已创建的链表
            while (dst_head) {
                vma_t *next = dst_head->vm_next;
                vma_free(dst_head);
                dst_head = next;
            }
            return NULL;
        }

        // 连接链表
        dst_vma->vm_prev = dst_prev;
        dst_vma->vm_next = NULL;

        if (dst_prev) {
            dst_prev->vm_next = dst_vma;
        } else {
            dst_head = dst_vma;
        }

        dst_prev = dst_vma;
        src_vma = src_vma->vm_next;
    }

    return dst_head;
}

// 深度拷贝整个VMA管理器
int vma_manager_copy(vma_manager_t *dst, vma_manager_t *src) {
    if (!dst || !src)
        return -1;

    // 初始化目标管理器
    dst->vma_list = NULL;
    dst->vm_total = src->vm_total;
    dst->vm_used = 0; // 将在插入过程中累加

    vma_t *src_vma = src->vma_list;
    vma_t *dst_prev = NULL;

    // 遍历源链表，拷贝每个VMA
    while (src_vma) {
        // 深度拷贝当前VMA
        vma_t *dst_vma = vma_copy(src_vma);
        if (!dst_vma) {
            // 拷贝失败，清理已拷贝的部分
            vma_manager_exit_cleanup(dst);
            return -1;
        }

        // 重建双向链表结构
        dst_vma->vm_prev = dst_prev;
        dst_vma->vm_next = NULL;

        if (dst_prev) {
            dst_prev->vm_next = dst_vma;
        } else {
            // 第一个节点
            dst->vma_list = dst_vma;
        }

        // 更新统计信息
        dst->vm_used += dst_vma->vm_end - dst_vma->vm_start;

        // 移动到下一个节点
        dst_prev = dst_vma;
        src_vma = src_vma->vm_next;
    }

    return 0;
}

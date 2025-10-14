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

// 克隆单个VMA
vma_t *vma_clone(vma_t *vma) {
    if (!vma)
        return NULL;

    // 分配新的VMA结构体
    vma_t *new_vma = vma_alloc();
    if (!new_vma)
        return NULL;

    // 复制所有字段
    new_vma->vm_start = vma->vm_start;
    new_vma->vm_end = vma->vm_end;
    new_vma->vm_flags = vma->vm_flags;
    new_vma->vm_type = vma->vm_type;
    new_vma->vm_offset = vma->vm_offset;
    new_vma->shm_id = vma->shm_id;

    // 文件描述符需要复制（如果有效）
    if (vma->vm_fd >= 0) {
        new_vma->vm_fd = vma->vm_fd;
        if (new_vma->vm_fd < 0) {
            // dup失败，清理并返回
            vma_free(new_vma);
            return NULL;
        }
    } else {
        new_vma->vm_fd = -1;
    }

    // 深拷贝vm_name字符串
    if (vma->vm_name) {
        new_vma->vm_name = strdup(vma->vm_name);
        if (!new_vma->vm_name) {
            vma_free(new_vma);
            return NULL;
        }
    } else {
        new_vma->vm_name = NULL;
    }

    // 注意：vm_next 和 vm_prev 将在插入时设置，这里初始化为NULL
    new_vma->vm_next = NULL;
    new_vma->vm_prev = NULL;

    return new_vma;
}

// 克隆整个VMA管理器（用于fork）
int vma_manager_clone(vma_manager_t *src_mgr, vma_manager_t *dst_mgr) {
    if (!src_mgr || !dst_mgr)
        return -1;

    // 初始化目标管理器
    dst_mgr->vma_list = NULL;
    dst_mgr->vm_total = src_mgr->vm_total;
    dst_mgr->vm_used = 0; // 会在插入VMA时重新计算

    vma_t *src_vma = src_mgr->vma_list;
    vma_t *dst_prev = NULL;

    // 遍历源管理器的所有VMA
    while (src_vma) {
        // 克隆当前VMA
        vma_t *dst_vma = vma_clone(src_vma);
        if (!dst_vma) {
            // 克隆失败，清理已经创建的VMA
            vma_manager_exit_cleanup(dst_mgr);
            return -1;
        }

        // 将克隆的VMA插入到目标管理器
        dst_vma->vm_prev = dst_prev;
        dst_vma->vm_next = NULL;

        if (dst_prev) {
            dst_prev->vm_next = dst_vma;
        } else {
            // 第一个VMA
            dst_mgr->vma_list = dst_vma;
        }

        // 更新vm_used统计
        dst_mgr->vm_used += dst_vma->vm_end - dst_vma->vm_start;

        dst_prev = dst_vma;
        src_vma = src_vma->vm_next;
    }

    dst_mgr->last_alloc_addr = src_mgr->last_alloc_addr;

    return 0;
}

// fork时调用的便捷函数
int vma_manager_fork(vma_manager_t *dest_mgt, vma_manager_t *parent_mgr) {
    if (!parent_mgr)
        return -1;

    // 分配新的管理器
    if (!dest_mgt)
        return -1;

    // 克隆父进程的VMA
    if (vma_manager_clone(parent_mgr, dest_mgt) < 0) {
        return -1;
    }

    return 0;
}

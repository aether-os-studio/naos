#include <mm/vma.h>
#include <fs/vfs/vfs.h>

void *malloc(size_t size);
void free(void *ptr);

// VMA分配
vma_t *vma_alloc(void) {
    vma_t *vma = (vma_t *)malloc(sizeof(vma_t));
    if (!vma)
        return NULL;

    memset(vma, 0, sizeof(vma_t));
    vma->node = NULL;
    vma->shm_id = -1;
    vma->vm_rb.rb_parent_color = 0;
    vma->vm_rb.rb_left = NULL;
    vma->vm_rb.rb_right = NULL;
    return vma;
}

// VMA释放
void vma_free(vma_t *vma) {
    if (vma) {
        if (vma->node)
            vma->node->refcount--;
        if (vma->vm_name)
            free(vma->vm_name);
        free(vma);
    }
}

// 使用红黑树查找包含指定地址的VMA
vma_t *vma_find(vma_manager_t *mgr, uint64_t addr) {
    rb_node_t *node = mgr->vma_tree.rb_node;

    while (node) {
        vma_t *vma = rb_entry(node, vma_t, vm_rb);

        if (addr < vma->vm_start)
            node = node->rb_left;
        else if (addr >= vma->vm_end)
            node = node->rb_right;
        else
            return vma;
    }
    return NULL;
}

// 使用红黑树查找与指定范围有交集的VMA
vma_t *vma_find_intersection(vma_manager_t *mgr, uint64_t start, uint64_t end) {
    rb_node_t *node = mgr->vma_tree.rb_node;

    while (node) {
        vma_t *vma = rb_entry(node, vma_t, vm_rb);

        // 检查交集: !(end <= vma->vm_start || start >= vma->vm_end)
        if (end <= vma->vm_start) {
            // 目标范围完全在当前VMA左侧
            node = node->rb_left;
        } else if (start >= vma->vm_end) {
            // 目标范围完全在当前VMA右侧
            node = node->rb_right;
        } else {
            // 找到交集
            return vma;
        }
    }

    // 未找到交集，需要检查左子树的最右节点
    // 因为可能存在 vma->vm_end > start 但被跳过的情况
    node = mgr->vma_tree.rb_node;
    vma_t *candidate = NULL;

    while (node) {
        vma_t *vma = rb_entry(node, vma_t, vm_rb);

        if (!(end <= vma->vm_start || start >= vma->vm_end)) {
            return vma;
        }

        if (start < vma->vm_start) {
            node = node->rb_left;
        } else {
            if (vma->vm_end > start)
                candidate = vma;
            node = node->rb_right;
        }
    }

    return candidate;
}

// 插入VMA（同时维护链表和红黑树）
int vma_insert(vma_manager_t *mgr, vma_t *new_vma) {
    if (!new_vma)
        return -1;

    // 检查是否有重叠
    if (vma_find_intersection(mgr, new_vma->vm_start, new_vma->vm_end)) {
        return -1;
    }

    // === 插入红黑树 ===
    rb_node_t **link = &mgr->vma_tree.rb_node;
    rb_node_t *parent = NULL;
    vma_t *prev_vma = NULL;
    vma_t *next_vma = NULL;

    while (*link) {
        parent = *link;
        vma_t *vma = rb_entry(parent, vma_t, vm_rb);

        if (new_vma->vm_start < vma->vm_start) {
            next_vma = vma;
            link = &(*link)->rb_left;
        } else {
            prev_vma = vma;
            link = &(*link)->rb_right;
        }
    }

    // 初始化红黑树节点
    rb_node_t *node = &new_vma->vm_rb;
    node->rb_parent_color = (uint64_t)parent;
    node->rb_left = node->rb_right = NULL;
    *link = node;

    rb_insert_color(node, &mgr->vma_tree);

    // === 维护双向链表 ===
    new_vma->vm_prev = prev_vma;
    new_vma->vm_next = next_vma;

    if (prev_vma) {
        prev_vma->vm_next = new_vma;
    } else {
        mgr->vma_list = new_vma;
    }

    if (next_vma) {
        next_vma->vm_prev = new_vma;
    }

    mgr->vm_used += new_vma->vm_end - new_vma->vm_start;
    return 0;
}

// 从链表和红黑树中移除VMA
int vma_remove(vma_manager_t *mgr, vma_t *vma) {
    if (!vma)
        return -1;

    // === 从红黑树中删除 ===
    rb_erase(&vma->vm_rb, &mgr->vma_tree);

    // === 从链表中删除 ===
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

// VMA分割（需要插入新节点到红黑树）
int vma_split(vma_manager_t *mgr, vma_t *vma, uint64_t addr) {
    if (!vma || addr <= vma->vm_start || addr >= vma->vm_end) {
        return -1;
    }

    vma_t *new_vma = vma_alloc();
    if (!new_vma)
        return -1;

    // 复制字段
    new_vma->vm_start = addr;
    new_vma->vm_end = vma->vm_end;
    new_vma->vm_flags = vma->vm_flags;
    new_vma->vm_type = vma->vm_type;
    new_vma->node = vma->node;
    if (new_vma->node)
        new_vma->node->refcount++;
    new_vma->vm_offset = vma->vm_offset;
    new_vma->shm_id = vma->shm_id;

    if (vma->vm_name) {
        new_vma->vm_name = strdup(vma->vm_name);
        if (!new_vma->vm_name) {
            free(new_vma);
            return -1;
        }
    }

    if (vma->vm_type == VMA_TYPE_FILE) {
        new_vma->vm_offset += addr - vma->vm_start;
    }

    // 更新原VMA
    vma->vm_end = addr;

    // 维护链表
    new_vma->vm_next = vma->vm_next;
    new_vma->vm_prev = vma;
    vma->vm_next = new_vma;

    if (new_vma->vm_next) {
        new_vma->vm_next->vm_prev = new_vma;
    }

    // 插入红黑树
    rb_node_t *parent = &vma->vm_rb;
    rb_node_t **link = &parent->rb_right;

    if (*link) {
        parent = *link;
        while (parent->rb_left) {
            parent = parent->rb_left;
        }
        link = &parent->rb_left;
    }

    rb_node_t *node = &new_vma->vm_rb;
    node->rb_parent_color = (uint64_t)parent;
    node->rb_left = node->rb_right = NULL;
    *link = node;

    rb_insert_color(node, &mgr->vma_tree);

    return 0;
}

// VMA合并（从红黑树删除vma2）
int vma_merge(vma_t *vma1, vma_t *vma2) {
    if (!vma1 || !vma2 || vma1->vm_end != vma2->vm_start) {
        return -1;
    }

    if (vma1->vm_flags != vma2->vm_flags || vma1->vm_type != vma2->vm_type ||
        vma1->node != vma2->node) {
        return -1;
    }

    if (!vma1->vm_name && vma2->vm_name) {
        vma1->vm_name = vma2->vm_name;
        vma2->vm_name = NULL;
    }

    vma1->vm_end = vma2->vm_end;
    vma1->vm_next = vma2->vm_next;

    if (vma2->vm_next) {
        vma2->vm_next->vm_prev = vma1;
    }

    // 注意：需要从红黑树删除vma2，但这里没有manager引用
    // 同样需要改进接口
    // rb_erase(&vma2->vm_rb, &mgr->vma_tree);

    vma_free(vma2);
    return 0;
}

// 改进的vma_merge
int vma_merge_ex(vma_manager_t *mgr, vma_t *vma1, vma_t *vma2) {
    if (!vma1 || !vma2 || vma1->vm_end != vma2->vm_start) {
        return -1;
    }

    if (vma1->vm_flags != vma2->vm_flags || vma1->vm_type != vma2->vm_type ||
        vma1->node != vma2->node) {
        return -1;
    }

    if (!vma1->vm_name && vma2->vm_name) {
        vma1->vm_name = vma2->vm_name;
        vma2->vm_name = NULL;
    }

    vma1->vm_end = vma2->vm_end;
    vma1->vm_next = vma2->vm_next;

    if (vma2->vm_next) {
        vma2->vm_next->vm_prev = vma1;
    }

    // 从红黑树删除vma2
    rb_erase(&vma2->vm_rb, &mgr->vma_tree);

    vma_free(vma2);
    return 0;
}

// unmap范围
int vma_unmap_range(vma_manager_t *mgr, uintptr_t start, uintptr_t end) {
    vma_t *vma = mgr->vma_list;
    vma_t *next;

    while (vma) {
        next = vma->vm_next;

        if (vma->vm_start >= start && vma->vm_end <= end) {
            // 完全包含
            vma_remove(mgr, vma);
            vma_free(vma);
        } else if (!(vma->vm_end <= start || vma->vm_start >= end)) {
            // 部分重叠
            if (vma->vm_start < start && vma->vm_end > end) {
                // 跨越整个范围
                vma_split(mgr, vma, end);
                vma_split(mgr, vma, start);
                vma_t *middle = vma->vm_next;
                vma_remove(mgr, middle);
                vma_free(middle);
            } else if (vma->vm_start < start) {
                // 截断末尾
                mgr->vm_used -= vma->vm_end - start;
                vma->vm_end = start;
            } else if (vma->vm_end > end) {
                // 截断开头
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

// 清理管理器（遍历红黑树更高效）
void vma_manager_exit_cleanup(vma_manager_t *mgr) {
    if (!mgr || !mgr->initialized)
        return;

    vma_t *vma = mgr->vma_list;
    vma_t *next;

    while (vma) {
        next = vma->vm_next;

        // 从红黑树删除
        rb_erase(&vma->vm_rb, &mgr->vma_tree);

        mgr->vm_used -= vma->vm_end - vma->vm_start;
        vma_free(vma);

        vma = next;
    }

    mgr->vma_list = NULL;
    mgr->vma_tree.rb_node = NULL;
    mgr->vm_total = 0;
    mgr->vm_used = 0;
}

// 深度拷贝单个VMA
vma_t *vma_copy(vma_t *src) {
    if (!src)
        return NULL;

    vma_t *dst = vma_alloc();
    if (!dst)
        return NULL;

    dst->vm_start = src->vm_start;
    dst->vm_end = src->vm_end;
    dst->vm_flags = src->vm_flags;
    dst->vm_type = src->vm_type;
    dst->node = src->node;
    if (dst->node)
        dst->node->refcount++;
    dst->vm_offset = src->vm_offset;
    dst->shm_id = src->shm_id;

    if (src->vm_name) {
        dst->vm_name = strdup(src->vm_name);
    } else {
        dst->vm_name = NULL;
    }

    dst->vm_next = NULL;
    dst->vm_prev = NULL;

    return dst;
}

// 深度拷贝VMA管理器
int vma_manager_copy(vma_manager_t *dst, vma_manager_t *src) {
    if (!dst || !src)
        return -1;

    memset(dst, 0, sizeof(vma_manager_t));

    if (!src->initialized) {
        return 0;
    }

    dst->vma_list = NULL;
    dst->vma_tree.rb_node = NULL;
    dst->vm_total = src->vm_total;
    dst->vm_used = 0;

    vma_t *src_vma = src->vma_list;

    while (src_vma) {
        vma_t *dst_vma = vma_copy(src_vma);
        if (!dst_vma) {
            vma_manager_exit_cleanup(dst);
            return -1;
        }

        // 使用vma_insert同时维护链表和红黑树
        if (vma_insert(dst, dst_vma) < 0) {
            vma_free(dst_vma);
            vma_manager_exit_cleanup(dst);
            return -1;
        }

        src_vma = src_vma->vm_next;
    }

    dst->initialized = src->initialized;

    return 0;
}

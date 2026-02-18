#include <fs/vfs/vfs.h>
#include <mm/vma.h>

void *malloc(size_t size);
void free(void *ptr);

static inline unsigned long vma_len(const vma_t *vma) {
    return vma->vm_end - vma->vm_start;
}

static vma_t *vma_copy(vma_t *src);

vma_t *vma_alloc(void) {
    vma_t *vma = (vma_t *)malloc(sizeof(vma_t));
    if (!vma)
        return NULL;

    memset(vma, 0, sizeof(vma_t));
    vma->node = NULL;
    vma->shm = NULL;
    vma->shm_id = -1;
    vma->vm_rb.rb_parent_color = 0;
    vma->vm_rb.rb_left = NULL;
    vma->vm_rb.rb_right = NULL;
    return vma;
}

void vma_free(vma_t *vma) {
    if (!vma)
        return;

    if (vma->node)
        vma->node->refcount--;
    if (vma->vm_name)
        free(vma->vm_name);
    free(vma);
}

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

vma_t *vma_find_intersection(vma_manager_t *mgr, uint64_t start, uint64_t end) {
    if (start >= end)
        return NULL;

    rb_node_t *node = rb_first(&mgr->vma_tree);
    while (node) {
        vma_t *vma = rb_entry(node, vma_t, vm_rb);
        if (vma->vm_start >= end)
            break;
        if (vma->vm_end > start)
            return vma;
        node = rb_next(node);
    }

    return NULL;
}

int vma_insert(vma_manager_t *mgr, vma_t *new_vma) {
    if (!new_vma)
        return -1;
    if (new_vma->vm_start >= new_vma->vm_end)
        return -1;

    rb_node_t **link = &mgr->vma_tree.rb_node;
    rb_node_t *parent = NULL;

    while (*link) {
        parent = *link;
        vma_t *vma = rb_entry(parent, vma_t, vm_rb);

        if (new_vma->vm_end <= vma->vm_start) {
            link = &(*link)->rb_left;
        } else if (new_vma->vm_start >= vma->vm_end) {
            link = &(*link)->rb_right;
        } else {
            return -1;
        }
    }

    rb_node_t *node = &new_vma->vm_rb;
    node->rb_parent_color = (uint64_t)parent;
    node->rb_left = NULL;
    node->rb_right = NULL;
    *link = node;
    rb_insert_color(node, &mgr->vma_tree);

    mgr->vm_used += vma_len(new_vma);
    return 0;
}

int vma_remove(vma_manager_t *mgr, vma_t *vma) {
    if (!vma)
        return -1;

    rb_erase(&vma->vm_rb, &mgr->vma_tree);
    mgr->vm_used -= vma_len(vma);
    return 0;
}

int vma_split(vma_manager_t *mgr, vma_t *vma, uint64_t addr) {
    if (!vma || addr <= vma->vm_start || addr >= vma->vm_end)
        return -1;

    vma_t *new_vma = vma_alloc();
    if (!new_vma)
        return -1;

    uint64_t old_end = vma->vm_end;

    new_vma->vm_start = addr;
    new_vma->vm_end = old_end;
    new_vma->vm_flags = vma->vm_flags;
    new_vma->vm_type = vma->vm_type;
    new_vma->node = vma->node;
    if (new_vma->node)
        new_vma->node->refcount++;
    new_vma->shm = vma->shm;
    new_vma->shm_id = vma->shm_id;
    new_vma->vm_offset = vma->vm_offset;

    if (vma->vm_type == VMA_TYPE_FILE)
        new_vma->vm_offset += addr - vma->vm_start;

    if (vma->vm_name) {
        new_vma->vm_name = strdup(vma->vm_name);
        if (!new_vma->vm_name) {
            if (new_vma->node)
                new_vma->node->refcount--;
            free(new_vma);
            return -1;
        }
    }

    vma->vm_end = addr;
    mgr->vm_used -= old_end - addr;

    if (vma_insert(mgr, new_vma) != 0) {
        vma->vm_end = old_end;
        mgr->vm_used += old_end - addr;
        vma_free(new_vma);
        return -1;
    }

    return 0;
}

int vma_merge(vma_manager_t *mgr, vma_t *vma1, vma_t *vma2) {
    if (!vma1 || !vma2 || vma1->vm_end != vma2->vm_start)
        return -1;

    if (vma1->vm_flags != vma2->vm_flags || vma1->vm_type != vma2->vm_type ||
        vma1->node != vma2->node || vma1->shm != vma2->shm ||
        vma1->vm_offset + (vma1->vm_end - vma1->vm_start) != vma2->vm_offset) {
        return -1;
    }

    if (!vma1->vm_name && vma2->vm_name) {
        vma1->vm_name = vma2->vm_name;
        vma2->vm_name = NULL;
    }

    vma1->vm_end = vma2->vm_end;
    rb_erase(&vma2->vm_rb, &mgr->vma_tree);
    vma_free(vma2);
    return 0;
}

int vma_merge_ex(vma_manager_t *mgr, vma_t *vma1, vma_t *vma2) {
    return vma_merge(mgr, vma1, vma2);
}

int vma_unmap_range(vma_manager_t *mgr, uintptr_t start, uintptr_t end) {
    if (!mgr || start >= end)
        return -1;

    while (true) {
        vma_t *vma = vma_find_intersection(mgr, start, end);
        if (!vma)
            break;

        if (vma->vm_start < start) {
            if (vma_split(mgr, vma, start) != 0)
                return -1;
            continue;
        }

        if (vma->vm_end > end) {
            if (vma_split(mgr, vma, end) != 0)
                return -1;
        }

        vma_remove(mgr, vma);
        vma_free(vma);
    }

    return 0;
}

void vma_manager_exit_cleanup(vma_manager_t *mgr) {
    if (!mgr || !mgr->initialized)
        return;

    rb_node_t *node;
    while ((node = rb_first(&mgr->vma_tree)) != NULL) {
        vma_t *vma = rb_entry(node, vma_t, vm_rb);
        vma_remove(mgr, vma);
        vma_free(vma);
    }

    mgr->vma_tree.rb_node = NULL;
    mgr->vm_used = 0;
}

static vma_t *vma_copy(vma_t *src) {
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
    dst->shm = src->shm;
    dst->vm_offset = src->vm_offset;
    dst->shm_id = src->shm_id;

    if (src->vm_name) {
        dst->vm_name = strdup(src->vm_name);
        if (!dst->vm_name) {
            vma_free(dst);
            return NULL;
        }
    }

    return dst;
}

int vma_manager_copy(vma_manager_t *dst, vma_manager_t *src) {
    if (!dst || !src)
        return -1;

    memset(dst, 0, sizeof(vma_manager_t));
    if (!src->initialized)
        return 0;

    dst->vma_tree.rb_node = NULL;
    dst->vm_used = 0;

    rb_node_t *node = rb_first(&src->vma_tree);
    while (node) {
        vma_t *src_vma = rb_entry(node, vma_t, vm_rb);
        node = rb_next(node);

        vma_t *dst_vma = vma_copy(src_vma);
        if (!dst_vma) {
            vma_manager_exit_cleanup(dst);
            return -1;
        }

        if (vma_insert(dst, dst_vma) != 0) {
            vma_free(dst_vma);
            vma_manager_exit_cleanup(dst);
            return -1;
        }
    }

    dst->initialized = src->initialized;
    return 0;
}

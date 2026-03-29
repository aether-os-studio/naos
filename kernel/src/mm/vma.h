#pragma once

#include <libs/klibc.h>
#include <libs/rbtree.h>
#include <mm/shm.h>

// VMA标志定义
#define VMA_READ 0x1
#define VMA_WRITE 0x2
#define VMA_EXEC 0x4
#define VMA_SHARED 0x8
#define VMA_ANON 0x10
#define VMA_SHM 0x20
#define VMA_DEVICE 0x40
#define VMA_STACK 0x80
#define VMA_GUARD 0x100
#define VMA_GUARD_SAVED_SHIFT 9
#define VMA_GUARD_SAVED_MASK (0x7UL << VMA_GUARD_SAVED_SHIFT)

// VMA类型
typedef enum {
    VMA_TYPE_ANON, // 匿名映射
    VMA_TYPE_FILE, // 文件映射
    VMA_TYPE_SHM   // 共享内存
} vma_type_t;

struct vfs_node;

// VMA结构体
typedef struct vma {
    unsigned long vm_start; // 起始地址
    unsigned long vm_end;   // 结束地址
    unsigned long vm_flags; // 权限标志
    vma_type_t vm_type;     // VMA类型
    struct vfs_node *node;  // 文件描述符
    shm_t *shm;             // 共享内存指针
    int64_t vm_offset;      // 文件偏移量
    uint64_t vm_file_len;   // 从 vm_start 起实际由文件提供的字节数
    uint64_t vm_file_flags; // 打开文件时的 fd flags
    int shm_id;             // 共享内存ID
    char *vm_name;          // VMA名
    rb_node_t vm_rb;        // 红黑树节点
} vma_t;

// VMA管理器
typedef struct vma_manager {
    rb_root_t vma_tree;    // 红黑树根
    unsigned long vm_used; // 已使用虚拟内存
    spinlock_t lock;
    bool initialized;
} vma_manager_t;

// 函数声明
void vma_manager_init(vma_manager_t *mgr, bool initialized);
vma_t *vma_alloc(void);
void vma_free(vma_t *vma);
vma_t *vma_find(vma_manager_t *mgr, unsigned long addr);
vma_t *vma_find_intersection(vma_manager_t *mgr, unsigned long start,
                             unsigned long end);
int vma_insert(vma_manager_t *mgr, vma_t *vma);
int vma_remove(vma_manager_t *mgr, vma_t *vma);
int vma_split(vma_manager_t *mgr, vma_t *vma, unsigned long addr);
int vma_merge(vma_manager_t *mgr, vma_t *vma1, vma_t *vma2);
void vma_try_merge_around(vma_manager_t *mgr, vma_t **vma);
int vma_unmap_range(vma_manager_t *mgr, uintptr_t start, uintptr_t end);
void vma_manager_exit_cleanup(vma_manager_t *mgr);
int vma_manager_copy(vma_manager_t *dst, vma_manager_t *src);

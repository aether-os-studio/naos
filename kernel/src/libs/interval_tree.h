#pragma once

#include <libs/klibc.h>

struct interval_tree_node
{
    uint64_t start;    // 区域起始地址
    uint64_t last;     // 区域结束地址 (包含)
    uint64_t max_last; // 子树最大结束地址
    struct interval_tree_node *left;
    struct interval_tree_node *right;
    struct interval_tree_node *parent;
    int color; // 红黑树颜色标记
};

struct mmap_region
{
    struct interval_tree_node it_node;
    int prot;
    int flags;
};

// 区间树操作函数
void interval_tree_insert(struct mmap_region *region, struct interval_tree_node **root);
void interval_tree_remove(struct mmap_region *region, struct interval_tree_node **root);
struct mmap_region *interval_tree_search(struct interval_tree_node *root, uint64_t start, uint64_t last);
struct mmap_region *interval_tree_iter_first(struct interval_tree_node *root, uint64_t start, uint64_t last);
struct mmap_region *interval_tree_iter_next(struct mmap_region *region);

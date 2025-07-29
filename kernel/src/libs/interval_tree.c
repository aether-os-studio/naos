#include <libs/interval_tree.h>

#define IT_RED 0
#define IT_BLACK 1

static void __rotate_left(struct interval_tree_node *node, struct interval_tree_node **root)
{
    struct interval_tree_node *right = node->right;
    if ((node->right = right->left))
        right->left->parent = node;

    right->parent = node->parent;

    if (!node->parent)
        *root = right;
    else if (node == node->parent->left)
        node->parent->left = right;
    else
        node->parent->right = right;

    right->left = node;
    node->parent = right;
}

static void __rotate_right(struct interval_tree_node *node, struct interval_tree_node **root)
{
    struct interval_tree_node *left = node->left;
    if ((node->left = left->right))
        left->right->parent = node;

    left->parent = node->parent;

    if (!node->parent)
        *root = left;
    else if (node == node->parent->right)
        node->parent->right = left;
    else
        node->parent->left = left;

    left->right = node;
    node->parent = left;
}

static void interval_tree_fixup(struct interval_tree_node **root, struct interval_tree_node *node)
{
    while (node != *root && node->parent->color == IT_RED)
    {
        struct interval_tree_node *parent = node->parent;
        struct interval_tree_node *grandpa = parent->parent;
        struct interval_tree_node *uncle;

        if (parent == grandpa->left)
        {
            uncle = grandpa->right;
            if (uncle && uncle->color == IT_RED)
            {
                // Case 1: 叔叔节点是红色
                parent->color = IT_BLACK;
                uncle->color = IT_BLACK;
                grandpa->color = IT_RED;
                node = grandpa;
            }
            else
            {
                // Case 2/3: 叔叔节点是黑色
                if (node == parent->right)
                {
                    // Case 2: 左旋转换为Case3
                    node = parent;
                    __rotate_left(node, root);
                    parent = node->parent;
                }
                // Case 3: 右旋并变色
                parent->color = IT_BLACK;
                grandpa->color = IT_RED;
                __rotate_right(grandpa, root);
            }
        }
        else
        {
            // 对称处理右子树情况
            uncle = grandpa->left;
            if (uncle && uncle->color == IT_RED)
            {
                parent->color = IT_BLACK;
                uncle->color = IT_BLACK;
                grandpa->color = IT_RED;
                node = grandpa;
            }
            else
            {
                if (node == parent->left)
                {
                    node = parent;
                    __rotate_right(node, root);
                    parent = node->parent;
                }
                parent->color = IT_BLACK;
                grandpa->color = IT_RED;
                __rotate_left(grandpa, root);
            }
        }
    }
    (*root)->color = IT_BLACK;
}

void interval_tree_insert(struct mmap_region *region, struct interval_tree_node **root)
{
    struct interval_tree_node *parent = NULL;
    struct interval_tree_node **cur = root;

    region->it_node.max_last = region->it_node.last;
    region->it_node.color = IT_RED;

    // 标准BST插入
    while (*cur)
    {
        parent = *cur;
        parent->max_last = MAX(parent->max_last, region->it_node.last);

        if (region->it_node.start < parent->start)
            cur = &parent->left;
        else
            cur = &parent->right;
    }

    *cur = &region->it_node;
    region->it_node.parent = parent;

    // 更新max_last向上传播
    for (struct interval_tree_node *p = parent; p; p = p->parent)
        p->max_last = MAX(p->max_last, region->it_node.last);

    interval_tree_fixup(root, &region->it_node);
}

static void __update_max_upwards(struct interval_tree_node *node)
{
    while (node)
    {
        uint64_t max = node->last;
        if (node->left && node->left->max_last > max)
            max = node->left->max_last;
        if (node->right && node->right->max_last > max)
            max = node->right->max_last;

        if (node->max_last == max)
            break;

        node->max_last = max;
        node = node->parent;
    }
}

static void __interval_tree_remove_fixup(struct interval_tree_node **root, struct interval_tree_node *node, struct interval_tree_node *parent)
{
    while (node != *root && (!node || node->color == IT_BLACK))
    {
        if (node == parent->left)
        {
            struct interval_tree_node *sibling = parent->right;
            if (sibling->color == IT_RED)
            {
                // Case 1: 兄弟节点是红色
                sibling->color = IT_BLACK;
                parent->color = IT_RED;
                __rotate_left(parent, root);
                sibling = parent->right;
            }
            if ((!sibling->left || sibling->left->color == IT_BLACK) &&
                (!sibling->right || sibling->right->color == IT_BLACK))
            {
                // Case 2: 兄弟节点子节点都是黑色
                sibling->color = IT_RED;
                node = parent;
                parent = node->parent;
            }
            else
            {
                if (!sibling->right || sibling->right->color == IT_BLACK)
                {
                    // Case 3: 兄弟右子节点是黑色
                    sibling->left->color = IT_BLACK;
                    sibling->color = IT_RED;
                    __rotate_right(sibling, root);
                    sibling = parent->right;
                }
                // Case 4: 兄弟右子节点是红色
                sibling->color = parent->color;
                parent->color = IT_BLACK;
                sibling->right->color = IT_BLACK;
                __rotate_left(parent, root);
                node = *root;
                break;
            }
        }
        else
        {
            // 对称处理右子树情况
            struct interval_tree_node *sibling = parent->left;
            if (sibling && sibling->color == IT_RED)
            {
                // Case 1镜像：兄弟节点是红色
                sibling->color = IT_BLACK;
                parent->color = IT_RED;
                __rotate_right(parent, root);
                sibling = parent->left;
            }
            if ((!sibling->right || sibling->right->color == IT_BLACK) &&
                (!sibling->left || sibling->left->color == IT_BLACK))
            {
                // Case 2镜像：兄弟子节点都是黑色
                sibling->color = IT_RED;
                node = parent;
                parent = node->parent;
            }
            else
            {
                if (!sibling->left || sibling->left->color == IT_BLACK)
                {
                    // Case 3镜像：兄弟左子节点是黑色
                    sibling->right->color = IT_BLACK;
                    sibling->color = IT_RED;
                    __rotate_left(sibling, root);
                    sibling = parent->left;
                }
                // Case 4镜像：兄弟左子节点是红色
                sibling->color = parent->color;
                parent->color = IT_BLACK;
                sibling->left->color = IT_BLACK;
                __rotate_right(parent, root);
                node = *root;
                break;
            }
        }
    }
    if (node)
        node->color = IT_BLACK;
}

void interval_tree_remove(struct mmap_region *region, struct interval_tree_node **root)
{
    struct interval_tree_node *node = &region->it_node;
    struct interval_tree_node *child, *parent;
    int color;

    if (!node->left)
        child = node->right;
    else if (!node->right)
        child = node->left;
    else
    {
        // 找到后继节点
        struct interval_tree_node *old = node;
        node = node->right;
        while (node->left)
            node = node->left;

        // 更新max_last
        __update_max_upwards(old->parent);

        child = node->right;
        parent = node->parent;
        color = node->color;

        if (child)
            child->parent = parent;
        if (parent == old)
            parent->right = child;
        else
            parent->left = child;

        node->parent = old->parent;
        node->color = old->color;
        node->left = old->left;
        node->right = old->right;

        if (old->parent)
        {
            if (old == old->parent->left)
                old->parent->left = node;
            else
                old->parent->right = node;
        }
        else
        {
            *root = node;
        }

        old->left->parent = node;
        if (old->right)
            old->right->parent = node;

        goto fixup;
    }

    parent = node->parent;
    color = node->color;

    if (child)
        child->parent = parent;

    if (parent)
    {
        if (node == parent->left)
            parent->left = child;
        else
            parent->right = child;

        // 更新max_last
        __update_max_upwards(parent);
    }
    else
    {
        *root = child;
    }

fixup:
    if (color == IT_BLACK)
        __interval_tree_remove_fixup(root, child, parent);
}

struct mmap_region *interval_tree_search(struct interval_tree_node *root, uint64_t start, uint64_t last)
{
    struct interval_tree_node *node = root;

    while (node)
    {
        if (node->start <= last && start <= node->last)
            return container_of(node, struct mmap_region, it_node);

        if (node->left && node->left->max_last >= start)
            node = node->left;
        else
            node = node->right;
    }
    return NULL;
}

struct mmap_region *interval_tree_iter_first(struct interval_tree_node *root, uint64_t start, uint64_t last)
{
    struct interval_tree_node *node = root;

    while (node)
    {
        if (node->left && node->left->max_last >= start)
        {
            node = node->left;
        }
        else if (node->start <= last && start <= node->last)
        {
            return container_of(node, struct mmap_region, it_node);
        }
        else
        {
            node = node->right;
        }
    }
    return NULL;
}

struct mmap_region *interval_tree_iter_next(struct mmap_region *region)
{
    struct interval_tree_node *node = &region->it_node;

    // 如果有右子树，返回右子树的最左节点
    if (node->right)
    {
        node = node->right;
        while (node->left)
            node = node->left;
        return container_of(node, struct mmap_region, it_node);
    }

    // 向上查找第一个右祖先
    struct interval_tree_node *parent;
    while ((parent = node->parent))
    {
        if (node == parent->left)
        {
            return container_of(parent, struct mmap_region, it_node);
        }
        node = parent;
    }
    return NULL;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_RBTREE_H_INCLUDED_
#define _NGX_RBTREE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef ngx_uint_t  ngx_rbtree_key_t;
typedef ngx_int_t   ngx_rbtree_key_int_t;


typedef struct ngx_rbtree_node_s  ngx_rbtree_node_t;

// struct ngx_rbtree_node_s
// 红黑树节点结构 {{{
struct ngx_rbtree_node_s {
    ngx_rbtree_key_t       key;		// 红黑树节点键值
    ngx_rbtree_node_t     *left;	// 左孩子
    ngx_rbtree_node_t     *right;	// 右孩子
    ngx_rbtree_node_t     *parent;	// 父节点
    u_char                 color;	// 颜色，0 表示黑色，1 表示红色
    u_char                 data;	// 数据，很少被使用
}; // }}}


typedef struct ngx_rbtree_s  ngx_rbtree_t;

typedef void (*ngx_rbtree_insert_pt) (ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

// struct ngx_rbtree_s
// 红黑树描述结构 {{{
struct ngx_rbtree_s {
    ngx_rbtree_node_t     *root;		// 根节点
    ngx_rbtree_node_t     *sentinel;	// 哨兵节点（空节点）
    ngx_rbtree_insert_pt   insert;		// 节点插入前回调函数
}; // }}}


#define ngx_rbtree_init(tree, s, i)                                           \
    ngx_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i


void ngx_rbtree_insert(ngx_thread_volatile ngx_rbtree_t *tree,
    ngx_rbtree_node_t *node);
void ngx_rbtree_delete(ngx_thread_volatile ngx_rbtree_t *tree,
    ngx_rbtree_node_t *node);
void ngx_rbtree_insert_value(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
void ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);


// 红黑树节点着色
#define ngx_rbt_red(node)               ((node)->color = 1)
#define ngx_rbt_black(node)             ((node)->color = 0)

// 判断红黑树节点颜色
#define ngx_rbt_is_red(node)            ((node)->color)
#define ngx_rbt_is_black(node)          (!ngx_rbt_is_red(node))

// 复制节点颜色
#define ngx_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */

// 将节点设为哨兵节点
#define ngx_rbtree_sentinel_init(node)  ngx_rbt_black(node)


// static ngx_inline ngx_rbtree_node_t *
// ngx_rbtree_min(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
// 获取红黑树中最小元素（最左叶子） {{{
static ngx_inline ngx_rbtree_node_t *
ngx_rbtree_min(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
} // }}}


#endif /* _NGX_RBTREE_H_INCLUDED_ */

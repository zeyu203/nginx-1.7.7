
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

// struct ngx_list_part_s
// 链表节点 {{{
struct ngx_list_part_s {
    void             *elts;		// 节点数组
    ngx_uint_t        nelts;	// 节点元素个数
    ngx_list_part_t  *next;		// 下一节点
}; // }}}


// typedef struct ngx_list_t
// nginx 链表结构(以数组为节点) {{{
typedef struct {
    ngx_list_part_t  *last;		// 最后一个节点
    ngx_list_part_t   part;		// 首个节点
    size_t            size;		// 单个节点占内存大小
    ngx_uint_t        nalloc;	// 每个节点中数组的容量
    ngx_pool_t       *pool;		// 为链表分配的内存池
} ngx_list_t; // }}}


ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

// 链表初始化 {{{
static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
} // }}}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */

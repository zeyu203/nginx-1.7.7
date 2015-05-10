
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


// 内存析构函数
typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

// struct ngx_pool_cleanup_s
// 内存清理结构 {{{
struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;	// 析构函数
    void                 *data;		// 析构函数参数
    ngx_pool_cleanup_t   *next;		// 下一析构函数
}; // }}}


typedef struct ngx_pool_large_s  ngx_pool_large_t;

// struct ngx_pool_large_s
// 大块内存结构 {{{
struct ngx_pool_large_s {
    ngx_pool_large_t     *next;
    void                 *alloc;
}; // }}}


<<<<<<< HEAD
// typedef struct
=======
// struct ngx_pool_data_t
>>>>>>> origin/master
// 内存池数据结构 {{{
typedef struct {
    u_char               *last;		// 当前内存分配的结束位置
    u_char               *end;		// 内存池的结束位置
    ngx_pool_t           *next;		// 下一内存池
    ngx_uint_t            failed;	// 内存分配失败计数
} ngx_pool_data_t; // }}}


// struct ngx_pool_s
// 内存池结构 {{{
struct ngx_pool_s {
    ngx_pool_data_t       d;		// 内存池数据块
    size_t                max;		// 数据块大小，小块内存最大值
    ngx_pool_t           *current;	// 指向内存可用数据块
    ngx_chain_t          *chain;	// 指向缓存链
    ngx_pool_large_t     *large;	// 指向大块内存分配
    ngx_pool_cleanup_t   *cleanup;	// 析构函数
    ngx_log_t            *log;		// 内存分配相关的log
}; // }}}


// struct ngx_pool_cleanup_file_t
// 内存池当前打开文件 {{{
typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t; // }}}


void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_calloc(size_t size, ngx_log_t *log);

ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */

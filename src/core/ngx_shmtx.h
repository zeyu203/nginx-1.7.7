
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_atomic_t   lock;
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t   wait;
#endif
} ngx_shmtx_sh_t;


// struct ngx_shmtx_t
// nginx 锁结构 {{{
typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)		// 是否支持原子操作
    ngx_atomic_t  *lock;
#if (NGX_HAVE_POSIX_SEM)		// 是否支持信号量
    ngx_atomic_t  *wait;
    ngx_uint_t     semaphore;	// 判断是否使用信号量
    sem_t          sem;			// 信号量
#endif
#else							// 不支持原子操作则使用文件操作
    ngx_fd_t       fd;
    u_char        *name;
#endif
    ngx_uint_t     spin;		// 自旋锁标识
} ngx_shmtx_t; // }}}


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr,
    u_char *name);
void ngx_shmtx_destroy(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);


#endif /* _NGX_SHMTX_H_INCLUDED_ */

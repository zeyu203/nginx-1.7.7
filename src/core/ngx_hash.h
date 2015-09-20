
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// struct ngx_hash_elt_t
// 哈希桶结构 {{{
typedef struct {
    void             *value;		// 为null代表该元素为当前bucket最尾元素
    u_short           len;			// key 长度
    u_char            name[1];		// key 的值
} ngx_hash_elt_t; // }}}


// struct ngx_hash_t
// 哈希表结构 {{{
typedef struct {
    ngx_hash_elt_t  **buckets;		// 哈希桶数组
    ngx_uint_t        size;			// buckets 数组长度
} ngx_hash_t; // }}}


// struct ngx_hash_wildcard_t
// 支持通配符的散列表结构 {{{
typedef struct {
    ngx_hash_t        hash;
    void             *value;
} ngx_hash_wildcard_t; // }}}


// struct ngx_hash_key_t
// 哈希表索引结构 {{{
typedef struct {
    ngx_str_t         key;			// 索引
    ngx_uint_t        key_hash;		// 索引指向的哈希值
    void             *value;		// 内容
} ngx_hash_key_t; // }}}


// 哈希表创建时指定的哈希函数
typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);


// struct ngx_hash_combined_t
// 通配符散列结构 {{{
typedef struct {
    ngx_hash_t            hash;
    ngx_hash_wildcard_t  *wc_head;
    ngx_hash_wildcard_t  *wc_tail;
} ngx_hash_combined_t; // }}}


// struct ngx_hash_init_t
// 哈希表创建限制结构 {{{
typedef struct {
    ngx_hash_t       *hash;			// 用于管理哈希表的结构体
    ngx_hash_key_pt   key;			// 哈希函数

    ngx_uint_t        max_size;		// 哈希桶个数最大值
    ngx_uint_t        bucket_size;	// 哈希桶大小

    char             *name;			// 哈希表名字
    ngx_pool_t       *pool;			// 哈希表所使用的内存池
    ngx_pool_t       *temp_pool;	// 估算时临时使用的内存池
} ngx_hash_init_t; // }}}


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


// struct ngx_hash_keys_arrays_t
// 用于初始化通配符散列结构的数据结构 {{{
typedef struct {
	// 下面 6 个数组每个数组的元素个数
    ngx_uint_t        hsize;

	// 用于分配空间的内存池结构
    ngx_pool_t       *pool;
    ngx_pool_t       *temp_pool;

	// 存储完整匹配关键字的 ngx_str_t 结构动态数组
    ngx_array_t       keys;
	// 存储完整匹配关键字的 ngx_hash_key_t 结构动态数组
    ngx_array_t      *keys_hash;

	// 存储前缀匹配关键字的 ngx_str_t 结构动态数组
    ngx_array_t       dns_wc_head;
	// 存储前缀匹配关键字的 ngx_hash_key_t 结构动态数组
    ngx_array_t      *dns_wc_head_hash;

	// 存储后缀匹配关键字的 ngx_str_t 结构动态数组
    ngx_array_t       dns_wc_tail;
	// 存储后缀匹配关键字的 ngx_hash_key_t 结构动态数组
    ngx_array_t      *dns_wc_tail_hash;
} ngx_hash_keys_arrays_t; // }}}


typedef struct {
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;


void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000400
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00000800
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00001000
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200


// struct ngx_http_upstream_state_t
// upstream 状态描述结构 {{{
typedef struct {
    ngx_msec_t                       bl_time;
    ngx_uint_t                       bl_state;

    ngx_uint_t                       status;
    time_t                           response_sec;
    ngx_uint_t                       response_msec;
    off_t                            response_length;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t; // }}}


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
    void                            *data;
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_str_t                        name;
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;

    unsigned                         down:1;
    unsigned                         backup:1;
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020


// struct ngx_http_upstream_srv_conf_s
// upstream 上游服务器配置描述结构 {{{
struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    in_port_t                        default_port;
    ngx_uint_t                       no_port;  /* unsigned no_port:1 */
}; // }}}


typedef struct {
    ngx_addr_t                      *addr;
    ngx_http_complex_value_t        *value;
} ngx_http_upstream_local_t;


// struct ngx_http_upstream_conf_t
// 配置参数描述结构 {{{
typedef struct {
	// 上游服务器配置
	// 当ngx_http_upstream_t中没有实现resolved成员时，这个变量才会生效
    ngx_http_upstream_srv_conf_t    *upstream;

	// 建立 TCP 连接超时
    ngx_msec_t                       connect_timeout;
	// 发送请求超时
    ngx_msec_t                       send_timeout;
	// 读取请求超时
    ngx_msec_t                       read_timeout;
    ngx_msec_t                       timeout;
    ngx_msec_t                       next_upstream_timeout;

	// TCP的SO_SNOLOWAT选项，表示发送缓冲区的下限
    size_t                           send_lowat;
	// 接收头部的缓冲区大小（ngx_http_upstream_t中的buffer缓冲区）
    size_t                           buffer_size;
    size_t                           limit_rate;

	// 当buffering=1，并且向下游转发响应时生效
    size_t                           busy_buffers_size;
	// 临时文件大小
	// buffering=1，若上游速度快于下游，则可能把上游的响应存在临时文件中
    size_t                           max_temp_file_size;
	// 一次写入临时文件的字符流最大长度
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

	// 以缓存响应的方式转发上游服务器的包体时所用的内存大小
    ngx_bufs_t                       bufs;

	// 针对ngx_http_upstream_t中的header_in成员
	// ignore_headers可根据位操作跳过一些头部
    ngx_uint_t                       ignore_headers;
	// 出错选择的下一个上游服务器
    ngx_uint_t                       next_upstream;
	// 创建的目录、文件的权限
    ngx_uint_t                       store_access;
    ngx_uint_t                       next_upstream_tries;
	// 决定转发响应方式的标志位
	// 1：认为上游快于下游，会尽量地在内存或者磁盘中缓存来自上游的响应
	// 0：仅开辟一块固定大小的内存块作为缓存来转发响应
    ngx_flag_t                       buffering;
    ngx_flag_t                       pass_request_headers;
    ngx_flag_t                       pass_request_body;

	// 如果为 1，上游服务器交互时不检查是否与下游客户端断开连接，继续执行交互内容
    ngx_flag_t                       ignore_client_abort;
	// 截取错误码，查看是否有对应可以返回的语义
    ngx_flag_t                       intercept_errors;
	// 是否复用临时文件中已经使用过的空间
    ngx_flag_t                       cyclic_temp_file;
    ngx_flag_t                       force_ranges;

	// 存放临时文件的路径
    ngx_path_t                      *temp_path;

	// 根据ngx_http_upstream_hide_headers_hash函数构造出的需要隐藏的HTTP头部散列表
    ngx_hash_t                       hide_headers_hash;
	// 不希望转发的头部
    ngx_array_t                     *hide_headers;
	// 明确希望转发的头部
    ngx_array_t                     *pass_headers;

	// 连接上游服务器时的本机地址
    ngx_http_upstream_local_t       *local;

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache;

    ngx_uint_t                       cache_min_uses;
    ngx_uint_t                       cache_use_stale;
    ngx_uint_t                       cache_methods;

    ngx_flag_t                       cache_lock;
    ngx_msec_t                       cache_lock_timeout;

    ngx_flag_t                       cache_revalidate;

    ngx_array_t                     *cache_valid;
    ngx_array_t                     *cache_bypass;
    ngx_array_t                     *no_cache;
#endif

	// 存放路径的长度
    ngx_array_t                     *store_lengths;
	// 存储路径
    ngx_array_t                     *store_values;

    signed                           store:2;
	// 是否捕获到404直接转发
    unsigned                         intercept_404:1;
	// 是否动态决定buffering标志位
	// 根据 ngx_http_upstream_t 的 headers_in 中的
	// X-Accel-Buffering（yes/no)的值来确定buffering 
    unsigned                         change_buffering:1;

#if (NGX_HTTP_SSL)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;

    ngx_http_complex_value_t        *ssl_name;
    ngx_flag_t                       ssl_server_name;
    ngx_flag_t                       ssl_verify;
#endif

	// upstream 模块名称，仅用于日志记录
    ngx_str_t                        module;
} ngx_http_upstream_conf_t; // }}}


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;
    ngx_table_elt_t                 *vary;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    ngx_array_t                      cache_control;
    ngx_array_t                      cookies;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} ngx_http_upstream_headers_in_t;


// struct ngx_http_upstream_resolved_t
// 上游主机描述结构 {{{
typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    ngx_addr_t                      *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t; // }}}


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


// struct ngx_http_upstream_s
// nginx upstream 机制描述结构 {{{
struct ngx_http_upstream_s {
	// 读事件回调函数
    ngx_http_upstream_handler_pt     read_event_handler;
	// 写事件回调函数
    ngx_http_upstream_handler_pt     write_event_handler;

	// 主动向上游服务器发起的连接
    ngx_peer_connection_t            peer;

    ngx_event_pipe_t                *pipe;

	// 发给上游服务器的请求
    ngx_chain_t                     *request_bufs;

	// 向下游发送响应的方式
    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

	// 配置参数描述结构
    ngx_http_upstream_conf_t        *conf;

	// 存储响应头部
    ngx_http_upstream_headers_in_t   headers_in;

	// 用于解析主机域名
    ngx_http_upstream_resolved_t    *resolved;

    ngx_buf_t                        from_client;

	// 接收上游服务器响应的缓冲区
    ngx_buf_t                        buffer;
	// 上游响应包体长度
    off_t                            length;

	// 当不需要转发包体，且使用默认的input_filter方法处理包体时
	// out_bufs指向响应包体
	// 当需要转发包体到下游时
	// 指向上一次下游转发响应到现在这段时间内接收自上游的缓存响应
    ngx_chain_t                     *out_bufs;
	// 当需要转发响应包体到下游时，它表示上一次向下游转发响应时没有发送完的内容
    ngx_chain_t                     *busy_bufs;
	// 用于回收out_bufs中已经发送给下游的ngx_buf_t结构体
    ngx_chain_t                     *free_bufs;

	// 处理包体前的初始化方法
    ngx_int_t                      (*input_filter_init)(void *data);
	// 处理包体的方法
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
	// 上述两个函数的参数
    void                            *input_filter_ctx;

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
	// HTTP模块实现，用于构造发往上游服务器的请求的函数
    ngx_int_t                      (*create_request)(ngx_http_request_t *r);
	// 与上游服务器通信失败后，重新发起连接
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);
	// 解析上游服务器返回响应的包头
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);
	// 请求中止时调用
    void                           (*abort_request)(ngx_http_request_t *r);
	// 请求结束时调用
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);
	// 可由HTTP模块实现的重定向函数
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h);

	// 全局超时
    ngx_msec_t                       timeout;

	// upstream 状态描述结构，上游响应的错误码、包体长度等信息
    ngx_http_upstream_state_t       *state;

    ngx_str_t                        method;
    ngx_str_t                        schema;
    ngx_str_t                        uri;

#if (NGX_HTTP_SSL)
    ngx_str_t                        ssl_name;
#endif

    ngx_http_cleanup_pt             *cleanup;

	// 是否指定缓存路径
    unsigned                         store:1;
	// 是否启用文件缓存
    unsigned                         cacheable:1;
    unsigned                         accel:1;
	// 是否基于SSL协议访问上游服务器
    unsigned                         ssl:1;
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

	// 向下游转发上游包体时，是否开启更大的内存及临时磁盘文件用于缓存
    unsigned                         buffering:1;
	// 是否保持长连接
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;

	// 是否已经向上游服务器发送了请求
    unsigned                         request_sent:1;
	// 是否把包头转发给客户端
    unsigned                         header_sent:1;
}; // }}}


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_http_upstream_param_t;


ngx_int_t ngx_http_upstream_cookie_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t ngx_http_upstream_header_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_SENDFILE           2


#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1


#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_LINGERING_ALWAYS       2


#define NGX_HTTP_IMS_OFF                0
#define NGX_HTTP_IMS_EXACT              1
#define NGX_HTTP_IMS_BEFORE             2


#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;
typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;


// struct ngx_http_listen_opt_t 
// listen socket的配置信息存储结构 {{{
typedef struct {
    union {
        struct sockaddr        sockaddr;
        struct sockaddr_in     sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6    sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un     sockaddr_un;
#endif
        u_char                 sockaddr_data[NGX_SOCKADDRLEN];
    } u;

    socklen_t                  socklen;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
#if (NGX_HTTP_SSL)
    unsigned                   ssl:1;
#endif
#if (NGX_HTTP_SPDY)
    unsigned                   spdy:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                   ipv6only:1;
#endif
    unsigned                   so_keepalive:2;
    unsigned                   proxy_protocol:1;

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    int                        fastopen;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t                 deferred_accept;
#endif

    u_char                     addr[NGX_SOCKADDR_STRLEN + 1];
} ngx_http_listen_opt_t; // }}}


// enum ngx_http_phases
// 11 个 HTTP 处理阶段枚举类型 {{{
typedef enum {
	// 接收到完整 HTTP 头部后处理阶段
    NGX_HTTP_POST_READ_PHASE = 0,

	// 在 URI 与 location 匹配前修改请求的 URI（重定向）
    NGX_HTTP_SERVER_REWRITE_PHASE,

	// 根据请求 URI 匹配 location 表达式
	// 该阶段只能由 ngx_http_core_module 模块实现
    NGX_HTTP_FIND_CONFIG_PHASE,

	// 匹配 location 后修改请求 URI
    NGX_HTTP_REWRITE_PHASE,

	// 防止递归修改 URI 造成死循环
	// 该阶段只能由 ngx_http_core_module 模块实现
    NGX_HTTP_POST_REWRITE_PHASE,

	// HTTP 模块介入处理阶段
    NGX_HTTP_PREACCESS_PHASE,

	// nginx 服务器访问限制
	// 如果 nginx 不允许访问则返回 NGX_HTTP_FORBIDDEN 或 NGX_HTTP_UNAUTHORIZED
    NGX_HTTP_ACCESS_PHASE,

	// 向用户发送拒绝服务的错误响应
    NGX_HTTP_POST_ACCESS_PHASE,

	// 如果 HTTP 请求访问静态文件资源
	// try_files 配置项可以使这个请求顺序的访问多个静态文件资源
	// 直到某个静态文件资源符合选取条件
    NGX_HTTP_TRY_FILES_PHASE,

	// 处理 HTTP 请求内容，大部分 HTTP 模块会介入该阶段
    NGX_HTTP_CONTENT_PHASE,

	// 处理请求后记录日志
    NGX_HTTP_LOG_PHASE
} ngx_http_phases; // }}}

typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;

typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

// struct ngx_http_phase_handler_s
// http 请求处理各阶段数组元素 {{{
struct ngx_http_phase_handler_s {
	// 仅可由 HTTP 框架实现，控制 HTTP 请求的处理流程
    ngx_http_phase_handler_pt  checker;
	// HTTP 模块实现的处理方法
    ngx_http_handler_pt        handler;
	// 下一个处理阶段中第一个 ngx_http_phase_handler_t 处理方法
	// 用于自定义执行顺序
    ngx_uint_t                 next;
}; // }}}


// struct ngx_http_phase_engine_t
// http 处理引擎，存储所有 ngx_http_phase_handler_t {{{
typedef struct {
	// 各阶段回调函数结构首地址
    ngx_http_phase_handler_t  *handlers;
	// 存储 NGX_HTTP_SERVER_REWRITE_PHASE 阶段第一个回调函数序号，用于快速跳转
    ngx_uint_t                 server_rewrite_index;
	// 存储 NGX_HTTP_REWRITE_PHASE 阶段第一个回调函数序号，用于快速跳转
    ngx_uint_t                 location_rewrite_index;
} ngx_http_phase_engine_t; // }}}


// struct ngx_http_phase_t
// http 请求处理各阶段数组，用于初始化 ngx_http_phase_engine_t {{{
typedef struct {
    ngx_array_t                handlers;
} ngx_http_phase_t; // }}}


// struct ngx_http_core_main_conf_t
// ngx_http_core_module 模块的 main_conf {{{
typedef struct {
	// 存储所有的ngx_http_core_srv_conf_t，元素的个数等于server块的个数
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

	// 存储 http 处理引擎，处理 http 连接时，会依次调用
	// 通过 handlers 域的 next 域构成链表
    ngx_http_phase_engine_t    phase_engine;

	// 存储所有的 request header
    ngx_hash_t                 headers_in_hash;

	// 存储所有的变量，比如通过rewrite模块的set指令设置的变量，会存储在这个hash中
	// 诸如$http_XXX和$cookie_XXX等内建变量不会在此分配空间
    ngx_hash_t                 variables_hash;

	// ngx_http_variable_t类型的数组，所有被索引的nginx变量被存储在这个数组中
    ngx_array_t                variables;       /* ngx_http_variable_t */
    ngx_uint_t                 ncaptures;

	// server names的hash表的允许的最大bucket数量，默认值是512
    ngx_uint_t                 server_names_hash_max_size;
	// server names的hash表中每个桶允许占用的最大空间，默认值是ngx_cacheline_size
    ngx_uint_t                 server_names_hash_bucket_size;

	// variables的hash表的允许的最大bucket数量，默认值是512
    ngx_uint_t                 variables_hash_max_size;
	// variables的hash表中每个桶允许占用的最大空间，默认值是64
    ngx_uint_t                 variables_hash_bucket_size;

	// 存储所有的变量名，以及变量名和变量内容的kv数组
	// 初始化variables_hash后，会被置为NULL
    ngx_hash_keys_arrays_t    *variables_keys;

	// 保存监听的所有端口，ngx_http_port_t类型，其中包含socket地址信息
    ngx_array_t               *ports;

    ngx_uint_t                 try_files;       /* unsigned  try_files:1 */

	// 所有的phase的数组，其中每个元素是该phase上注册的handler的数组
    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
} ngx_http_core_main_conf_t; // }}}


// struct ngx_http_core_srv_conf_t
// 主机配置结构 {{{
typedef struct {
    /* array of the ngx_http_server_name_t, "server_name" directive */
	// 存储所有server的配置结构
    ngx_array_t                 server_names;

    /* server ctx */
	// 指向 http 模块 server 配置上下文
    ngx_http_conf_ctx_t        *ctx;

	// 主机名
    ngx_str_t                   server_name;

	// 连接池大小限制
    size_t                      connection_pool_size;
	// 请求连接池大小限制
    size_t                      request_pool_size;
	// header 大小限制
    size_t                      client_header_buffer_size;

    ngx_bufs_t                  large_client_header_buffers;

    ngx_msec_t                  client_header_timeout;

    ngx_flag_t                  ignore_invalid_headers;
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif

    ngx_http_core_loc_conf_t  **named_locations;
} ngx_http_core_srv_conf_t; // }}}


/* list of structures to find core_srv_conf quickly at run time */


// struct ngx_http_server_name_t
// 虚拟主机名结构 {{{
typedef struct {
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;
#endif
    ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;
} ngx_http_server_name_t; // }}}


typedef struct {
     ngx_hash_combined_t       names;

     ngx_uint_t                nregex;
     ngx_http_server_name_t   *regex;
} ngx_http_virtual_names_t;


struct ngx_http_addr_conf_s {
    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;

    ngx_http_virtual_names_t  *virtual_names;

#if (NGX_HTTP_SSL)
    unsigned                   ssl:1;
#endif
#if (NGX_HTTP_SPDY)
    unsigned                   spdy:1;
#endif
    unsigned                   proxy_protocol:1;
};


typedef struct {
    in_addr_t                  addr;
    ngx_http_addr_conf_t       conf;
} ngx_http_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_http_addr_conf_t       conf;
} ngx_http_in6_addr_t;

#endif


typedef struct {
    /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
    void                      *addrs;
    ngx_uint_t                 naddrs;
} ngx_http_port_t;


// struct ngx_http_conf_port_t
// 配置 port 结构 {{{
typedef struct {
    ngx_int_t                  family;	// ip 地址协议族
    in_port_t                  port;	// 端口号
    ngx_array_t                addrs;     /* array of ngx_http_conf_addr_t */
} ngx_http_conf_port_t; // }}}


// struct ngx_http_conf_addr_t
// 配置地址结构 {{{
typedef struct {
    ngx_http_listen_opt_t      opt;				// listen socket的配置信息存储结构

    ngx_hash_t                 hash;			// 存储虚拟地址的哈希结构
    ngx_hash_wildcard_t       *wc_head;			// 前缀通配符哈希结构
    ngx_hash_wildcard_t       *wc_tail;			// 后缀通配符哈希结构

#if (NGX_PCRE)
    ngx_uint_t                 nregex;			// 正则表达式解析器索引
    ngx_http_server_name_t    *regex;			// 正则表达式解析器
#endif

    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;	// 默认 server 配置结构
    ngx_array_t                servers;  /* array of ngx_http_core_srv_conf_t */
} ngx_http_conf_addr_t; // }}}


typedef struct {
    ngx_int_t                  status;
    ngx_int_t                  overwrite;
    ngx_http_complex_value_t   value;
    ngx_str_t                  args;
} ngx_http_err_page_t;


typedef struct {
    ngx_array_t               *lengths;
    ngx_array_t               *values;
    ngx_str_t                  name;

    unsigned                   code:10;
    unsigned                   test_dir:1;
} ngx_http_try_file_t;


struct ngx_http_core_loc_conf_s {
    ngx_str_t     name;          /* location name */

#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
#if (NGX_HTTP_DEGRADATION)
    unsigned      gzip_disable_degradation:2;
#endif
#endif

    ngx_http_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    ngx_http_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    ngx_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    ngx_str_t     root;                    /* root, alias */
    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        limit_rate;              /* limit_rate */
    size_t        limit_rate_after;        /* limit_rate_after */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    ngx_msec_t    resolver_timeout;        /* resolver_timeout */

    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    ngx_uint_t    keepalive_requests;      /* keepalive_requests */
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close */
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    ngx_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    ngx_flag_t    internal;                /* internal */
    ngx_flag_t    sendfile;                /* sendfile */
#if (NGX_HAVE_FILE_AIO)
    ngx_flag_t    aio;                     /* aio */
#endif
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */
    ngx_flag_t    log_subrequest;          /* log_subrequest */
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    ngx_flag_t    server_tokens;           /* server_tokens */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    ngx_flag_t    etag;                    /* etag */

#if (NGX_HTTP_GZIP)
    ngx_flag_t    gzip_vary;               /* gzip_vary */

    ngx_uint_t    gzip_http_version;       /* gzip_http_version */
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (NGX_HAVE_OPENAT)
    ngx_uint_t    disable_symlinks;        /* disable_symlinks */
    ngx_http_complex_value_t  *disable_symlinks_from;
#endif

    ngx_array_t  *error_pages;             /* error_page */
    ngx_http_try_file_t    *try_files;     /* try_files */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    ngx_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    ngx_uint_t    open_file_cache_min_uses;
    ngx_flag_t    open_file_cache_errors;
    ngx_flag_t    open_file_cache_events;

    ngx_log_t    *error_log;

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

    ngx_queue_t  *locations;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};


// struct ngx_http_location_queue_t
// 存储所有 location 配置的双向链表结构 {{{
typedef struct {
	// 双向链表结构
    ngx_queue_t                      queue;
	// 处理嵌套 location 配置的情况，指向子级 location 配置结构
    ngx_http_core_loc_conf_t        *exact;
	// 处理嵌套 location 配置的情况，指向父级 location 配置结构
    ngx_http_core_loc_conf_t        *inclusive;
	// 当前 location 名
    ngx_str_t                       *name;
    u_char                          *file_name;
    ngx_uint_t                       line;
    ngx_queue_t                      list;
} ngx_http_location_queue_t; // }}}


// struct ngx_http_location_tree_node_s
// location 三叉排序树结构 {{{
struct ngx_http_location_tree_node_s {
    ngx_http_location_tree_node_t   *left;			// 左节点
    ngx_http_location_tree_node_t   *right;			// 右节点
    ngx_http_location_tree_node_t   *tree;			// 中间节点

    ngx_http_core_loc_conf_t        *exact;			// 前缀
    ngx_http_core_loc_conf_t        *inclusive;		// 范围匹配

    u_char                           auto_redirect;
    u_char                           len;			// value 的长度
    u_char                           name[1];		// value 首字母
}; // }}}


void ngx_http_core_run_phases(ngx_http_request_t *r);
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_try_files_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);


void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
void ngx_http_set_exten(ngx_http_request_t *r);
ngx_int_t ngx_http_set_etag(ngx_http_request_t *r);
void ngx_http_weak_etag(ngx_http_request_t *r);
ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_http_complex_value_t *cv);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
#if (NGX_HTTP_GZIP)
ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
#endif


ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **sr,
    ngx_http_post_subrequest_t *psr, ngx_uint_t flags);
ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);


ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);


typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_set_disable_symlinks(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of);

ngx_int_t ngx_http_get_forwarded_addr(ngx_http_request_t *r, ngx_addr_t *addr,
    ngx_array_t *headers, ngx_str_t *value, ngx_array_t *proxies,
    int recursive);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;

extern ngx_str_t  ngx_http_core_get_method;


#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }

#define ngx_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */

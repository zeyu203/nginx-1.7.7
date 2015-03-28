
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

// struct ngx_listening_s
// socket 属性结构 {{{
struct ngx_listening_s {
    ngx_socket_t        fd;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;
    ngx_str_t           addr_text; // 点分十进制IP字符串

    int                 type;

    int                 backlog;
    int                 rcvbuf;
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;

    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;
    ngx_log_t          *logp;

    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;

    ngx_listening_t    *previous;
    ngx_connection_t   *connection;

    unsigned            open:1;
    unsigned            remain:1;
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:1;
#endif
    unsigned            keepalive:2;

#if (NGX_HAVE_DEFERRED_ACCEPT)
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

}; // }}}


typedef enum {
     NGX_ERROR_ALERT = 0,
     NGX_ERROR_ERR,
     NGX_ERROR_INFO,
     NGX_ERROR_IGNORE_ECONNRESET,
     NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
     NGX_TCP_NODELAY_UNSET = 0,
     NGX_TCP_NODELAY_SET,
     NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET,
     NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_SPDY_BUFFERED      0x02


// struct ngx_connection_s
// nginx 连接结构 {{{
struct ngx_connection_s {
	// 连接未使用时，充当连接池空闲链表中的 next 指针
	// 连接使用后，由模块定义其意义
	// HTTP 模块中，data 指向 ngx_http_request_t
    void               *data;
	// 连接对应的读事件
    ngx_event_t        *read;
	// 连接对应的写事件
    ngx_event_t        *write;

	// 连接 fd
    ngx_socket_t        fd;

	// 直接接收网络字符流的方法
	ngx_recv_pt         recv;
	// 直接发送网络字符流的方法
    ngx_send_pt         send;
	// 以链表来接收网络字符流的方法
    ngx_recv_chain_pt   recv_chain;
	// 以链表来发送网络字符流的方法
    ngx_send_chain_pt   send_chain;

	// 监听对象，此连接由listening监听端口的事件建立
    ngx_listening_t    *listening;

	// 这个连接上已发送的字节数
    off_t               sent;

    ngx_log_t          *log;

	// 一般在accept一个新的连接时，会创建一个内存池
	// 而在这个连接结束时会销毁内存池
	// 内存池大小是由 listening 成员的 pool_size 决定的
    ngx_pool_t         *pool;		

	// 连接客户端的sockaddr
    struct sockaddr    *sockaddr;
	// sockaddr结构体的长度
    socklen_t           socklen;
	// 连接客户段字符串形式的IP地址
    ngx_str_t           addr_text;

	// 代理协议地址
    ngx_str_t           proxy_protocol_addr;

#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif

	// 本机监听端口对应的sockaddr结构体
    struct sockaddr    *local_sockaddr;
	// sockaddr结构体的长度
    socklen_t           local_socklen;

	// 用户接受、缓存客户端发来的字符流，分配在连接池中
    ngx_buf_t          *buffer;

	// 用来将当前连接以双向链表元素的形式添加到 ngx_cycle_t 核心结构体的
	// reuseable_connection_queue 双向链表中，表示可以重用的连接
    ngx_queue_t         queue;

	// 连接使用次数
    ngx_atomic_uint_t   number;

	// 处理的请求次数
    ngx_uint_t          requests;

	// 缓存中业务类型
    unsigned            buffered:8;

	// 日志级别
    unsigned            log_error:3;     /* ngx_connection_log_error_e */

	// 为1时表示独立的连接，为0表示依靠其他连接行为而建立起来的非独立连接
    unsigned            unexpected_eof:1;
	// 为1表示连接已经超时
    unsigned            timedout:1;
	// 为1表示连接处理过程中出现错误
    unsigned            error:1;
	// 为1表示连接已经销毁
    unsigned            destroyed:1;

	// 为1表示连接处于空闲状态，如 keepalive 两次请求中间的状态
    unsigned            idle:1;
	// 为1表示连接可重用，与 queue 字段对应使用
    unsigned            reusable:1;
	// 为1表示连接关闭
    unsigned            close:1;

	// 为1表示正在将文件中的数据发往连接的另一端
    unsigned            sendfile:1;
	// 为1表示只有连接套接字对应的发送缓冲区必须满足最低设置的大小阀值时，
	// 事件驱动模块才会分发该事件
	// 这与ngx_handle_write_event方法中的lowat参数是对应的
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (NGX_HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_HAVE_AIO_SENDFILE)
    unsigned            aio_sendfile:1;
    unsigned            busy_count:2;
    ngx_buf_t          *busy_sendfile;
#endif

#if (NGX_THREADS)
    ngx_atomic_t        lock;
#endif
}; // }}}


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, void *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */

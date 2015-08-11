
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

// struct ngx_shm_zone_s
// 共享内存空间 {{{
struct ngx_shm_zone_s {
    void                     *data;		// 初始化回调函数所需的参数
    ngx_shm_t                 shm;		// 共享内存结构
    ngx_shm_zone_init_pt      init;		// 初始化共享内存调用的回调函数
    void                     *tag;		// 标记
}; // }}}

// struct ngx_cycle_s
// nginx 运行核心结构 {{{
struct ngx_cycle_s {
    void                  ****conf_ctx;				// 配置上下文数组(含所有模块)
    ngx_pool_t               *pool;					// 内存池起始地址

    ngx_log_t                *log;					// 日志
    ngx_log_t                 new_log;

	/* unsigned  log_use_stderr:1; */
    ngx_uint_t                log_use_stderr;

    ngx_connection_t        **files;				// 连接文件
    ngx_connection_t         *free_connections;		// 空闲连接
    ngx_uint_t                free_connection_n;	// 空闲连接数

    ngx_queue_t               reusable_connections_queue;
													// 再利用连接队列

    ngx_array_t               listening;			// 监听数组
    ngx_array_t               paths;				// 路径数组
    ngx_list_t                open_files;			// 已打开文件链表
    ngx_list_t                shared_memory;		// 共享内存链表

    ngx_uint_t                connection_n;			// 连接个数
    ngx_uint_t                files_n;				// 打开文件数

    ngx_connection_t         *connections;			// 连接
    ngx_event_t              *read_events;			// 读事件
    ngx_event_t              *write_events;			// 写事件

    ngx_cycle_t              *old_cycle;

    ngx_str_t                 conf_file;			// 配置文件
    ngx_str_t                 conf_param;			// 配置参数
    ngx_str_t                 conf_prefix;			// 配置前缀
    ngx_str_t                 prefix;				// 程序目录路径
    ngx_str_t                 lock_file;			// 锁文件
    ngx_str_t                 hostname;				// 主机名
}; // }}}


// struct ngx_core_conf_t
// nginx 核心配置结构体 {{{
typedef struct {
     ngx_flag_t               daemon;
     ngx_flag_t               master;

     ngx_msec_t               timer_resolution;		// 最大超时时间

     ngx_int_t                worker_processes;		// worker 进程数
     ngx_int_t                debug_points;

     ngx_int_t                rlimit_nofile;		// 系统最大文件描述符数
     ngx_int_t                rlimit_sigpending;	// 系统最大挂起信号数
     off_t                    rlimit_core;			// 内核转存文件的最大长度

     int                      priority;				// 进程优先级

     ngx_uint_t               cpu_affinity_n;		// CPU 数
     uint64_t                *cpu_affinity;

     char                    *username;				// 用户名
     ngx_uid_t                user;					// 用户ID
     ngx_gid_t                group;				// 组ID

     ngx_str_t                working_directory;	// 当前工作路径
     ngx_str_t                lock_file;			// 锁文件

     ngx_str_t                pid;					// pid 文件
     ngx_str_t                oldpid;				// 老的 pid 文件，用于平滑启动

     ngx_array_t              env;					// 环境变量
     char                   **environment;			// 环境变量

#if (NGX_THREADS)
     ngx_int_t                worker_threads;		// worker 线程数
     size_t                   thread_stack_size;	// 线程栈大小
#endif

} ngx_core_conf_t; // }}}


typedef struct {
     ngx_pool_t              *pool;   /* pcre's malloc() pool */
} ngx_core_tls_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
uint64_t ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_quiet_mode;
#if (NGX_THREADS)
extern ngx_tls_key_t          ngx_core_tls_key;
#endif


#endif /* _NGX_CYCLE_H_INCLUDED_ */

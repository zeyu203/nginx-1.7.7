
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

// struct ngx_process_t
// 进程描述结构 {{{
typedef struct {
    ngx_pid_t           pid;			// pid
    int                 status;			// 当前进程的退出状态
    ngx_socket_t        channel[2];		// 用于进程间通信的两个 socketfd

    ngx_spawn_proc_pt   proc;			// 进程创建后执行的函数
    void               *data;			// proc 参数
    char               *name;			// 进程名

    unsigned            respawn:1;		// 退出后是否重建
    unsigned            just_spawn:1;	// 第一次创建
    unsigned            detached:1;		// 分离进程
    unsigned            exiting:1;		// 正在退出的进程
    unsigned            exited:1;		// 已经退出的进程
} ngx_process_t; // }}}


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024

#define NGX_PROCESS_NORESPAWN     -1	// 子进程退出时，父进程不再创建
#define NGX_PROCESS_JUST_SPAWN    -2
	//用于在子进程退出并重新创建后标记是刚刚创建的新进程，防止被父进程意外终止
#define NGX_PROCESS_RESPAWN       -3	// 子进程退出时，父进程需要重新创建
#define NGX_PROCESS_JUST_RESPAWN  -4	// 该标记用来标记进程数组中哪些是新创建的子进程
#define NGX_PROCESS_DETACHED      -5	// 热代码替换


#define ngx_getpid   getpid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#if (NGX_TEST_BUILD_EPOLL)

/* epoll declarations */

// epoll_event 结构 events 域取值 {{{
#define EPOLLIN        0x001	// 连接上有数据可读，包括 tcp 连接关闭时收到 FIN 包
#define EPOLLPRI       0x002	// 连接上有紧急数据可读
#define EPOLLOUT       0x004	// 连接可写
#define EPOLLRDNORM    0x040	// 普通数据可读
#define EPOLLRDBAND    0x080	// 优先级数据可读
#define EPOLLWRNORM    0x100	// 普通数据可写
#define EPOLLWRBAND    0x200	// 优先级数据可写
#define EPOLLMSG       0x400	// 消息队列数据
#define EPOLLERR       0x008	// 连接上发生错误
#define EPOLLHUP       0x010	// 连接被挂起
#define EPOLLRDHUP     0x2000	// 连接远端已经关闭或半关闭
// }}}

#define EPOLLET        0x80000000	// 边沿触发
#define EPOLLONESHOT   0x40000000	// 只对事件处理一次，处理完毕即丢弃

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

// union epoll_data_t
// epoll 信息记录联合体 {{{
typedef union epoll_data {
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t; // }}}

// struct epoll_event
// epoll 事件结构 {{{
struct epoll_event {
    uint32_t      events;	// 事件的属性，具体取值位于本文件上方
    epoll_data_t  data;		// 事件的具体数据
}; // }}}


int epoll_create(int size);

int epoll_create(int size)
{
    return -1;
}


int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}


int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#if (NGX_HAVE_FILE_AIO)

#define SYS_io_setup      245
#define SYS_io_destroy    246
#define SYS_io_getevents  247
#define SYS_eventfd       323

typedef u_int  aio_context_t;

struct io_event {
    uint64_t  data;  /* the data field from the iocb */
    uint64_t  obj;   /* what iocb this event came from */
    int64_t   res;   /* result code for this event */
    int64_t   res2;  /* secondary result */
};


#endif
#endif


// struct ngx_epoll_conf_t
// epoll 模块配置信息结构体 {{{
typedef struct {
    ngx_uint_t  events;
    ngx_uint_t  aio_requests;
} ngx_epoll_conf_t; // }}}


static ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_epoll_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c,
    ngx_uint_t flags);
static ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);

#if (NGX_HAVE_FILE_AIO)
static void ngx_epoll_eventfd_handler(ngx_event_t *ev);
#endif

static void *ngx_epoll_create_conf(ngx_cycle_t *cycle);
static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf);

static int                  ep = -1;
static struct epoll_event  *event_list;
static ngx_uint_t           nevents;

#if (NGX_HAVE_FILE_AIO)

int                         ngx_eventfd = -1;
aio_context_t               ngx_aio_ctx = 0;

static ngx_event_t          ngx_eventfd_event;
static ngx_connection_t     ngx_eventfd_conn;

#endif

static ngx_str_t      epoll_name = ngx_string("epoll");

static ngx_command_t  ngx_epoll_commands[] = {

    { ngx_string("epoll_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, events),
      NULL },

    { ngx_string("worker_aio_requests"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, aio_requests),
      NULL },

      ngx_null_command
};


// ngx_event_module_t  ngx_epoll_module_ctx
// epoll 模块配置，相应接口的实现 {{{
ngx_event_module_t  ngx_epoll_module_ctx = {
    &epoll_name,
	// 创建存储配置信息的结构体 ngx_epoll_conf_t  *epcf
    ngx_epoll_create_conf,               /* create configuration */
	// 初始化配置信息
    ngx_epoll_init_conf,                 /* init configuration */

	// ngx_event_actions_t 类型，包含全部回调函数
    {
		// add，事件添加
        ngx_epoll_add_event,             /* add an event */
		// del，事件删除
        ngx_epoll_del_event,             /* delete an event */
		// enable，事件启用
        ngx_epoll_add_event,             /* enable an event */
		// disable，事件禁用
        ngx_epoll_del_event,             /* disable an event */
		// add_conn，添加连接
        ngx_epoll_add_connection,        /* add an connection */
		// del_conn，删除连接
        ngx_epoll_del_connection,        /* delete an connection */
		// process_changes，线程模式下分发事件
        NULL,                            /* process the changes */
		// process_events，事件处理
        ngx_epoll_process_events,        /* process the events */
		// 初始化事件驱动模块
        ngx_epoll_init,                  /* init the events */
		// 退出事件驱动模块前调用的方法
        ngx_epoll_done,                  /* done the events */
    }
}; // }}}

ngx_module_t  ngx_epoll_module = {
    NGX_MODULE_V1,
    &ngx_epoll_module_ctx,               /* module context */
    ngx_epoll_commands,                  /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


#if (NGX_HAVE_FILE_AIO)

/*
 * We call io_setup(), io_destroy() io_submit(), and io_getevents() directly
 * as syscalls instead of libaio usage, because the library header file
 * supports eventfd() since 0.3.107 version only.
 */

static int
io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}


static int
io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}


static int
io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,
    struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}


// static void ngx_epoll_aio_init(ngx_cycle_t *cycle, ngx_epoll_conf_t *epcf)
// 初始化异步 IO 机制 {{{
static void
ngx_epoll_aio_init(ngx_cycle_t *cycle, ngx_epoll_conf_t *epcf)
{
    int                 n;
    struct epoll_event  ee;

	// 调用 eventfd 获取 eventfd 对象，用来在内核态与用户态之间传递通知
#if (NGX_HAVE_SYS_EVENTFD_H)
    ngx_eventfd = eventfd(0, 0);
#else
	// syscall 直接调用指定 id 的系统调用，即系统并没有开放用户态接口
    ngx_eventfd = syscall(SYS_eventfd, 0);
#endif

    if (ngx_eventfd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "eventfd() failed");
        ngx_file_aio = 0;
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventfd: %d", ngx_eventfd);

    n = 1;

	// 设置 eventfd 为非阻塞
    if (ioctl(ngx_eventfd, FIONBIO, &n) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "ioctl(eventfd, FIONBIO) failed");
        goto failed;
    }

	// 创建异步 IO 上下文
    if (io_setup(epcf->aio_requests, &ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "io_setup() failed");
        goto failed;
    }

	// 异步 IO 回调函数 ngx_epoll_eventfd_handler 的参数，nginx 连接结构
    ngx_eventfd_event.data = &ngx_eventfd_conn;
	// 绑定事件回调函数
    ngx_eventfd_event.handler = ngx_epoll_eventfd_handler;
    ngx_eventfd_event.log = cycle->log;
    ngx_eventfd_event.active = 1;
    ngx_eventfd_conn.fd = ngx_eventfd;
    ngx_eventfd_conn.read = &ngx_eventfd_event;
    ngx_eventfd_conn.log = cycle->log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &ngx_eventfd_conn;

	// 将 eventfd 添加到 epoll 中
    if (epoll_ctl(ep, EPOLL_CTL_ADD, ngx_eventfd, &ee) != -1) {
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                  "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

	// 执行失败则删除异步 IO 上下文
    if (io_destroy(ngx_aio_ctx) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "io_destroy() failed");
    }

failed:

	// 关闭 eventfd
    if (close(ngx_eventfd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    ngx_eventfd = -1;
    ngx_aio_ctx = 0;
    ngx_file_aio = 0;
} // }}}

#endif


// static ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
// epoll 模块初始化 {{{
static ngx_int_t
ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_epoll_conf_t  *epcf;

    epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_epoll_module);

    if (ep == -1) {
		// 创建 epoll fd
        ep = epoll_create(cycle->connection_n / 2);

        if (ep == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "epoll_create() failed");
            return NGX_ERROR;
        }

#if (NGX_HAVE_FILE_AIO)

		// 初始化异步IO
        ngx_epoll_aio_init(cycle, epcf);

#endif
    }

	// 事件列表容量不足则重新分配事件列表
    if (nevents < epcf->events) {
        if (event_list) {
            ngx_free(event_list);
        }

        event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,
                               cycle->log);
        if (event_list == NULL) {
            return NGX_ERROR;
        }
    }

    nevents = epcf->events;

    ngx_io = ngx_os_io;

	// 初始化事件添加、删除、启用、禁用、事件分发等回调函数
    ngx_event_actions = ngx_epoll_module_ctx.actions;

#if (NGX_HAVE_CLEAR_EVENT)
	// 边缘触发
    ngx_event_flags = NGX_USE_CLEAR_EVENT
#else
	// 水平触发
    ngx_event_flags = NGX_USE_LEVEL_EVENT
#endif
                      |NGX_USE_GREEDY_EVENT
                      |NGX_USE_EPOLL_EVENT;

    return NGX_OK;
} // }}}


// static void ngx_epoll_done(ngx_cycle_t *cycle)
// epoll 模块析构函数 {{{
static void
ngx_epoll_done(ngx_cycle_t *cycle)
{
    if (close(ep) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "epoll close() failed");
    }

    ep = -1;

#if (NGX_HAVE_FILE_AIO)

    if (ngx_eventfd != -1) {

        if (io_destroy(ngx_aio_ctx) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "io_destroy() failed");
        }

        if (close(ngx_eventfd) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "eventfd close() failed");
        }

        ngx_eventfd = -1;
    }

    ngx_aio_ctx = 0;

#endif

    ngx_free(event_list);

    event_list = NULL;
    nevents = 0;
} // }}}


// static ngx_int_t
// ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
// 将事件加入 epoll 监听 {{{
// 三个传入参数分别是：事件对象、nginx 事件属性和 epoll 事件属性
static ngx_int_t
ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    c = ev->data; // 在 epoll 模块中，事件结构的 data 域是指向连接结构的指针

    events = (uint32_t) event;

    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;
#if (NGX_READ_EVENT != EPOLLIN|EPOLLRDHUP)
        events = EPOLLIN|EPOLLRDHUP;
#endif

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
#if (NGX_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }

	// 如果连接已经存在，则将已经在 epoll 中注册过的 fd 更新，否则加入新的 fd
    if (e->active) {
        op = EPOLL_CTL_MOD;
        events |= prev;

    } else {
        op = EPOLL_CTL_ADD;
    }

    ee.events = events | (uint32_t) flags;
	// ev->instance 判断事件是否过期，过期则不处理
	// 因为对齐的原因，地址最低位一定是 0，因此用这一位作为 instance 位
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll add event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

	// 将事件加入 EPOLL 队列
    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

	// 将事件设为活跃状态
    ev->active = 1;
#if 0
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
#endif

    return NGX_OK;
} // }}}


// static ngx_int_t
// ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
// 从 epoll 中去除事件 {{{
static ngx_int_t
ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;

    /*
     * when the file descriptor is closed, the epoll automatically deletes
     * it from its queue, so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        ev->active = 0;
        return NGX_OK;
    }

    c = ev->data;

    if (event == NGX_READ_EVENT) {
        e = c->write;
        prev = EPOLLOUT;

    } else {
        e = c->read;
        prev = EPOLLIN|EPOLLRDHUP;
    }

    if (e->active) {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);

    } else {
        op = EPOLL_CTL_DEL;
        ee.events = 0;
        ee.data.ptr = NULL;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "epoll del event: fd:%d op:%d ev:%08XD",
                   c->fd, op, ee.events);

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    ev->active = 0;

    return NGX_OK;
} // }}}


// static ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c)
// 增加连接 {{{
static ngx_int_t
ngx_epoll_add_connection(ngx_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET|EPOLLRDHUP;
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);

    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NGX_ERROR;
    }

    c->read->active = 1;
    c->write->active = 1;

    return NGX_OK;
} // }}}


// static ngx_int_t
// ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags)
// 从 epoll 中移除连接 {{{
static ngx_int_t
ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;

    /*
     * when the file descriptor is closed the epoll automatically deletes
     * it from its queue so we do not need to delete explicitly the event
     * before the closing the file descriptor
     */

    if (flags & NGX_CLOSE_EVENT) {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "epoll del connection: fd:%d", c->fd);

    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;

    if (epoll_ctl(ep, op, c->fd, &ee) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }

    c->read->active = 0;
    c->write->active = 0;

    return NGX_OK;
} // }}}


// static ngx_int_t
// ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
// 		ngx_uint_t flags)
// epoll 事件处理函数 {{{
static ngx_int_t
ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    int                events;
    uint32_t           revents;
    ngx_int_t          instance, i;
    ngx_uint_t         level;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev;
    ngx_queue_t       *queue;
    ngx_connection_t  *c;

    /* NGX_TIMER_INFINITE == INFTIM */

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "epoll timer: %M", timer);

	// epoll_wait，获取发生的事件列表 event_list
    events = epoll_wait(ep, event_list, (int) nevents, timer);

    err = (events == -1) ? ngx_errno : 0;

	// 如果配置文件中配置了 ngx_timer_resolution
	// 则在调用 ngx_timer_signal_handler 的过程中会将 ngx_event_timer_alarm 置 1
    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        ngx_time_update();
    }

	// 出错处理
    if (err) {
        if (err == NGX_EINTR) {

            if (ngx_event_timer_alarm) {
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }

            level = NGX_LOG_INFO;

        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "epoll_wait() failed");
        return NGX_ERROR;
    }

	// 超时
    if (events == 0) {
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

		// 如果 timer 为 -1（永久阻塞），则说明调用出错
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "epoll_wait() returned no events without timeout");
        return NGX_ERROR;
    }

	// 事件处理
    for (i = 0; i < events; i++) {
        c = event_list[i].data.ptr;

		// 无论是 32 位还是 64 位系统，地址的最低位一定是0
		// 因此，nginx 使用连接地址的最后一位保存 instance 变量，用于记录是否过期
		//
		// 这里取出 instance 变量，并恢复地址
        instance = (uintptr_t) c & 1;
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

        rev = c->read;

		// 非监听 fd 或已过期
        if (c->fd == -1 || rev->instance != instance) {

            /*
             * the stale event from a file descriptor
             * that was just closed in this iteration
             */

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll: stale event %p", c);
            continue;
        }

        revents = event_list[i].events;

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "epoll: fd:%d ev:%04XD d:%p",
                       c->fd, revents, event_list[i].data.ptr);

        if (revents & (EPOLLERR|EPOLLHUP)) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "epoll_wait() error on fd:%d ev:%04XD",
                           c->fd, revents);
        }

#if 0
        if (revents & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP)) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "strange epoll_wait() events fd:%d ev:%04XD",
                          c->fd, revents);
        }
#endif

        if ((revents & (EPOLLERR|EPOLLHUP))
             && (revents & (EPOLLIN|EPOLLOUT)) == 0)
        {
            /*
             * if the error events were returned without EPOLLIN or EPOLLOUT,
             * then add these flags to handle the events at least in one
             * active handler
             */

            revents |= EPOLLIN|EPOLLOUT;
        }

		// 事件可读
        if ((revents & EPOLLIN) && rev->active) {

#if (NGX_HAVE_EPOLLRDHUP)
            if (revents & EPOLLRDHUP) {
                rev->pending_eof = 1;
            }
#endif

            rev->ready = 1;

			// 拿着锁则先把事件放到队列中延后处理
            if (flags & NGX_POST_EVENTS) {
                queue = rev->accept ? &ngx_posted_accept_events
                                    : &ngx_posted_events;

				// 如果进程正在占用锁，则先将事件缓存在队列中
                ngx_post_event(rev, queue);

            } else {
				// 调用读事件回调函数
				// 如果是 epoll 时间则会调用 ngx_event_accept 处理 accept
                rev->handler(rev);
            }
        }

        wev = c->write;

        if ((revents & EPOLLOUT) && wev->active) {

            if (c->fd == -1 || wev->instance != instance) {

                /*
                 * the stale event from a file descriptor
                 * that was just closed in this iteration
                 */

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "epoll: stale event %p", c);
                continue;
            }

            wev->ready = 1;

            if (flags & NGX_POST_EVENTS) {
                ngx_post_event(wev, &ngx_posted_events);

            } else {
                wev->handler(wev);
            }
        }
    }

    return NGX_OK;
} // }}}


#if (NGX_HAVE_FILE_AIO)

// static void ngx_epoll_eventfd_handler(ngx_event_t *ev)
// 异步 IO 回调函数 {{{
static void
ngx_epoll_eventfd_handler(ngx_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    ngx_err_t         err;
    ngx_event_t      *e;
    ngx_event_aio_t  *aio;
    struct io_event   event[64];
    struct timespec   ts;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");

    n = read(ngx_eventfd, &ready, 8);

    err = ngx_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);

    if (n != 8) {
        if (n == -1) {
            if (err == NGX_EAGAIN) {
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "read(eventfd) failed");
            return;
        }

        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "read(eventfd) returned only %d bytes", n);
        return;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

    while (ready) {

		// 获取异步 IO 请求的事件
        events = io_getevents(ngx_aio_ctx, 1, 64, event, &ts);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_getevents: %l", events);

        if (events > 0) {
            ready -= events;

            for (i = 0; i < events; i++) {

                ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                               "io_event: %uXL %uXL %L %L",
                                event[i].data, event[i].obj,
                                event[i].res, event[i].res2);

                e = (ngx_event_t *) (uintptr_t) event[i].data;

                e->complete = 1;
                e->active = 0;
                e->ready = 1;

                aio = e->data;
                aio->res = event[i].res;

				// 将事件添加到事件消息队列中
                ngx_post_event(e, &ngx_posted_events);
            }

            continue;
        }

        if (events == 0) {
            return;
        }

        /* events == -1 */
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "io_getevents() failed");
        return;
    }
} // }}}

#endif


// static void * ngx_epoll_create_conf(ngx_cycle_t *cycle)
// 创建存储配置项的结构体 ngx_epoll_conf_t  *epcf {{{
static void *
ngx_epoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_epoll_conf_t  *epcf;

    epcf = ngx_palloc(cycle->pool, sizeof(ngx_epoll_conf_t));
    if (epcf == NULL) {
        return NULL;
    }

    epcf->events = NGX_CONF_UNSET;
    epcf->aio_requests = NGX_CONF_UNSET;

    return epcf;
} // }}}


// static char * ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
// 初始化配置信息结构体 {{{
static char *
ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_epoll_conf_t *epcf = conf;

    ngx_conf_init_uint_value(epcf->events, 512);
    ngx_conf_init_uint_value(epcf->aio_requests, 32);

    return NGX_CONF_OK;
} // }}}

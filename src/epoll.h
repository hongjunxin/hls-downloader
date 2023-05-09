/*
 * Copyright (c) hongjunxin
 */

#ifndef _EPOLL_H_
#define _EPOLL_H_

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include "utility.h"
#include "http.h"
#include "media.h"

#define EPOLL_MAX_EVENTS  100
#define epoll_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
#define epoll_blocking(s) fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK)

int epoll_do_create(int event_cnt);
int epoll_do_ctl(int epfd, int op, struct epoll_event *ev);
int epoll_do_wait(int epfd, int event_cnt, ts_list_t *ts_list, http_event_t *hevs);

#endif

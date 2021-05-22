/*
 * Copyright (c) hongjunxin
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "log.h"
#include "http.h"
#include "epoll.h"
#include "utility.h"

static void epoll_show_download_progress(ts_list_t *ts_list);

int epoll_do_create(int event_cnt)
{
    int fd;

    fd = epoll_create1(0);

    if (fd == -1) {
        log_error("epoll: create epoll failed");
        return -1;
    }

    return fd;
}

int epoll_do_wait(int epfd, int event_cnt, ts_list_t *ts_list)
{
    struct epoll_event  events[event_cnt];
    http_event_t *hev;
    int nfds, n, ret;
    char *ts;

    for (;;) {

        nfds = epoll_wait(epfd, events, event_cnt, -1);

        if (nfds == -1) {
            if (errno == EINTR) {
                continue;
            }
            log_error("epoll: epoll_wait() failed");
            return -1;
        }

        for (n = 0; n < nfds; ++n) {
            hev = events[n].data.ptr;
            ret = hev->handler[hev->current].handler(hev);
            
            if (ret == 0) {
                hev->doing = 0;
                if (hev->handler[++hev->current].handler) {
                    if (hev->handler[hev->current - 1].read != hev->handler[hev->current].read) {
                        epoll_do_ctl(epfd, EPOLL_CTL_MOD, &events[n]);
                    }                    
                } else {
                    ts_list->success++;
                    util_show_download_progress(ts_list);

                    ts = ts_list->get_ts_name(ts_list);
                    if (ts) {
                        memset(hev->uri, '\0', sizeof(hev->uri));
                        memcpy(hev->uri, ts_list->base_uri, strlen(ts_list->base_uri));
                        memcpy(&hev->uri[strlen(hev->uri)], "/", 1);
                        memcpy(&hev->uri[strlen(hev->uri)], ts, strlen(ts));
                        memset(hev->buffer.file, '\0', hev->buffer.filename_len);
                        hev->current = 0;
                        epoll_do_ctl(epfd, EPOLL_CTL_MOD, &events[n]);
                    } else {
                        epoll_do_ctl(epfd, EPOLL_CTL_DEL, &events[n]);
                    }
                }
            } else if (ret == EAGAIN) {
                hev->again_timer++;
            } else {
                log_info("epoll: handle '%s' failed, handler=%d, retry", hev->uri, hev->current);

                hev->current = 0;
                hev->doing = 0;
                hev->again_timer = 0;

                epoll_do_ctl(epfd, EPOLL_CTL_DEL, &events[n]);

                if (http_connect_server(hev) != 0) {
                    log_error("main: connect |%s:%d| failed", hev->ip, hev->port);
                    util_exit();
                }

                epoll_do_ctl(epfd, EPOLL_CTL_ADD, &events[n]);
            }
        }

        if (ts_list->success + ts_list->failure == ts_list->ts_cnt) {
            log_info("epoll: download all ts file done");
            return 0;
        }
    }

    return 0;
}

int epoll_do_ctl(int epfd, int op, struct epoll_event *ev)
{
    http_event_t *hev;

    hev = ev->data.ptr;

    switch (op) {
        case EPOLL_CTL_ADD:
        case EPOLL_CTL_MOD:
            if (hev->handler[hev->current].read) {
                ev->events = EPOLLIN;
            } else {
                ev->events = EPOLLOUT;
            }
            break;
        case EPOLL_CTL_DEL:
            /* todo? */
            break;
        default:
            return -1;
    }

    if (epoll_ctl(epfd, op, hev->fd, ev) == -1) {
        log_error("epoll: epoll_ctl failed, op=%d, epfd=%d, fd=%d", op, epfd, hev->fd);
        return -1;
    }

    if (op == EPOLL_CTL_DEL) {
        http_free_event(hev);  /* must after epoll_ctl */
    }

    return 0;
}

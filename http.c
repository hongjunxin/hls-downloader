/*
 * Copyright (c) hongjunxin
 */

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "log.h"
#include "http.h"
#include "utility.h"

#define REQUEST_HEAD \
        "GET %s HTTP/1.1 \r\n"          \
        "Accept: */* \r\n"              \
        "Host: %s \r\n"                 \
        "Connection: keep-alive \r\n"   \
        "\r\n"                          \

extern int errno;
extern int h_errno;

static int http_get_file_name(http_event_t *hev);
static int http_save_file(http_event_t *hev);
static int http_read_headers(http_event_t *hev);

int http_connect_server(http_event_t *hev)
{
    struct sockaddr_in svaddr;
    struct hostent* hostent;
    char *addr;
    int cfd = -1;
    int i, cnt, try_timer;

    memset(&svaddr, 0, sizeof(svaddr));
    svaddr.sin_port = htons(hev->port);
    svaddr.sin_family = AF_INET;
    
    cfd = socket(AF_INET, SOCK_STREAM, 0);  /* lack AF_INET6 */
    if (cfd == -1) {
        log_error( "http: socket failed (errno=%d)", errno);
        goto err;        
    }

    if (hev->fd != -1) {
        close(hev->fd);
        hev->fd = -1;
    }

    try_timer = 10;

    if (strlen(hev->ip) != 0) {
        if (inet_pton(AF_INET, hev->ip, &svaddr.sin_addr) == 1) {

            log_debug("http: connecting %s |%s:%d|", hev->host, hev->ip, hev->port);

            for (i = 0; i < try_timer; ++i) {
                if (connect(cfd, (struct sockaddr *) &svaddr, sizeof(svaddr)) != 0) {
                    sleep(1);
                } else {
                    log_debug("http: connected");
                    hev->fd = cfd;
                    return 0;
                }                
            }
        }
    }

    hostent = gethostbyname(hev->host);    
    if (!hostent) {
        log_error("http: %s", hstrerror(h_errno));
        return -1;
    }        

    for (i = 0; hostent->h_addr_list[i]; i++) {
        svaddr.sin_addr = *(struct in_addr*) hostent->h_addr_list[i];
        svaddr.sin_family = hostent->h_addrtype;
        inet_ntop(svaddr.sin_family, &svaddr.sin_addr, hev->ip, sizeof(hev->ip) - 1);

        log_debug("http: connecting %s |%s:%d|", hev->host, hev->ip, hev->port);

        for (cnt = 0; i < try_timer; ++cnt) {
            if (connect(cfd, (struct sockaddr *) &svaddr, sizeof(svaddr)) != 0) {
                sleep(1);
            } else {
                log_debug("http: connected");
                hev->fd = cfd;
                return 0;
            }
        }
    }

    log_error("http: connect %s |%s:%d| failed", hev->host, hev->ip, hev->port);

err:
    if (cfd != -1) {
        close(cfd);
    }

    return -1;
}

int http_send_request(http_event_t *hev)
{
    http_buffer_t *buffer;
    ssize_t ret;

    buffer = &hev->buffer;

    if (!hev->doing) {
        memset(buffer->buf, '\0', sizeof(buffer->buf));
        snprintf(buffer->buf, sizeof(buffer->buf) - 1, REQUEST_HEAD, hev->uri, hev->host);
        buffer->len = strlen(buffer->buf);
        buffer->cnt = 0;
        buffer->dst = -1;

        hev->doing = 1;

        log_debug("http: request\n%s", buffer->buf);
    }

    while (buffer->cnt < buffer->len) {
        ret = write(hev->fd, buffer->buf + buffer->cnt, buffer->len - buffer->cnt);
        if (ret == -1) {
            if (errno == EAGAIN) {
                return EAGAIN;
            }
            goto err;
        }
        
        if (ret == 0) {
            break;
        }

        buffer->cnt += ret;
    }

    if (buffer->cnt == buffer->len) {
        hev->doing = 0;
        return 0;
    }

err:
    log_error("http: request %s failed", hev->uri);
    hev->doing = 0;
    return -1;    
}

int http_read_response(http_event_t *hev)
{
    char line[2048] = {'\0'};
    char buf[64] = {'\0'};
    char *mark, *p;
    int i, ret, end = 0;

    http_buffer_t *buffer = &hev->buffer;

    if (!hev->doing) {
        memset(buffer->buf, '\0', sizeof(buffer->buf));
        buffer->len = 0;
        buffer->cnt = 0;
        buffer->dst = -1;
        hev->doing = 1;
    }

    ret = http_read_headers(hev);
    if (ret == EAGAIN) {
        return EAGAIN;
    } else if (ret == -1) {
        goto err;
    }

    buffer->len = buffer->cnt;
    buffer->cnt = 0;

    while (buffer->cnt < buffer->len) {
        for (i = 0; buffer->cnt < buffer->len && buffer->buf[buffer->cnt] != '\r';
                ++i, ++buffer->cnt) {
            line[i] = buffer->buf[buffer->cnt];
        }

        line[i] = '\0';
        buffer->cnt += strlen("\r\n");

        log_debug("http: header '%s'", line);

        if (strlen(line) == 0) {
            end = 1;
            break;
        }

        if (util_str_begin_with(line, "HTTP/", strlen("HTTP/"))) {
            log_debug("%s", line);
            if (!strstr(line, "200 OK")) {
                log_error("%s", line);
                goto err;
            }
        } else if ((mark = util_str_begin_with(line, "Content-Length: ", strlen("Content-Length: ")))) {
            mark += strlen("Content-Length: ");
            p = mark;
            while (*mark != '\r') {
                ++mark;
            }
            snprintf(buf, mark - p + 1, "%s", p);
            hev->headers_in.content_length = atoi(buf);
        } else if (!strstr(line, ": ")) {
            log_error("http: header format error");
            util_exit();
        }
    }

    if (end != 1) {
        log_error("http: parse header failed, not found the end of headers.");
        goto err;
    }

    hev->doing = 0;
    return 0;

err:
    hev->doing = 0;
    return -1;    
}

int http_download_file(http_event_t *hev)
{
    ssize_t ret;
    struct stat st;
    http_buffer_t *buffer = &hev->buffer;
    char path[256] = {'\0'};

    if (!hev->doing) {
        hev->doing = 1;

        if (hev->headers_in.content_length == 0) {
            log_error("http: Content-Length is 0");
            util_exit();
        }

        if (http_get_file_name(hev) != 0) {
            log_error("http: get file name failed, uri='%s'", hev->uri);
            return -1;
        }

        log_debug("http: saving to '%s', content length %ld bytes, fd=%d", 
            buffer->file, hev->headers_in.content_length, hev->fd);

        if (strlen(buffer->dir) != 0) {
            memcpy(path, buffer->dir, strlen(buffer->dir));
            memcpy(&path[strlen(path)], "/", 1);
            memcpy(&path[strlen(path)], buffer->file, strlen(buffer->file));
        } else {
            memcpy(path, buffer->file, strlen(buffer->file));
        }

        if (stat(path, &st) == 0 && st.st_size == hev->headers_in.content_length) {
            hev->doing = 0;
            buffer->dst = -1;
            return 0;
        }

        if ((buffer->dst = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1) {
            log_error("http: open '%s' failed", path);
            goto err;
        }

        if (buffer->cnt < buffer->len) {
            while (buffer->cnt < buffer->len) {
                ret = write(buffer->dst, &buffer->buf[buffer->cnt], buffer->len - buffer->cnt);
                if (ret == -1) {
                    log_error("http: write to '%s' failed", path);
                    goto err;
                }
                buffer->cnt += ret;
            }
        }    

        buffer->cnt = 0;
        buffer->len = hev->headers_in.content_length - ret;
    }

    ret = http_save_file(hev);

    if (ret == 0) {
        log_debug("http: save '%s' done, fd=%d", buffer->file, hev->fd);

        hev->doing = 0;
        close(buffer->dst);
        buffer->dst = -1;
        return 0;        
    } else if (ret == EAGAIN) {
        return EAGAIN;
    }

err:
    log_error("http: download '%s' failed", buffer->file);

    hev->doing = 0;
    if (buffer->dst != -1) {
        close(buffer->dst);
        buffer->dst = -1;
    }
    return -1;
}

static int http_read_headers(http_event_t *hev)
{
    ssize_t ret;
    http_buffer_t *buffer = &hev->buffer;

    for (;;) {
        ret = read(hev->fd, buffer->buf + buffer->cnt, sizeof(buffer->buf) - buffer->cnt);
        if (ret == -1) {
            if (errno == EAGAIN) {
                return EAGAIN;
            } 
            goto err;
        }
        
        if (ret == 0) {
            if (strstr(buffer->buf, "\r\n\r\n")) {
                return 0;
            } 
            goto err;
        }

        buffer->cnt += ret;

        if (strstr(buffer->buf, "\r\n\r\n")) {
            return 0;
        }
    }

err:
    log_info("http: read headers failed, uri='%s'", hev->uri);
    return -1;
}

static int http_save_file(http_event_t *hev)
{
    ssize_t ret = 0;
    char buf[1024];

    http_buffer_t *buffer = &hev->buffer;

    while (buffer->cnt < buffer->len) {
        memset(buf, '\0', sizeof(buf));
        ret = read(hev->fd, buf, sizeof(buf));
        if (ret == -1) {
            return errno == EAGAIN ? EAGAIN : -1;
        } else if (ret == 0) {
            goto done;
        }
        buffer->cnt += ret;

        if (ret != write(buffer->dst, buf, ret)) {
            log_error( "http: write '%s' failed", buffer->file);
            return -1;
        }
    }

done:
    return buffer->cnt == buffer->len ? 0 : -1;
}

static int http_get_file_name(http_event_t *hev)
{
    char *p, *mark;
    http_buffer_t *buffer;
    int name_len;

    if (strlen(hev->uri) == 0) {
        return -1;
    }

    buffer = &hev->buffer;

    p = hev->uri + strlen(hev->uri);
    mark = p;

    while (p != hev->uri) {
        if (*p == '?') {
            mark = p;
        } else if (*p == '/') {
            break;
        }
        --p;
    }

    ++p;

    name_len = mark - p + 1;
    if (name_len > buffer->filename_len) {
        if (buffer->file) {
            free(buffer->file);
        }

        buffer->file = util_calloc(sizeof(char), name_len);
        if (!buffer->file) {
            return -1;
        }
        buffer->filename_len = name_len;
    }

    snprintf(buffer->file, name_len, "%s", p);

    return 0;
}

int http_parse_url(char *url, http_event_t *hev)
{
    char p[16] = {'\0'};
    char *p1, *p2;
    unsigned short port;

    if (strstr(url, "https://") != NULL) {
        p2 = url + strlen("https://");
    } else if (strstr(url, "http://") != NULL) {
        p2 = url + strlen("http://");
    } else {
        log_error("-i '%s' without http(s)", url);
        return -1;
    }

    p1 = p2;
    while (*p2 != '/' && *p2 != '\0') {
        if (*p2 == ':') {
            memcpy(hev->host, p1, p2 - p1);
            p1 = p2 + 1;
        }
        ++p2;
    }

    if (strlen(hev->host) == 0) {
        memcpy(hev->host, p1, p2 - p1);
        hev->port = 80;
    } else {
        memcpy(p, p1, p2 - p1);
        hev->port = atoi(p);
    }

    snprintf(hev->uri, sizeof(hev->uri), "%s", p2);

    return 0;
}

void http_free_event(http_event_t *hev)
{
    http_buffer_t *buffer;

    buffer = &hev->buffer;

    if (hev->fd != -1) {
        close(hev->fd);
        hev->fd = -1;
    }

    if (buffer->dst != -1) {
        close(buffer->dst);
        buffer->dst = -1;
    }

    if (buffer->file) {
        free(buffer->file);
        buffer->file = NULL;
        buffer->filename_len = 0;
    }

}

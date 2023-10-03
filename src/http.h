/*
 * Copyright (c) hongjunxin
 */

#ifndef _HTTP_H_
#define _HTTP_H_

#include <openssl/ssl.h>
#include "utility.h"

#define HTTP_BUFFER_SIZE 4096*2
#define HTTP_RESP_HEADERS_MAX  128

#define HTTP_SEND_REQUEST   0
#define HTTP_READ_RESPONSE  1
#define HTTP_DOWNLOAD_FILE  2
#define HTTP_DONE           3

typedef struct http_event_s http_event_t;

typedef int (*http_event_handler_pt)(http_event_t *ev);

typedef struct {
    int status;
    ssize_t content_length;
    unsigned chunked:1;
} http_headers_in_t;

typedef struct {
    char key[64];
    char value[256];
} header_t;

typedef struct {
    ssize_t len;
    ssize_t cnt;
    ssize_t pre_cnt;
    int dst;             /* dst file fd */
    char dst_file[256];  /* dst file name */
    char dir[256];       /* dst file dir exclude m3u8 */
    char buf[HTTP_BUFFER_SIZE];
} http_buffer_t;

typedef struct {
    http_event_handler_pt handler;
    unsigned  read:1;
} http_handler_t;

struct http_event_s {
    http_handler_t *handler;
    int current;
    int fd;
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    unsigned short port;
    char host[64];
    char uri[640];
    char parameter[256];  // such as k1=v1&k2=v2
    char ip[16];
    http_buffer_t buffer;
    http_headers_in_t headers_in;
    header_t *resp_headers[HTTP_RESP_HEADERS_MAX];
    int again_timer;
    int tick;
    unsigned doing:1;
    unsigned use_ssl:1;
    unsigned reset_fd:1;
    unsigned done:1;
};

typedef struct ts_list {
    char *m3u8_url;
    char base_uri[256];
    int ts_cnt;
    int taken_cnt;
    int failure;
    int success;
    list_t *ts;
    char* (*get_ts_name)(struct ts_list *self);
} ts_list_t;

int http_insert_header(header_t **hs, header_t *h);
char *http_find_header(header_t **hs, const char *key);
void http_print_header(header_t **hs);

int http_parse_video_url(char *url, http_event_t *hev);
int http_connect_server(http_event_t *hev);
int http_send_request(http_event_t *hev);
int http_read_response(http_event_t *hev);
int http_download_file(http_event_t *hev);
void http_free_event(http_event_t *hev);
int http_update_next_ts_uri(http_event_t *hev, ts_list_t *ts_list);

#endif

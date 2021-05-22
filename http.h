/*
 * Copyright (c) hongjunxin
 */

#ifndef _HTTP_H_
#define _HTTP_H_

#define HTTP_BUFFER_SIZE 4096

typedef struct http_event http_event_t;

typedef int (*http_event_handler_pt)(http_event_t *ev);

typedef struct {
    int status;
    ssize_t content_length;
} http_headers_in_t;

typedef struct {
    ssize_t len;
    ssize_t cnt;
    int dst;        /* dst file fd */
    char *file; /* dst file name */
    int filename_len;
    char dir[256];  /* dst file dir */
    char buf[HTTP_BUFFER_SIZE];
} http_buffer_t;

typedef struct {
    http_event_handler_pt handler;
    unsigned  read:1;
} http_handler_t;

typedef struct http_event {
    http_handler_t *handler;  // free it in http_free_event
    int current;
    int fd;
    unsigned short port;
    char host[64];
    char uri[128];
    char ip[16];
    http_buffer_t buffer;
    http_headers_in_t headers_in;
    int again_timer;
    unsigned doing:1;
} http_event_t;

int http_parse_url(char *url, http_event_t *hev);
int http_connect_server(http_event_t *hev);
int http_get_file(char *host, char* uri, int fd);
int http_get_file_name(http_event_t *hev);
int http_send_request(http_event_t *hev);
int http_read_response(http_event_t *hev);
int http_download_file(http_event_t *hev);
void http_free_event(http_event_t *hev);

#endif

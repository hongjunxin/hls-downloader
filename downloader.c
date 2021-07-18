/*
 * Copyright (c) hongjunxin
 */

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <curl/curl.h>

#include "log.h"
#include "http.h"
#include "epoll.h"
#include "utility.h"
#include "mcurl.h"

static int parse_option(int argc, char **argv);
static void set_log_level(char *level);
static int parse_url(char *url, http_event_t *hev);
static int get_m3u8_file(http_event_t *hev);
static int parse_m3u8(http_event_t *hev, ts_list_t *ts_list);
static int add_download_ts_event(int epfd, http_event_t *hev, ts_list_t *ts_list);
static char* get_ts_file_name(ts_list_t *ts_list);
static void merge_ts_files_task(char *desc_file, char *out_file);
static int check_output_file_format(char *filename_out);
static void signal_handler(int signo);
static int check_file_exist(char *filename);
static int download_ts_files(http_event_t *hevs, ts_list_t *tslist);

extern int errno;
static char *m3u8_url = NULL;
static char *m3u8_file = NULL;
static char *filename_out = NULL;
static int fd_nums = 20;
static http_event_t *hevs;

#define FILE_TS_LIST "ts.list"
#define DEFAULT_OUTPUT_FILE "output.mp4"

#define PRINTF_HIDE_CURSOR() printf("\033[?25l")
#define PRINTF_SHOW_CURSOR() printf("\033[?25h")

int log_level = error;

int main(int argc, char **argv)
{
    struct sigaction sa;
    int epfd, i, len;
    char *oldpath;
    char cmd[256];
    ts_list_t ts_list;    
    pid_t child;
    int wstatus;

    if (check_file_exist("ffmpeg") == -1) {
        printf("error: 'ffmpeg' not found, install it at first.\n");
        return -1;
    }

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) == -1 ||
            sigaction(SIGQUIT, &sa, NULL) == -1) {
        log_error("main: sigaction failed");
        return -1;
    }

    if (parse_option(argc, argv) != 0) {
        return -1;
    }

    if (m3u8_url == NULL) {
        log_error("main: lack of '-i' parameter, '-h' option for help.");
        return -1;
    }

    memset(&ts_list, 0, sizeof(ts_list_t));
    ts_list.get_ts_name = get_ts_file_name;
    ts_list.m3u8_url = m3u8_url;

    hevs = util_calloc(fd_nums, sizeof(http_event_t));
    if (!hevs) {
        return -1;
    }

    for (i = 0; i < fd_nums; ++i) {
        hevs[i].fd = -1;
        hevs[i].buffer.dst = -1;
    }

    PRINTF_HIDE_CURSOR();
    printf("\n");

    if (get_m3u8_file(&hevs[0]) != 0 ||
            parse_m3u8(&hevs[0], &ts_list) != 0 ||
            download_ts_files(hevs, &ts_list) != 0) {
        util_exit();
    }

    if (!filename_out) {
        filename_out = DEFAULT_OUTPUT_FILE;
    }    

    child = fork();

    switch (child) {
        case -1:
            log_error("main: fork failed");
            util_exit();
        case 0:
            if (chdir(hevs[0].buffer.dir) == -1) {
                log_error("main: chdir '%s' failed", hevs[0].buffer.dir);
                util_exit();
            }        
            merge_ts_files_task(FILE_TS_LIST, filename_out);
            break;
        default:
            break;
    }

    waitpid(child, &wstatus, 0);

    if (!WIFEXITED(wstatus)) {
        log_error("main: child %d exit abnormal", child);        
    } else {
        len = strlen(hevs[0].buffer.dir) + strlen(filename_out) + 2;
        oldpath = util_calloc(sizeof(char), len);
        if (!oldpath) {
            util_exit();
        }

        snprintf(oldpath, len, "%s/%s", hevs[0].buffer.dir, filename_out);
        rename(oldpath, filename_out);
        remove(m3u8_file);

        memset(cmd, '\0', sizeof(cmd));
        memcpy(cmd, "rm -rf ", 7);
        memcpy(cmd + 7, hevs[0].buffer.dir, strlen(hevs[0].buffer.dir));
        system(cmd);

        free(oldpath);

        printf("\n\nmerge ts files done, save to '%s'\n", filename_out);        
    }

    PRINTF_SHOW_CURSOR();

    return 0;
}

static int get_m3u8_file(http_event_t *hev)
{
    if (http_parse_url(m3u8_url, hev) != 0) {
        return -1;
    }

#ifdef USE_CURL
    CURL *curl;
    CURLcode ret;
    http_buffer_t *buffer = &hev->buffer;
    char path[256] = {'\0'};

    curl = curl_easy_init();
    if (curl == NULL) {
        log_error("main: curl_easy_init() failed");
        return -1;
    }

    if (http_get_file_name(hev) != 0) {
        log_error("main: get file name failed, uri='%s'", hev->uri);
        goto err;
    }

    if (strlen(buffer->dir) != 0) {
        memcpy(path, buffer->dir, strlen(buffer->dir));
        memcpy(&path[strlen(path)], "/", 1);
        memcpy(&path[strlen(path)], buffer->file, strlen(buffer->file));
    } else {
        memcpy(path, buffer->file, strlen(buffer->file));
    }

    buffer->dst = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (buffer->dst == -1) {
        log_error("http: open '%s' failed", path);
        goto err;
    }

    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_handler);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer->dst);
    curl_easy_setopt(curl, CURLOPT_URL, m3u8_url);

    ret = curl_easy_perform(curl);
    if (ret != CURLE_OK) {
        log_error("main: curl_easy_perform() failed, error='%s'", curl_easy_strerror(ret));
        goto err;
    }

    if (buffer->dst != -1) {
        close(buffer->dst);
    }
    curl_easy_cleanup(curl);
    return 0;

err:
    if (buffer->dst != -1) {
        close(buffer->dst);
    }
    curl_easy_cleanup(curl);
    return -1;

#else
    if (http_connect_server(hev) != 0) {
        return -1;
    }

    if (http_send_request(hev) != 0 ||
           http_read_response(hev) != 0 ||
           http_download_file(hev) != 0) {
        return -1;
    }

    return 0;
#endif
}

static int download_ts_files(http_event_t *hevs, ts_list_t *tslist)
{
    char *mark;
    int i, ret;

    m3u8_file = util_calloc(sizeof(char), hevs[0].buffer.filename_len);
    if (!m3u8_file) {
        util_exit();
    }
    memcpy(m3u8_file, hevs[0].buffer.file, hevs[0].buffer.filename_len);

    mark = strstr(hevs[0].uri, hevs[0].buffer.file);
    memcpy(tslist->base_uri, hevs[0].uri, mark - hevs[0].uri - 1);

#ifdef USE_CURL
    for (i = 1; i < fd_nums; ++i) {
        memcpy(hevs[i].buffer.dir, hevs[0].buffer.dir, strlen(hevs[0].buffer.dir));
    }

    return curl_download_ts_files(hevs, fd_nums, tslist);

#else
    int epfd;

    if ((epfd = epoll_do_create(EPOLL_MAX_EVENTS)) == -1) {
        return -1;
    }

    epoll_nonblocking(hevs[0].fd);
    hevs[0].reuse_fd = 1;

    if (add_download_ts_event(epfd, &hevs[0], tslist) != 0) {
        return -1;
    }

    for (i = 1; i < fd_nums; ++i) {
        memcpy(hevs[i].buffer.dir, hevs[0].buffer.dir, strlen(hevs[0].buffer.dir));
        memcpy(hevs[i].host, hevs[0].host, strlen(hevs[0].host));
        memcpy(hevs[i].ip, hevs[0].ip, strlen(hevs[0].ip));
        hevs[i].port = hevs[0].port;
        hevs[i].use_ssl = hevs[0].use_ssl;
        hevs[i].reuse_fd = 1;

        if (http_connect_server(&hevs[i]) != 0) {
            log_error("main: connect |%s:%d| failed", hevs[i].ip, hevs[i].port);
            return -1;
        }
        
        epoll_nonblocking(hevs[i].fd);

        if (add_download_ts_event(epfd, &hevs[i], tslist) != 0) {
            return -1;
        }
    }

    if (epoll_do_wait(epfd, fd_nums, tslist, hevs) == -1) {
        return -1;
    }

#endif

    return 0;
}

static int parse_m3u8(http_event_t *hev, ts_list_t *ts_list)
{
	int src = -1, dst = -1;
    char buffer[4096];
    char line[128];
    char path[128];
    ssize_t cnt, ret, i, mark;
    void *elt;
    char *p;
	
    p = strstr(hev->buffer.file, ".m3u8");
    if (p) {
        snprintf(path, util_min(p - hev->buffer.file + 1, sizeof(path)),
            "%s", hev->buffer.file);
    } else {
        snprintf(path, util_min(strlen(hev->buffer.file) + 1, sizeof(path)), 
            "%s", hev->buffer.file);
    }

    if (mkdir(path, 0644) == -1 && errno != EEXIST) {
        log_error("main: mkdir '%s' failed", path);
        goto err;
    }

    memcpy(hev->buffer.dir, path, strlen(path));

    memset(path, '\0', sizeof(path));
    memcpy(path, hev->buffer.dir, strlen(hev->buffer.dir));
    memcpy(&path[strlen(path)], "/", 1);
    memcpy(&path[strlen(path)], FILE_TS_LIST, strlen(FILE_TS_LIST));

	if ((src = open(hev->buffer.file, O_RDONLY)) == -1) {
        log_error("main: open '%s' failed", hev->buffer.file);
        goto err;
	}

    if ((dst = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1) {
        log_error("main: open '%s' failed", path);
        goto err;
    }

    cnt = 0;

    for (;;) {
        if (lseek(src, cnt, SEEK_SET) == -1) {
            log_error("main: lseek failed (errno=%d)", errno);
            goto err;
        }
        ret = read(src, buffer, sizeof(buffer));
        if (ret == -1) {
            log_error("main: read '%s' failed", hev->buffer.file);
            goto err;
        } else if (ret == 0) {
            break;
        }

        mark = 0;
        for (i = 0; i < ret; ++i) {
            if (buffer[i] == '\n') {
                if (buffer[i - 1] == 's' &&
                        buffer[i - 2] == 't' &&
                        buffer[i -3] == '.')
                {                               
                    ts_list->ts_cnt++;

                    ret = i - mark + strlen("file ''\n") + 1;
                    snprintf(line, ret, "file '%.*s'\n", (int) (i - mark), &buffer[mark]);
                    --ret; /* ignore '\0' */ 
                    if (ret != write(dst, line, ret)) {
                        log_error("main: write '%s' failed", path);
                        goto err;
                    }

                    if (!ts_list->ts) {
                        ts_list->ts = util_create_list(i - mark + 5, 500);
                        if (!ts_list->ts) {
                            return -1;
                        }                                            
                    }
                    elt = util_list_push(ts_list->ts);
                    if (!elt) {
                        return -1;
                    }
                    memcpy(elt, &buffer[mark], i - mark);
                }
                cnt += (i - mark + 1);
                mark = i + 1;
            }            
        }
    }

    if (fsync(dst) != 0) {
        log_error("main: fsync '%s' failed (errno=%d)", FILE_TS_LIST, errno);
        goto err;
    }    

    close(src);
    close(dst);

    return 0;

err:
    if (src != -1) {
        close(src);
    }

    if (dst != -1) {
        close(dst);
    }

    log_error("main: parse m3u8 file failed");

    return -1;
}

static int parse_option(int argc, char **argv)
{
    int ch;
    
    if (argc == 1) {
        return 0;
    }

    while ((ch = getopt(argc, argv, "i:o:l:c:h")) != -1) {
        switch (ch) {
        case 'i':
            m3u8_url = util_calloc(sizeof(char), strlen(optarg) + 1);
            if (!m3u8_url) {
                util_exit();
            }
            memcpy(m3u8_url, optarg, strlen(optarg));
            break;
        case 'o':
            if (check_output_file_format(optarg) != 0) {
                printf("warning! '%s' without valid format, use default output name '%s'\n", 
                    optarg, DEFAULT_OUTPUT_FILE);
                break;
            }
            filename_out = util_calloc(sizeof(char), strlen(optarg) + 1);
            if (!filename_out) {
                util_exit();
            }
            memcpy(filename_out, optarg, strlen(optarg));
            break;
        case 'l':
            set_log_level(optarg);
            break;
        case 'c':
            fd_nums = atoi(optarg);
            if (fd_nums == 0) {
                fd_nums = 10;
            }
            break;
        case 'h':
            printf("-i [m3u8 url]               eg: '-i https://example.com/hls/index.m3u8'\n"
                   "-o [output path]            eg: '-o output.mp4'\n"   
                   "-l [error|warn|info|debug]\n" 
                   "-c [num]                    concurrent fd to download ts file\n"          
                   "-h                          show this help\n");
            exit(0);
        case '?':
            return -1;
        }
    }

    return 0;
}

static void set_log_level(char *level)
{
    if (!strcmp(level, "error")) {
        log_level = error;
    } else if (!strcmp(level, "warn")) {
        log_level = warn;
    } else if (!strcmp(level, "info")) {
        log_level = info;
    } else if (!strcmp(level, "debug")) {
        log_level = debug;
    }
}

static int add_download_ts_event(int epfd, http_event_t *hev, ts_list_t *ts_list)
{
    struct epoll_event ev;
    char *ts;

    ev.data.ptr = hev;

    ts = ts_list->get_ts_name(ts_list);
    if (!ts) {
        return 0;
    }

    memset(hev->uri, '\0', sizeof(hev->uri));
    memcpy(hev->uri, ts_list->base_uri, strlen(ts_list->base_uri));
    memcpy(&hev->uri[strlen(hev->uri)], "/", 1);
    memcpy(&hev->uri[strlen(hev->uri)], ts, strlen(ts));

    hev->handler = util_calloc(4, sizeof(http_handler_t));
    if (!hev->handler) {
        return -1;
    }

    hev->handler[HTTP_SEND_REQUEST].handler = http_send_request;
    hev->handler[HTTP_SEND_REQUEST].read = 0;
    hev->handler[HTTP_READ_RESPONSE].handler = http_read_response;
    hev->handler[HTTP_READ_RESPONSE].read = 1;
    hev->handler[HTTP_DOWNLOAD_FILE].handler = http_download_file;
    hev->handler[HTTP_DOWNLOAD_FILE].read = 1;
    hev->handler[HTTP_DONE].handler = NULL;

    if (epoll_do_ctl(epfd, EPOLL_CTL_ADD, &ev) == -1) {
        return -1;
    }
    
    return 0;   
}

static char* get_ts_file_name(ts_list_t *ts_list)
{
    int npart, nelt, i;
    list_part_t *part;
    char *elt;

    if (ts_list->taken_cnt >= ts_list->ts_cnt) {
        return NULL;
    }
    
    npart = ts_list->taken_cnt / ts_list->ts->nalloc;    
    if (npart >= ts_list->ts->npart) {
        return NULL;
    }

    part = &ts_list->ts->part;
    for (i = 0; i < npart; ++i) {
        part = part->next;
    }

    nelt = ts_list->taken_cnt % ts_list->ts->nalloc;
    if (nelt >= part->nelts) {
        return NULL;
    }
 
    elt = part->elts + ts_list->ts->size * nelt;
    ts_list->taken_cnt++;

    return elt;
}

static void merge_ts_files_task(char *desc_file, char *out_file)
{
    char *cmd = "ffmpeg";
    char *argv[] = {cmd, "-f", "concat", "-safe", "0", "-i",
        desc_file, "-c", "copy", out_file, NULL};

    remove(out_file);

    if (execvp(cmd, argv) == -1) {
        log_error("main: execvp '%s' failed", cmd);
        util_exit();
    }
}

static int check_output_file_format(char *filename_out)
{
    char *mark, **f;
    char suffix[8] = {'\0'};
    int i;
    char *format[] = {"mp4", "mkv", "wmv", "rmvb", "mpg", "mpeg",
        "3gp", "mov", "avi", "flv", "asf", "asx", NULL};

    mark = strstr(filename_out, ".");
    if (!mark) {
        return -1;
    }

    ++mark;

    for (i = 0; *mark != '\0' && i < sizeof(suffix) - 1; ++mark, ++i) {
        suffix[i] = *mark;
    }

    if (strlen(suffix) == 0) {
        return -1;
    }

    for (f = format; *f != NULL; ++f) {
        if (strcmp(*f, suffix) == 0) {
            return 0;
        }
    }

    return -1;
}

static void signal_handler(int signo)
{
    if (signo == SIGINT || signo == SIGQUIT) {
        PRINTF_SHOW_CURSOR();
    }

    exit(-1);
}

static int check_file_exist(char *filename)
{
    char *prefix[] = {"/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/usr/local/bin", "/usr/local/sbin", NULL};

    char **p;
    char path[128];

    for (p = prefix; *p != NULL; ++p) {
        snprintf(path, strlen(*p) + strlen(filename) + 2, "%s/%s", *p, filename);
        if (access(path, F_OK) == 0) {
            return 0;
        }
    }

    memset(path, '\0', sizeof(path));

    for (p = prefix; *p != NULL; ++p) {
        memcpy(&path[strlen(path)], *p, strlen(*p));
        memcpy(&path[strlen(path)], ":", 1);
    }

    path[strlen(path) - 1] = '\0';

    printf("error: '%s' not found in '%s'\n", filename, path);

    return -1;
}

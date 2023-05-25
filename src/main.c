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

#include "log.h"
#include "utility.h"
#include "media.h"

typedef struct config {
    int fd_nums;
    char *video_url;    // such as http://xxx/yy.m3u8 or http://xxx/yy.flv
    char *filename_out;
} config_t;

static int parse_option(int argc, char **argv, config_t *conf);
static void set_log_level(char *level);
static int check_output_file_format(char *filename_out);
static void signal_handler(int signo);
static int check_file_exist(char *filename);

extern int errno;
#define DEFAULT_OUTPUT_FILE "output.mp4"

int log_level = error;

int main(int argc, char **argv)
{
    struct sigaction sa;
    int ret;
    config_t config = {.fd_nums = 20, .video_url = NULL, .filename_out = NULL};

#if USE_FFMPEG_TOOL

    if (check_file_exist("ffmpeg") == -1) {
        printf("error: 'ffmpeg' not found, install it at first.\n");
        return -1;
    }

#endif

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) == -1 ||
            sigaction(SIGQUIT, &sa, NULL) == -1) {
        log_error("main: sigaction failed");
        return -1;
    }

    if (parse_option(argc, argv, &config) != 0) {
        return -1;
    }

    PRINTF_HIDE_CURSOR();
    ret = download_video(config.video_url, config.filename_out, config.fd_nums);
    if (ret == -1) {
        log_error("main: download video from %s failed", config.video_url);
    }

    PRINTF_SHOW_CURSOR();
    return ret;
}

static int parse_option(int argc, char **argv, config_t *conf)
{
    int ch;
    
    if (argc == 1) {
        return 0;
    }

    while ((ch = getopt(argc, argv, "i:o:l:c:h")) != -1) {
        switch (ch) {
        case 'i':
            conf->video_url = util_calloc(sizeof(char), strlen(optarg) + 1);
            if (!conf->video_url) {
                return -1;
            }
            memcpy(conf->video_url, optarg, strlen(optarg));
            break;
        case 'o':
            if (check_output_file_format(optarg) != 0) {
                printf("warning! '%s' without valid format, use default output name '%s'\n", 
                    optarg, DEFAULT_OUTPUT_FILE);
                conf->filename_out = DEFAULT_OUTPUT_FILE;
            } else {
                conf->filename_out = util_calloc(sizeof(char), strlen(optarg) + 1);
                if (!conf->filename_out) {
                    return -1;
                }
                memcpy(conf->filename_out, optarg, strlen(optarg));
            }
            break;
        case 'l':
            set_log_level(optarg);
            break;
        case 'c':
            conf->fd_nums = atoi(optarg);
            if (conf->fd_nums == 0) {
                conf->fd_nums = 10;
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

    if (conf->video_url == NULL) {
        log_error("main: lack of '-i' parameter, '-h' option for help.");
        return -1;
    }

    if (conf->filename_out == NULL) {
        conf->filename_out = DEFAULT_OUTPUT_FILE;
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

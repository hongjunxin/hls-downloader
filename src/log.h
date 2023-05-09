/*
 * Copyright (c) hongjunxin
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <sys/time.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

extern int log_level;

static char date[128] = {'\0'};

static char *get_localtime(void)
{
    struct tm tm;
    struct timeval now;

    gettimeofday(&now, NULL);
    strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", localtime_r(&now.tv_sec, &tm));

    return date;
}

typedef enum {
    error,
    warn,
    info,
    debug,
} log_level_t;

/*
#define log_error(msg, ...) \
    if (log_level >= error) { \
        fprintf(stderr, "[%s][error] ", get_localtime()); \
        fprintf(stderr, msg, ##__VA_ARGS__); \
        fprintf(stderr, "\n");  \
    } \

#define log_info(msg, ...) \
    if (log_level >= info) { \
        fprintf(stderr, "[%s][info] ", get_localtime()); \
        fprintf(stderr, msg, ##__VA_ARGS__); \
        fprintf(stderr, "\n");  \
    } \
*/

#define log_error(msg, ...) \
    if (log_level >= error) { \
        fprintf(stderr, "[error] "); \
        fprintf(stderr, msg, ##__VA_ARGS__); \
        fprintf(stderr, "\n");  \
        if (errno != 0)  { \
            perror("[error]");\
        } \
    } \

#define log_info(msg, ...) \
    if (log_level >= info) { \
        fprintf(stderr, "[info] "); \
        fprintf(stderr, msg, ##__VA_ARGS__); \
        fprintf(stderr, "\n");  \
    } \

#define log_debug(msg, ...) \
    if (log_level >= debug) { \
        fprintf(stderr, "[debug] "); \
        fprintf(stderr, msg, ##__VA_ARGS__); \
        fprintf(stderr, "\n");  \
    } \

#endif

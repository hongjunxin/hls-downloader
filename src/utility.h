/*
 * Copyright (c) hongjunxin
 */

#ifndef _UTILITY_H_
#define _UTILITY_H_

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define util_min(val1, val2)    ((val1) < (val2) ? (val1) : (val2))

typedef struct list_part {
    void *elts;
    int nelts;
    struct list_part *next;
} list_part_t;

typedef struct {
    list_part_t part;
    list_part_t *last;
    int npart;
    int nalloc;
    int size;
} list_t;

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

void *util_calloc(size_t nmemb, size_t size);
void *util_list_push(list_t *l);
list_t *util_create_list(int size, int nalloc);
char *util_str_begin_with(char *haystack, char *needle, size_t len);
void util_exit(void);
void util_show_download_progress(ts_list_t *ts_list);

#endif

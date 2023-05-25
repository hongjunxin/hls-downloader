/*
 * Copyright (c) hongjunxin
 */

#ifndef _UTILITY_H_
#define _UTILITY_H_

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define util_min(val1, val2)    ((val1) < (val2) ? (val1) : (val2))
#define PRINTF_HIDE_CURSOR() printf("\033[?25l")
#define PRINTF_SHOW_CURSOR() printf("\033[?25h")

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

void *util_calloc(size_t nmemb, size_t size);
void *util_list_push(list_t *l);
list_t *util_create_list(int size, int nalloc);
char *util_str_begin_with(char *haystack, char *needle, size_t len);
void util_show_progress(const char *hint, int done, int total);

#endif

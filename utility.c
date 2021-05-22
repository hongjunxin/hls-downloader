/*
 * Copyright (c) hongjunxin
 */

#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include "utility.h"
#include "log.h"

void *util_calloc(size_t nmemb, size_t size)
{
    void *ret;

    ret = calloc(nmemb, size);

    if (!ret) {
        log_error("util: calloc %ld bytes failed", nmemb * size);
        return NULL;
    }

    return ret;
}

list_t *util_create_list(int size, int nalloc)
{
    list_t *list;

    list = util_calloc(1, sizeof(list_t));
    if (!list) {
        return NULL;
    }

    list->nalloc = nalloc;
    list->size = size;

    list->part.elts = util_calloc(nalloc, size);
    if (!list->part.elts) {
        free(list);
        return NULL;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->npart = 1;

    return list;
}

void *util_list_push(list_t *l)
{
    void *elt;
    list_part_t *last;

    last = l->last;

    if (last->nelts == l->nalloc) {

        last = util_calloc(1, sizeof(list_part_t));
        if (!last) {
            return NULL;
        }

        last->elts = util_calloc(l->nalloc, l->size);
        if (!last->elts) {
            free(last);
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

        l->last->next = last;
        l->last = last;
        l->npart++;
    }

    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;

    return elt;
}

char *util_str_begin_with(char *haystack, char *needle, size_t len)
{
    char *ret;

    ret = haystack;

    if (strlen(haystack) < len || strlen(needle) < len) {
        return NULL;
    }

    while (len--) {
        if (*haystack != *needle) {
            return NULL;
        }
        ++haystack;
        ++needle;
    }

    return ret;
}

void util_exit(void)
{
    kill(getpid(), SIGQUIT);
    sleep(3);
}

void util_show_download_progress(ts_list_t *ts_list)
{
    char bar[52] = {'\0'};
    int percent, i;

    percent = ts_list->success * 100 / ts_list->ts_cnt;

    for (i = 0; i < percent / 2; ++i) {
        bar[i] = '=';
    }
    bar[i] = '>';

    printf("download ts files... %%%d [%-51s] [%d/%d]\r", 
        percent, bar, ts_list->success, ts_list->ts_cnt);
}

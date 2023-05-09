/*
 * Copyright (c) hongjunxin
 */

#ifndef _MEDIA_H_
#define _MEDIA_H_

#include "utility.h"

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

int download_video(char *video_url, char *filename_out, int fd_nums);
void util_show_download_progress(ts_list_t *ts_list);

#endif
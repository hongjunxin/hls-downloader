#pragma

typedef struct config {
    int fd_nums;
    char segment_file_suffix[8];
    char *video_url;    // such as http://xxx/yy.m3u8 or http://xxx/yy.flv
    char *filename_out;
} config_t;

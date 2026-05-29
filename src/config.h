#pragma

#define REQUEST_HEADERS_MAX 32
#define REQUEST_HEADER_LEN 1024

typedef struct config {
    int fd_nums;
    char segment_file_suffix[8];
    char *video_url;    // such as http://xxx/yy.m3u8 or http://xxx/yy.flv
    char *filename_out;
    char request_headers[REQUEST_HEADERS_MAX][REQUEST_HEADER_LEN];
    int request_header_count;
} config_t;

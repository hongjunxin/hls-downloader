#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <libavutil/timestamp.h>
#include <libavformat/avformat.h>

#include "media.h"
#include "http.h"
#include "epoll.h"
#include "log.h"

static int download_hls(char *m3u8_url, char *filename_out, int fd_nums);
static int get_m3u8_file(http_event_t *hev, ts_list_t *ts_list);
static int parse_m3u8_file(http_event_t *hev, ts_list_t *ts_list);
static int download_ts_files(http_event_t *hevs, ts_list_t *tslist, int fd_nums);
static int add_download_ts_event(int epfd, http_event_t *hev, ts_list_t *ts_list);
static char* get_ts_file_name(ts_list_t *ts_list);
static void merge_ts_files_task(char *desc_file, char *out_file); // use ffmpeg tool
static int merge_ts_files(const char *ts_list, int ts_nums, const char *out_filename); // use ffmpeg libav

static char m3u8_file[256] = {'\0'};

#define FILE_TS_LIST "ts.list"

int download_video(char *video_url, char *filename_out, int fd_nums)
{
    int i;
    
    i = strlen(video_url);
    for (; i >= 0; i--) {
        if (*(video_url + i) == '?') {
            break;
        }
    }

    // no parameters in url
    if (i < 0) {
        i = strlen(video_url);
    }

    for (; i >= 0; i--) {
        if (*(video_url + i) == '.') {
            break;
        }
    }

    if (i < 0) {
        log_error("media: %s not a video url", video_url);
        return -1;
    }
    
    // http://host/path/xxx.m3u8?a=b

    if (strncmp(video_url + i, ".m3u8", strlen(".m3u8")) == 0) {
        return download_hls(video_url, filename_out, fd_nums);
    } else {
        log_error("media: just support download m3u8 so far");
        return -1;
    }

    return 0;
}

static int download_hls(char *m3u8_url, char *filename_out, int fd_nums)
{
    int epfd, i, len, ret;
    http_event_t *hevs = NULL;
    char *oldpath = NULL;
    char cmd[256];
    ts_list_t ts_list;    
    pid_t child;
    int wstatus;

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

    printf("\n");

    if (get_m3u8_file(&hevs[0], &ts_list) != 0) {
        log_error("media: get m3u8 file failed");
        goto error;
    }
    
    if (parse_m3u8_file(&hevs[0], &ts_list) != 0) {
        log_error("media: parse m3u8 file failed");
        goto error;
    }

    if (download_ts_files(hevs, &ts_list, fd_nums) != 0) {
        log_error("media: download ts files failed");
        goto error;
    }

#if USE_FFMPEG_TOOL

    child = fork();
    switch (child) {
        case -1:
            log_error("media: fork failed");
            goto error;
        case 0:
            if (chdir(hevs[0].buffer.dir) == -1) {
                log_error("media: chdir '%s' failed", hevs[0].buffer.dir);
                return -1;
            }
            merge_ts_files_task(FILE_TS_LIST, filename_out);
            exit(0);
        default:
            break;
    }

    waitpid(child, &wstatus, 0);

    if (!WIFEXITED(wstatus)) {
        log_error("media: child %d exit abnormal", child);
        goto error;
    }
#else
    // cd to ts files directory
    if (chdir(hevs[0].buffer.dir) == -1) {
        log_error_errno("media: chdir '%s' failed", hevs[0].buffer.dir);
        goto error;
    }
    if (merge_ts_files(FILE_TS_LIST, ts_list.ts_cnt, filename_out) == -1) {
        log_error("media: merge ts file failed");
        goto error;
    }
    if (chdir("../") == -1) {
        log_error_errno("media: chdir '../' failed");
        goto error;
    }

#endif

    len = strlen(hevs[0].buffer.dir) + strlen(filename_out) + 2;
    oldpath = util_calloc(sizeof(char), len);
    if (!oldpath) {
        goto error;
    }

    snprintf(oldpath, len, "%s/%s", hevs[0].buffer.dir, filename_out);
    rename(oldpath, filename_out);
    remove(m3u8_file);
    memcpy(&m3u8_file[strlen(m3u8_file)], ".done", 5);
    remove(m3u8_file);

    memset(cmd, '\0', sizeof(cmd));
    memcpy(cmd, "rm -rf ", 7);
    memcpy(cmd + 7, hevs[0].buffer.dir, strlen(hevs[0].buffer.dir));
    system(cmd);

    free(oldpath);

    printf("merge ts files done, save to '%s'\n", filename_out);  
    return 0;

error:
    if (hevs) {
        free(hevs);
    }
    return -1;
}

static int get_m3u8_file(http_event_t *hev, ts_list_t *ts_list)
{
    if (http_parse_video_url(ts_list->m3u8_url, hev) != 0) {
        return -1;
    }

    if (http_connect_server(hev) != 0) {
        return -1;
    }

    if (access(hev->buffer.dst_file, F_OK) == 0) {
        log_debug("'%s' already in disk", hev->buffer.dst_file);
        return 0;
    }

    if (http_send_request(hev) != 0 ||
           http_read_response(hev) != 0 ||
           http_download_file(hev) != 0) {
        return -1;
    }

    return 0;
}

static int download_ts_files(http_event_t *hevs, ts_list_t *tslist, int fd_nums)
{
    char *mark;
    int i, ret;

    memcpy(m3u8_file, hevs[0].buffer.dst_file, strlen(hevs[0].buffer.dst_file));

    mark = strstr(hevs[0].uri, hevs[0].buffer.dst_file);
    memcpy(tslist->base_uri, hevs[0].uri, mark - hevs[0].uri - 1);

    int epfd;
    http_event_t *hev;

    if ((epfd = epoll_do_create(EPOLL_MAX_EVENTS)) == -1) {
        return -1;
    }

    hev = &hevs[0];
    if (hev->reset_fd) {
        hev->reset_fd = 0;
        if (http_connect_server(hev) != 0) {
            log_error("media: connect |%s:%d| failed", hev->ip, hev->port);
            return -1;
        }
    }
    epoll_nonblocking(hev->fd);

    if (add_download_ts_event(epfd, hev, tslist) != 0) {
        return -1;
    }

    for (i = 1; i < fd_nums; ++i) {
        memcpy(hevs[i].buffer.dir, hevs[0].buffer.dir, strlen(hevs[0].buffer.dir));
        memcpy(hevs[i].host, hevs[0].host, strlen(hevs[0].host));
        memcpy(hevs[i].ip, hevs[0].ip, strlen(hevs[0].ip));
        memcpy(hevs[i].parameter, hevs[0].parameter, strlen(hevs[0].parameter));
        hevs[i].port = hevs[0].port;
        hevs[i].use_ssl = hevs[0].use_ssl;

        if (http_connect_server(&hevs[i]) != 0) {
            log_error("media: connect |%s:%d| failed", hevs[i].ip, hevs[i].port);
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

    return 0;
}

static int parse_m3u8_file(http_event_t *hev, ts_list_t *ts_list)
{
	int src = -1, dst = -1;
    char buffer[4096];
    char line[128];
    char path[128];
    ssize_t cnt, ret, i, mark;
    void *elt;
    char *p;
	
    p = strstr(hev->buffer.dst_file, ".m3u8");
    if (p) {
        snprintf(path, util_min(p - hev->buffer.dst_file + 1, sizeof(path)),
            "%s", hev->buffer.dst_file);
    } else {
        snprintf(path, util_min(strlen(hev->buffer.dst_file) + 1, sizeof(path)), 
            "%s", hev->buffer.dst_file);
    }

    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        log_error_errno("media: mkdir '%s' failed", path);
        goto err;
    }

    memcpy(hev->buffer.dir, path, strlen(path));

    memset(path, '\0', sizeof(path));
    memcpy(path, hev->buffer.dir, strlen(hev->buffer.dir));
    memcpy(&path[strlen(path)], "/", 1);
    memcpy(&path[strlen(path)], FILE_TS_LIST, strlen(FILE_TS_LIST));

    // open m3u8 file
	if ((src = open(hev->buffer.dst_file, O_RDONLY)) == -1) {
        log_error_errno("media: open '%s' failed", hev->buffer.dst_file);
        goto err;
	}

    if ((dst = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1) {
        log_error_errno("media: open '%s' failed", path);
        goto err;
    }

    cnt = 0;

    for (;;) {
        if (lseek(src, cnt, SEEK_SET) == -1) {
            log_error_errno("media: lseek failed (errno=%d)", errno);
            goto err;
        }
        ret = read(src, buffer, sizeof(buffer));
        if (ret == -1) {
            log_error_errno("media: read '%s' failed", hev->buffer.dst_file);
            goto err;
        } else if (ret == 0) {
            break;
        }

        mark = 0;
        for (i = 0; i < ret; ++i) {
            if (buffer[i] == '\n') {
                buffer[i] = '\0';
                if ((p = strstr(&buffer[mark], ".ts")) != NULL)
                {           
                    ts_list->ts_cnt++;
                    p += strlen(".ts");

                    char *ts_name_begin;
                    if (strstr(&buffer[mark], "http") == NULL) {
                        ts_name_begin = &buffer[mark];
                    } else {
                        ts_name_begin = p;
                        while (*ts_name_begin != '/') {
                            ts_name_begin--;
                        }
                        ts_name_begin++;
                    }

                    ret = p - ts_name_begin + strlen("file ''\n") + 1;
                    snprintf(line, ret, "file '%.*s'\n", (int) (p - ts_name_begin), ts_name_begin);
                    --ret; /* ignore '\0' */ 
                    if (ret != write(dst, line, ret)) {
                        log_error_errno("media: write '%s' failed", path);
                        goto err;
                    }

                    if (!ts_list->ts) {
                        ts_list->ts = util_create_list(p - ts_name_begin + 5, 500);
                        if (!ts_list->ts) {
                            return -1;
                        }                                            
                    }
                    elt = util_list_push(ts_list->ts);
                    if (!elt) {
                        return -1;
                    }
                    memcpy(elt, ts_name_begin, p - ts_name_begin);
                }
                cnt += (i - mark + 1);
                mark = i + 1;
                buffer[i] = '\n';
            }            
        }
    }

    if (fsync(dst) != 0) {
        log_error_errno("media: fsync '%s' failed", FILE_TS_LIST);
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

    return -1;
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
        log_error_errno("media: execvp '%s' failed", cmd);
    }
}

static int add_download_ts_event(int epfd, http_event_t *hev, ts_list_t *ts_list)
{
    struct epoll_event ev;
    char *ts;

    ev.data.ptr = hev;

    if (http_update_next_ts_uri(hev, ts_list) == 0) {
        return 0;
    }

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

static int copy_packet(AVFormatContext *in_format_ctx, 
                            AVFormatContext *out_format_ctx,
                            int *streams_list)
{
    AVPacket packet;
    AVStream *in_stream, *out_stream;
    int ret;
    int number_of_streams = in_format_ctx->nb_streams;

    for (;;) {
        ret = av_read_frame(in_format_ctx, &packet);
        if (ret < 0) {
            break;
        }
        in_stream = in_format_ctx->streams[packet.stream_index];
        if (packet.stream_index >= number_of_streams || streams_list[packet.stream_index] < 0) {
            av_packet_unref(&packet);
            continue;
        }
        packet.stream_index = streams_list[packet.stream_index];
        out_stream = out_format_ctx->streams[packet.stream_index];
        /* copy packet */
        packet.pts = av_rescale_q_rnd(packet.pts, in_stream->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
        packet.dts = av_rescale_q_rnd(packet.dts, in_stream->time_base, out_stream->time_base, AV_ROUND_NEAR_INF|AV_ROUND_PASS_MINMAX);
        packet.duration = av_rescale_q(packet.duration, in_stream->time_base, out_stream->time_base);
        // https://ffmpeg.org/doxygen/trunk/structAVPacket.html#ab5793d8195cf4789dfb3913b7a693903
        packet.pos = -1;

        //https://ffmpeg.org/doxygen/trunk/group__lavf__encoding.html#ga37352ed2c63493c38219d935e71db6c1
        ret = av_interleaved_write_frame(out_format_ctx, &packet);
        if (ret < 0) {
            log_error("media: muxing packet error");
            av_packet_unref(&packet);
            return -1;
        }
        av_packet_unref(&packet);
    }
    return 0;
}

static int get_ts_filename(int fd, char *buffer, int buf_size)
{
    int ret, i = 0;

    lseek(fd, strlen("file '"), SEEK_CUR);

    for (;;) {
        ret = read(fd, buffer + i, 1);
        if (ret != 1) {
            log_error_errno("media: read failed");
            return -1;
        }
        if (buffer[i] == '\'') {
            read(fd, buffer + i, 1); // read '\n' at line end
            buffer[i] = '\0';
            break;
        }
        if (++i >= buf_size) {
            log_error("media: read failed, buffer size not enough");
            return -1;
        }
    }
    return 0;
}

static int merge_ts_files(const char *ts_list, int ts_nums, const char *out_filename)
{
    AVFormatContext *in_format_ctx = NULL, *out_format_ctx = NULL;
    int i, fd = -1, ret = -1;
    int stream_index = 0;
    int number_of_streams = 0;
    int *streams_list = NULL;
    char in_filename[128] = {'\0'};

    fd = open(ts_list, O_RDONLY);
    if (fd == -1) {
        log_error_errno("media: open '%s' failed", ts_list);
        return -1;
    }

    ret = get_ts_filename(fd, in_filename, sizeof(in_filename));
    if (ret == -1) {
        log_error("media: get ts filename from '%s' failed", ts_list);
        goto end;
    }

    ret = avformat_open_input(&in_format_ctx, in_filename, NULL, NULL);
    if (ret < 0) {
        log_error("media: avformat_open_input() open file '%s' failed", in_filename);
        goto end;
    }

    ret = avformat_find_stream_info(in_format_ctx, NULL);
    if (ret < 0) {
        log_error("media: avformat_find_stream_info() from '%s' failed", in_filename);
        goto end;
    }

    avformat_alloc_output_context2(&out_format_ctx, NULL, NULL, out_filename);
    if (out_format_ctx == NULL) {
        log_error("media: avformat_alloc_output_context2() failed");
        ret = AVERROR_UNKNOWN;
        goto end;
    }

    number_of_streams = in_format_ctx->nb_streams;
    streams_list = av_malloc_array(number_of_streams, sizeof(*streams_list));
    memset(streams_list, 0, number_of_streams * sizeof(*streams_list));

    if (streams_list == NULL) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    for (i = 0; i < in_format_ctx->nb_streams; i++) {
        AVStream *out_stream;
        AVStream *in_stream = in_format_ctx->streams[i];
        AVCodecParameters *in_codecpar = in_stream->codecpar;

        if (in_codecpar->codec_type != AVMEDIA_TYPE_AUDIO &&
                in_codecpar->codec_type != AVMEDIA_TYPE_VIDEO &&
                in_codecpar->codec_type != AVMEDIA_TYPE_SUBTITLE) {
            streams_list[i] = -1;
            continue;
        }

        streams_list[i] = stream_index++;
        out_stream = avformat_new_stream(out_format_ctx, NULL);
        if (out_stream == NULL) {
            log_error("media: avformat_new_stream() for output stream failed");
            ret = AVERROR_UNKNOWN;
            goto end;
        }

        ret = avcodec_parameters_copy(out_stream->codecpar, in_codecpar);
        if (ret < 0) {
            log_error("media: failed to copy odec parameters");
            goto end;
        }
        out_stream->codecpar->codec_tag = 0;
    }

    // https://ffmpeg.org/doxygen/trunk/group__lavf__misc.html#gae2645941f2dc779c307eb6314fd39f10
    av_dump_format(out_format_ctx, 0, out_filename, 1);

    // unless it's a no file (we'll talk later about that) write to the disk (FLAG_WRITE)
    // but basically it's a way to save the file to a buffer so you can store it
    // wherever you want.
    if (!(out_format_ctx->oformat->flags & AVFMT_NOFILE)) {
        ret = avio_open(&out_format_ctx->pb, out_filename, AVIO_FLAG_WRITE);
        if (ret < 0) {
            log_error("media: open output file '%s' failed", out_filename);
            goto end;
        }
    }

    AVDictionary* opts = NULL;
    // optional manipulation
    // https://developer.mozilla.org/en-US/docs/Web/API/Media_Source_Extensions_API/Transcoding_assets_for_MSE
    // jaxon: cause error "Malformed AAC bitstream detected: use the audio bitstream filter 'aac_adtstoasc' 
    // to fix it ('-bsf:a aac_adtstoasc' option with ffmpeg)" if add this option
    //av_dict_set(&opts, "movflags", "frag_keyframe+empty_moov+default_base_moof", 0);

    // https://ffmpeg.org/doxygen/trunk/group__lavf__encoding.html#ga18b7b10bb5b94c4842de18166bc677cb
    ret = avformat_write_header(out_format_ctx, &opts);
    if (ret < 0) {
        log_error("media: avformat_write_header() for '%s' failed", out_filename);
        goto end;
    }

    ret = copy_packet(in_format_ctx, out_format_ctx, streams_list);
    avformat_close_input(&in_format_ctx);
    if (ret == -1) {
        log_error("media: copy '%s' to '%s' failed", in_filename, out_filename);
        goto end;
    } else {
        int total = ts_nums;
        for (--ts_nums; ts_nums > 0; --ts_nums) {
            util_show_progress("merge ts files...", total - ts_nums, total);
            ret = get_ts_filename(fd, in_filename, sizeof(in_filename));
            if (ret == -1) {
                log_error("media: get ts filename failed");
                goto end;
            }
            ret = avformat_open_input(&in_format_ctx, in_filename, NULL, NULL);
            if (ret < 0) {
                log_error("media: open '%s' failed", in_filename);
                goto end;
            }
            ret = avformat_find_stream_info(in_format_ctx, NULL);
            if (ret < 0) {
                log_error("media: avformat_find_stream_info() from '%s' failed", in_filename);
                goto end;
            }
            ret = copy_packet(in_format_ctx, out_format_ctx, streams_list);
            avformat_close_input(&in_format_ctx);
            if (ret == -1) {
                log_error("media: copy '%s' to '%s' failed", in_filename, out_filename);
                goto end;
            }
        }
        util_show_progress("merge ts files...", total, total);
        printf("\n");
    }

    //https://ffmpeg.org/doxygen/trunk/group__lavf__encoding.html#ga7f14007e7dc8f481f054b21614dfec13
    ret = av_write_trailer(out_format_ctx);
    if (ret < 0) {
        log_error("media: av_write_trailer() for '%s' failed", out_filename);
        goto end;
    }

end:
    if (fd != -1) {
        close(fd);
    }

    if (out_format_ctx) {
        if (!(out_format_ctx->oformat->flags & AVFMT_NOFILE)) {
            avio_closep(&out_format_ctx->pb);
        }
        avformat_free_context(out_format_ctx);
    }

    av_freep(&streams_list);
    if (ret == -1) {
        return ret;
    }
    if (ret < 0 && ret != AVERROR_EOF) {
        log_error("media: libav error \"%s\"", av_err2str(ret));
        return -1;
    }
    return 0;
}

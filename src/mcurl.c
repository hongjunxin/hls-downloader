#include <curl/curl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "mcurl.h"
#include "log.h"
#include "utility.h"

static CURL* curl_init_download_ts_handle(http_event_t *hev, ts_list_t *tslist, CURL *shandle);

size_t curl_write_handler(void *content, size_t size, size_t nmemb, void *userp)
{
    int outfd;

    outfd = *((int*) userp);

    /* libcurl failed if the ret of write not equal size*nmemb */
    return write(outfd, content, size * nmemb);
}

int curl_download_ts_files(http_event_t *hevs, int hevs_cnt, ts_list_t *tslist)
{
    CURLM *mhandle;
    CURL *shandle;
    CURLcode res;
    CURLMcode mc;
    int i, ret, transfers, numfds, msgq;
    struct CURLMsg *msg;
    http_event_t *hev;

    ret = -1;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    mhandle = curl_multi_init();
    if (mhandle == NULL) {
        log_error("mcurl: curl_multi_init() failed");
        return ret;
    }

    for (i = 0; i < hevs_cnt; ++i) {

        if (tslist->taken_cnt >= tslist->ts_cnt) {
            break;
        }

        shandle = curl_init_download_ts_handle(&hevs[i], tslist, NULL);
        if (shandle == NULL) {
            log_error("mcurl: curl_add_download_ts_event() failed");
            goto end;
        }
  
        res = curl_multi_add_handle(mhandle, shandle);
        if (res != CURLM_OK) {
            /* todo: how to cleanup shandle */
            log_error("mcurl: curl_multi_add_handle() failed");
            goto end;
        }
    }

    do {
        mc = curl_multi_perform(mhandle, &transfers);
        if (mc != CURLM_OK) {
            log_error("mcurl: curl_multi_perform() failed");
            goto end;
        }

        if (transfers) {
            mc = curl_multi_poll(mhandle, NULL, 0, -1, NULL);
            if (mc != CURLM_OK) {
                log_error("mcurl: curl_multi_poll() failed, error='%s'", curl_multi_strerror(mc));
                goto end;
            }
        }

        msg = curl_multi_info_read(mhandle, &msgq);

        if (msg && msg->msg == CURLMSG_DONE) {
            shandle = msg->easy_handle;
            curl_easy_getinfo(shandle, CURLINFO_PRIVATE, &hev);
            close(hev->buffer.dst);
            curl_multi_remove_handle(mhandle, shandle);

            if (tslist->taken_cnt < tslist->ts_cnt) {
                shandle = curl_init_download_ts_handle(hev, tslist, shandle);
                if (shandle == NULL) {
                    log_error("mcurl: curl_add_download_ts_event() failed");
                    goto end;
                }
                
                res = curl_multi_add_handle(mhandle, shandle);
                if (res != CURLM_OK) {
                    log_error("curl_multi_add_handle() failed (code=%d)", res);
                    goto end;
                }

                ++transfers;
            } else {
                curl_easy_cleanup(shandle);
            }

            tslist->success++;
            util_show_download_progress(tslist);
        }

    } while (transfers);

    ret = 0;

end:
    curl_multi_cleanup(mhandle);
    curl_global_cleanup();

    return ret;
}

static CURL* curl_init_download_ts_handle(http_event_t *hev, ts_list_t *tslist, CURL *shandle)
{
    http_buffer_t *buffer;
    char path[256] = {'\0'};
    char url[256] = {'\0'};
    char *ts, *p;
    int len;
    static char *url_pre = NULL;

    buffer = &hev->buffer;

    ts = tslist->get_ts_name(tslist);
    if (!ts) {
        return NULL;
    }

    memset(hev->uri, '\0', sizeof(hev->uri));
    memcpy(hev->uri, tslist->base_uri, strlen(tslist->base_uri));
    memcpy(&hev->uri[strlen(hev->uri)], "/", 1);
    memcpy(&hev->uri[strlen(hev->uri)], ts, strlen(ts));

    if (http_get_file_name(hev) != 0) {
        log_error("mcurl: get file name failed, uri='%s'", hev->uri);
        return NULL;
    }

    if (strlen(buffer->dir) != 0) {
        memcpy(path, buffer->dir, strlen(buffer->dir));
        memcpy(&path[strlen(path)], "/", 1);
        memcpy(&path[strlen(path)], buffer->dst_file, strlen(buffer->dst_file));
    } else {
        memcpy(path, buffer->dst_file, strlen(buffer->dst_file));
    }

    if ((buffer->dst = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1) {
        log_error_errno("http: open '%s' failed", path);
        return NULL;
    }

    if (shandle == NULL) {
        shandle = curl_easy_init();
        if (shandle == NULL) {
            log_error("mcurl: curl_easy_init() failed");
            close(buffer->dst);
            return NULL;
        }
    } else {
        curl_easy_reset(shandle);
    }

    if (url_pre == NULL) {
        p = strstr(tslist->m3u8_url, "https://");
        if (p != NULL) {
            p = tslist->m3u8_url + strlen("https://");
        } else {
            p = tslist->m3u8_url + strlen("http://");
        }

        while (*p != '/') {
            ++p;
        }

        len = p - tslist->m3u8_url;
        url_pre = calloc(len, sizeof(char));
        memcpy(url_pre, tslist->m3u8_url, len);
    }

    snprintf(url, sizeof(url), "%s%s", url_pre, hev->uri);

    log_debug("mcurl: download '%s'", url);

    curl_easy_setopt(shandle, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(shandle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(shandle, CURLOPT_WRITEFUNCTION, curl_write_handler);
    curl_easy_setopt(shandle, CURLOPT_WRITEDATA, &buffer->dst);
    curl_easy_setopt(shandle, CURLOPT_URL, url);
    curl_easy_setopt(shandle, CURLOPT_PRIVATE, hev);
    curl_easy_setopt(shandle, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0");

    return shandle;
}

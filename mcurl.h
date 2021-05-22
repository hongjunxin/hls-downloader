#ifndef _MCURL_H_
#define _MCURL_H_

#include "http.h"
#include "utility.h"

size_t curl_write_handler(void *content, size_t size, size_t nmemb, void *userp);
int curl_download_ts_files(http_event_t *hevs, int hevs_cnt, ts_list_t *tslist);

#endif

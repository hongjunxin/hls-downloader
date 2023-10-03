/*
 * Copyright (c) hongjunxin
 */

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include "log.h"
#include "http.h"
#include "utility.h"

#define REQUEST_HEAD \
        "GET %s HTTP/1.1\r\n"                      \
        "User-Agent: Wget/1.20.3 (linux-gnu)\r\n"  \
        "Accept: */*\r\n"                          \
        "Host: %s\r\n"                             \
        "Connection: Keep-Alive\r\n"               \
        "\r\n"                                     \

extern int errno;
extern int h_errno;

static int http_save_file(http_event_t *hev);
static int http_save_chunked_file(http_event_t *hev);
static int http_get_chunked_size(const char *hex, int *size);
static int http_get_resp_headers(http_event_t *hev);
static int http_ssl_connect(http_event_t *hev);
static int check_server_certificate(X509 *cert, char *host);
static void error_string(unsigned long err);

int http_connect_server(http_event_t *hev)
{
    struct sockaddr_in svaddr;
    struct hostent* hostent;
    int cfd = -1;
    int i, cnt, try_timer, ret;

    if (hev->use_ssl) {
        return http_ssl_connect(hev);
    }

    memset(&svaddr, 0, sizeof(svaddr));
    svaddr.sin_port = htons(hev->port);
    svaddr.sin_family = AF_INET;
    
    cfd = socket(AF_INET, SOCK_STREAM, 0);  /* lack AF_INET6 */
    if (cfd == -1) {
        log_error_errno( "http: socket failed");
        goto err;        
    }

    if (hev->fd != -1) {
        close(hev->fd);
        hev->fd = -1;
    }

    try_timer = 10;

    if (strlen(hev->ip) != 0) {
        if (inet_pton(AF_INET, hev->ip, &svaddr.sin_addr) == 1) {

            log_debug("http: connecting %s |%s:%d|", hev->host, hev->ip, hev->port);

            for (i = 0; i < try_timer; ++i) {
                if (connect(cfd, (struct sockaddr *) &svaddr, sizeof(svaddr)) != 0) {
                    sleep(1);
                } else {
                    log_debug("http: connected");
                    hev->fd = cfd;
                    return 0;
                }                
            }
        }
    }

    hostent = gethostbyname(hev->host);    
    if (!hostent) {
        log_error("http: %s", hstrerror(h_errno));
        return -1;
    }        

    for (i = 0; hostent->h_addr_list[i]; i++) {
        svaddr.sin_addr = *(struct in_addr*) hostent->h_addr_list[i];
        svaddr.sin_family = hostent->h_addrtype;
        inet_ntop(svaddr.sin_family, &svaddr.sin_addr, hev->ip, sizeof(hev->ip) - 1);

        log_debug("http: connecting %s |%s:%d|", hev->host, hev->ip, hev->port);

        for (cnt = 0; i < try_timer; ++cnt) {
            if (connect(cfd, (struct sockaddr *) &svaddr, sizeof(svaddr)) != 0) {
                sleep(1);
            } else {
                log_debug("http: connected");
                hev->fd = cfd;
                return 0;
            }
        }
    }

    log_error("http: connect %s |%s:%d| failed", hev->host, hev->ip, hev->port);

err:
    if (cfd != -1) {
        close(cfd);
    }

    return -1;
}

static void ssl_info_callback(const SSL *ssl, int where, int ret)
{
    if (where & SSL_CB_ALERT) {
        if (ret != 256) {
            log_error("http: TLS alert, %s", SSL_alert_desc_string_long(ret));
        }
    }
}

static int do_ssl_connect(http_event_t *hev)
{
    SSL *ssl = NULL;
    SSL_CTX *ctx = NULL;
    X509 *server_cert;
    const char *str;
    int ret, err;

    ctx = SSL_CTX_new(TLS_client_method()); // version-flexible

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
	SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
	SSL_CTX_set_info_callback(ctx, ssl_info_callback);

    // if use SSL_VERIFY_PEER option in SSL_CTX_set_verify()
    // we needn't verify server certificate by ourself through
    // check_server_certificate(server_cert, hev->host)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    //SSL_CTX_set_read_ahead(ctx, 1);
	//SSL_CTX_set_quiet_shutdown(ctx, 1);
    //SSL_CTX_set_verify_depth(ctx, 2);

    // we can call SSL_CTX_load_verify_locations(cert.pem) to specify CAfile,
    // but here use the default system certificate trust store
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        log_warn("http: SSL root CA certificates unavailable");
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, hev->fd);

    SSL_set_hostflags(ssl, 0);  // flags default 0
    SSL_set1_host(ssl, hev->host);

    // one IP can bind to more than one hostname
    // in this case we should tell server which hostname we want to access.
    SSL_set_tlsext_host_name(ssl, hev->host);
    
    // todo: this code block do what?
    // BIO *in_bio, *out_bio;
	// if (!(in_bio = BIO_new(BIO_s_mem())) || !(out_bio = BIO_new(BIO_s_mem()))) {
    //     log_error("http: BIO_new() failed");
    //     goto error;
    // }
	// BIO_set_mem_eof_return(in_bio, -1);
	// BIO_set_mem_eof_return(out_bio, -1);
	// SSL_set_bio(ssl, in_bio, out_bio);

    // When using the SSL_connect(3) or SSL_accept(3) routines, 
    // the correct handshake routines are automatically set. So needn't
    // call SSL_set_connect_state() explicitly
    ret = SSL_connect(ssl);
    if (ret != 1) {
        err = SSL_get_error(ssl, ret);  // err such as SSL_ERROR_SYSCALL
        log_error("http: ssl connect failed, ret=%d, err=%d", ret, err);
        error_string(err);
        goto error;
    }

    if (log_level >= debug) {
        server_cert = SSL_get_peer_certificate(ssl);
        str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
        log_debug("server certificate:");
        log_debug("subject: %s", str);
        str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
        log_debug("issuer: %s", str);
        X509_free(server_cert);
    }

    hev->ssl = ssl;
    hev->ssl_ctx = ctx;
    return 0;

error:
    if (ssl != NULL) {
        SSL_free(ssl);
    }

    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    
    return -1;
}

static int http_ssl_connect(http_event_t *hev)
{
    int cfd = -1;
    int ret, i, cnt, try_timer;
    struct hostent *hostent;
    struct sockaddr_in svaddr;
    
    memset(&svaddr, 0, sizeof(svaddr));
    svaddr.sin_port = htons(hev->port);
    svaddr.sin_family = AF_INET;
    
    cfd = socket(AF_INET, SOCK_STREAM, 0);  /* lack AF_INET6 */
    if (cfd == -1) {
        log_error_errno( "http: socket failed");
        return -1;
    }

    if (hev->fd != -1) {
        close(hev->fd);
        hev->fd = -1;
    }

    if (hev->ssl != NULL) {
        SSL_shutdown(hev->ssl);
        SSL_free(hev->ssl);
        hev->ssl = NULL;
    }

    if (hev->ssl_ctx != NULL) {
        SSL_CTX_free(hev->ssl_ctx);
        hev->ssl_ctx = NULL;
    }

    try_timer = 10;

    // already got server ip
    if (strlen(hev->ip) != 0) {
        if (inet_pton(AF_INET, hev->ip, &svaddr.sin_addr) == 1) {

            log_debug("http: connecting %s |%s:%d|", hev->host, hev->ip, hev->port);

            for (i = 0; i < try_timer; ++i) {
                if (connect(cfd, (struct sockaddr *) &svaddr, sizeof(svaddr)) != 0) {
                    sleep(1);
                } else {
                    log_debug("http: tcp connected");
                    hev->fd = cfd;

                    if (do_ssl_connect(hev) == 0) {
                        log_debug("http: ssl connected");
                        return 0;
                    } else {
                        goto error;
                    }
                }                
            }
        }
    }

    hostent = gethostbyname(hev->host);
    if (!hostent) {
        log_error("http: %s", hstrerror(h_errno));
        goto error;
    }        

    for (i = 0; hostent->h_addr_list[i]; i++) {
        svaddr.sin_addr = *(struct in_addr*) hostent->h_addr_list[i];
        svaddr.sin_family = hostent->h_addrtype;
        svaddr.sin_port = htons(hev->port);
        memset(hev->ip, '\0', sizeof(hev->ip));
        inet_ntop(svaddr.sin_family, &svaddr.sin_addr, hev->ip, sizeof(hev->ip) - 1);

        log_debug("http: connecting %s |%s:%d|", hev->host, hev->ip, hev->port);

        for (cnt = 0; i < try_timer; ++cnt) {
            if (connect(cfd, (struct sockaddr*) &svaddr, sizeof(svaddr)) != 0) {
                sleep(1);
            } else {
                log_debug("http: tcp connected");
                hev->fd = cfd;
                goto next;
            }
        }
    }

next:
    if (do_ssl_connect(hev) != 0) {
        goto error;
    }
    log_debug("http: ssl connected");
    return 0;

error:
    if (cfd != -1) {
        close(cfd);
        hev->fd = -1;
    }
    return -1;
}

static int check_name(char *host, ASN1_STRING *pattern)
{
    int slen, plen;
    const char *s, *p, *mark;

    s = host;
    slen = strlen(host);
    p = ASN1_STRING_get0_data(pattern);
    plen = ASN1_STRING_length(pattern);

    if (slen < plen) {
        return -1;
    }

    if (slen == plen && strncmp(s, p, slen) == 0) {
        return 0;
    }

    if (plen > 2 && p[0] == '*' && p[1] == '.') {
        mark = p + 1;
        s += slen - 1;
        p += plen - 1;
        for (; p > mark; p--, s--) {
            if (*s != *p) {
                return -1;
            }
        }
        return 0;
    }

    return -1;
}

static int check_server_certificate(X509 *cert, char *host)
{
    GENERAL_NAME            *altname;
    STACK_OF(GENERAL_NAME)  *altnames;
    X509_NAME *sname;
    X509_NAME_ENTRY *entry;
    int n, i;
    ASN1_STRING *str;

    altnames = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (altnames) {
        // SubjectAltName maybe more than one
        n = sk_GENERAL_NAME_num(altnames);
        for (i = 0; i < n; i++) {
            altname = sk_GENERAL_NAME_value(altnames, i);
            if (altname->type != GEN_DNS) {
                continue;
            }
            str = altname->d.dNSName;
            if (check_name(host, str) == 0) {
                log_debug("http: host \"%s\" matched cert's SubjectAltName \"%*s\"",
                    host, ASN1_STRING_length(str), ASN1_STRING_get0_data(str));
                log_debug("http: SSL certificate verify ok");
                GENERAL_NAMES_free(altnames);
                return 0;
            }
        }

        log_error("http: host \"%s\" not matched cert's SubjectAltName \"%*s\"",
            host, ASN1_STRING_length(str), ASN1_STRING_get0_data(str));
        log_error("http: SSL certificate verify failed");
        GENERAL_NAMES_free(altnames);
        return -1;
    }

    sname = X509_get_subject_name(cert);
    if (sname == NULL) {
        log_error("http: get subject name failed");
        return -1;
    }

    i = -1;
    for ( ;; ) {
        i = X509_NAME_get_index_by_NID(sname, NID_commonName, i);

        if (i < 0) {
            break;
        }

        entry = X509_NAME_get_entry(sname, i);
        str = X509_NAME_ENTRY_get_data(entry);
        log_debug("SSL commonName: %*s", ASN1_STRING_length(str), ASN1_STRING_get0_data(str));
        if (check_name(host, str) == 0) {
            log_debug("http: host \"%s\" matched cert's CommonName \"%*s\"",
                host, ASN1_STRING_length(str), ASN1_STRING_get0_data(str));
            log_debug("http: SSL certificate verify ok");
            return 0;
        }
    }

    log_error("http: host \"%s\" not matched cert's CommonName \"%*s\"",
        host, ASN1_STRING_length(str), ASN1_STRING_get0_data(str));
    log_error("http: SSL certificate verify failed");

    return -1;
}

static void error_string(unsigned long err)
{
	char buffer[256] = {'\0'};
	ERR_error_string_n(err, buffer, 256);
	log_error("http: ssl error \"%s\"", buffer);
}

int http_send_request(http_event_t *hev)
{
    http_buffer_t *buffer;
    ssize_t ret;

    buffer = &hev->buffer;

    if (!hev->doing) {
        memset(buffer->buf, '\0', sizeof(buffer->buf));
        snprintf(buffer->buf, sizeof(buffer->buf) - 1, REQUEST_HEAD, hev->uri, hev->host);
        buffer->len = strlen(buffer->buf);
        buffer->cnt = 0;
        buffer->dst = -1;
        hev->doing = 1;

        log_debug("\n\nhttp: request (len=%ld), fd=%d\n%s",
            strlen(buffer->buf), hev->fd, buffer->buf);
    }

    while (buffer->cnt < buffer->len) {
        if (hev->use_ssl) {
            ret = SSL_write(hev->ssl, buffer->buf + buffer->cnt, buffer->len - buffer->cnt);
        } else {
            ret = write(hev->fd, buffer->buf + buffer->cnt, buffer->len - buffer->cnt);
        }
        
        if (ret == -1) {
            if (errno == EAGAIN) {
                return EAGAIN;
            }
            goto err;
        }
        
        if (ret == 0) {
            break;
        }

        buffer->cnt += ret;
    }

    if (buffer->cnt == buffer->len) {
        hev->doing = 0;
        return 0;
    }

err:
    log_error("http: request %s failed", hev->uri);
    hev->doing = 0;
    return -1;    
}

int http_read_response(http_event_t *hev)
{
    char line[2048] = {'\0'};
    char buf[64] = {'\0'};
    char *mark, *p;
    int i, ret, end = 0;

    http_buffer_t *buffer = &hev->buffer;

    if (!hev->doing) {
        memset(buffer->buf, '\0', sizeof(buffer->buf));
        buffer->len = 0;
        buffer->cnt = 0;
        buffer->pre_unwritten_len = 0;
        buffer->dst = -1;
        hev->doing = 1;
    }

    ret = http_get_resp_headers(hev);
    if (ret == EAGAIN) {
        return EAGAIN;
    } else if (ret == -1) {
        goto err;
    }

    buffer->len = buffer->cnt;
    buffer->cnt = 0;

    for (i = 0; i < HTTP_RESP_HEADERS_MAX && hev->resp_headers[i]; i++) {
        free(hev->resp_headers[i]);
        hev->resp_headers[i] = NULL;
    }

    while (buffer->cnt < buffer->len) {
        for (i = 0; buffer->cnt < buffer->len && buffer->buf[buffer->cnt] != '\r';
                ++i, ++buffer->cnt) {
            line[i] = buffer->buf[buffer->cnt];
        }

        line[i] = '\0';
        buffer->cnt += strlen("\r\n");

        if (strlen(line) == 0) {
            end = 1;
            break;
        }

        if (util_str_begin_with(line, "HTTP/", strlen("HTTP/"))) {
            log_debug("%s", line);
            if (!strstr(line, "200 OK")) {
                log_error("%s", line);
                goto err;
            }
        } else {
            if (!strstr(line, ": ")) {
                log_error("http: header format error");
                goto err;
            }
            header_t *h = (header_t*) malloc(sizeof(header_t));
            if (!h) {
                log_error("malloc header_t error");
                goto err;
            }
            memset(h, '\0', sizeof(header_t));

            char *p1, *p2;
            p1 = line;
            p2 = strchr(p1, ':');
            memcpy(h->key, p1, p2 - p1);

            p1 = p2 + 2; // skip ": "
            p2 = line + strlen(line);
            memcpy(h->value, p1, p2 - p1);

            if (http_insert_header(hev->resp_headers, h) != 0) {
                goto err;
            }

            if (strcmp(h->key, "Content-Length") == 0) {
                hev->headers_in.content_length = atoi(h->value);
            }

            if (strcmp(h->key, "Transfer-Encoding") == 0 &&
                    strcmp(h->value, "chunked") == 0) {
                hev->headers_in.chunked = 1;        
            }
        }
    }

    if (end != 1) {
        log_error("http: parse header failed, not found the end of headers.");
        goto err;
    }

    if (log_level == debug) {
        log_debug("http: response header, fd=%d", hev->fd);
        http_print_header(hev->resp_headers);
    }

    hev->doing = 0;
    return 0;

err:
    hev->doing = 0;
    return -1;    
}

int http_download_file(http_event_t *hev)
{
    ssize_t ret;
    int fd = -1;
    http_buffer_t *buffer = &hev->buffer;
    
    if (!hev->doing) {
        hev->doing = 1;
        buffer->pre_cnt = 0;

        if (hev->headers_in.content_length == 0 && hev->headers_in.chunked == 0) {
            log_error("http: Content-Length is 0, and not chunked");
            return -1;
        }

        if (hev->headers_in.chunked) {
            log_debug("http: saving to '%s', chunked data, fd=%d", 
                buffer->dst_file, hev->fd);
        } else {
            log_debug("http: saving to '%s', content length %ld bytes, fd=%d", 
                buffer->dst_file, hev->headers_in.content_length, hev->fd);
        }

        char tmppath[522] = {'\0'};
        if (strlen(buffer->dir) > 0) {
            snprintf(tmppath, sizeof(tmppath) - 1, "%s/%s.tmp", buffer->dir, buffer->dst_file);
        } else {
            snprintf(tmppath, sizeof(tmppath) - 1, "%s.tmp", buffer->dst_file);
        }

        if ((buffer->dst = open(tmppath, O_CREAT|O_RDWR|O_TRUNC, 0644)) == -1) {
            log_error("http: open '%s' failed", tmppath);
            goto err;
        }

        if (buffer->cnt < buffer->len) {
            int cnt = buffer->cnt;
            while (buffer->cnt < buffer->len) {
                ret = write(buffer->dst, &buffer->buf[buffer->cnt], buffer->len - buffer->cnt);
                if (ret == -1) {
                    log_error("http: write to '%s' failed, %s", buffer->dst_file, strerror(errno));
                    return -1;
                }
                buffer->cnt += ret;
            }
            buffer->len = hev->headers_in.content_length - (buffer->len - cnt);
        } else {
            buffer->len = hev->headers_in.content_length;
        }

        buffer->cnt = 0;
    }

    if (hev->headers_in.content_length > 0) {
        ret = http_save_file(hev);
    } else {
        ret = http_save_chunked_file(hev);
    }

    if (ret == 0) {
        char dstpath[522] = {'\0'};
        char tmppath[522] = {'\0'};

        if (strlen(buffer->dir) > 0) {
            snprintf(tmppath, sizeof(tmppath) - 1, "%s/%s.tmp", buffer->dir, buffer->dst_file);
            snprintf(dstpath, sizeof(dstpath) - 1, "%s/%s", buffer->dir, buffer->dst_file);
        } else {
            snprintf(tmppath, sizeof(tmppath) - 1, "%s.tmp", buffer->dst_file);
            snprintf(dstpath, sizeof(dstpath) - 1, "%s", buffer->dst_file);
        }

        if (hev->headers_in.chunked) {
            char buf[256 * 1024] = {'\0'};
            fd = open(dstpath, O_CREAT|O_WRONLY|O_TRUNC, 0664);
            if (fd == -1) {
                log_error("open '%s' failed, %s", dstpath, strerror(errno));
                goto err;
            }

            lseek(buffer->dst, 0, SEEK_SET);

            char str_size[32] = {'\0'};
            int i = 0, size;
            for (;;) {
                if (read(buffer->dst, &str_size[i], 1) != 1) {
                    log_error("http: read char from '%s' failed, %s", tmppath, strerror(errno));
                    goto err;
                }
                if (str_size[i] == '\r') {
                    read(buffer->dst, &str_size[i], 1);
                    str_size[i] = '\0';
                    http_get_chunked_size(str_size, &size);
                    if (size == 0) {
                        break;
                    }
                    i = 0;
                    if (size > sizeof(buf)) {
                        int cnt;
                        while (size > 0) {
                            cnt = (size > sizeof(buf)) ? sizeof(buf) : size;
                            if (cnt != read(buffer->dst, buf, cnt)) {
                                log_error("http: read '%s' in part", tmppath);
                                goto err;
                            }
                            if (cnt != write(fd, buf, sizeof(buf))) {
                                log_error("http: write '%s' in part", dstpath);
                                goto err;
                            }
                            size -= sizeof(buf);
                        }
                    } else {
                        if (size != read(buffer->dst, buf, size)) {
                            log_error("http: read '%s' in part", tmppath);
                            goto err;
                        }
                        if (size != write(fd, buf, size)) {
                            log_error("http: write '%s' in part", dstpath);
                            goto err;
                        }
                    }
                    read(buffer->dst, &str_size[i], 2);  // skip "\r\n"
                } else {
                    i++;
                }
            }
            close(fd);
            remove(tmppath);
        } else {
            if (rename(tmppath, dstpath) != 0) {
                log_error("rename '%s' to '%s' failed, fd=%d, %s",
                          tmppath, dstpath, hev->fd, strerror(errno));
            }
        }

        char *closed = http_find_header(hev->resp_headers, "Connection");
        if (closed && strcmp(closed, "close") == 0) {
            hev->reset_fd = 1;
        }

        log_debug("http: save '%s' done, fd=%d", dstpath, hev->fd);

        hev->doing = 0;
        close(buffer->dst);
        buffer->dst = -1;
        return 0;        
    } else if (ret == EAGAIN) { 
        return EAGAIN;
    }

err:
    log_error("http: download '%s' failed", buffer->dst_file);

    hev->doing = 0;
    if (buffer->dst != -1) {
        close(buffer->dst);
        buffer->dst = -1;
    }

    if (fd != -1) {
        close(fd);
    }

    return -1;
}

static int http_get_resp_headers(http_event_t *hev)
{
    ssize_t ret;
    http_buffer_t *buffer = &hev->buffer;

    for (;;) {

        if (buffer->cnt >= sizeof(buffer->buf)) {
            log_info("http: response headers so large (more than %ldk)?",
                sizeof(buffer->buf)/1024);
            goto err;
        }

        if (hev->use_ssl) {
            ret = SSL_read(hev->ssl, buffer->buf + buffer->cnt, sizeof(buffer->buf) - buffer->cnt);
        } else {
            ret = read(hev->fd, buffer->buf + buffer->cnt, sizeof(buffer->buf) - buffer->cnt);
        }
        
        if (ret == -1) {
            if (errno == EAGAIN) {
                return EAGAIN;
            }
            log_info("http: read response error, %s", strerror(errno));
            goto err;
        }
        
        if (ret == 0) {
            if (strstr(buffer->buf, "\r\n\r\n")) {
                return 0;
            }
            if (buffer->cnt == 0) {
                log_info("http: empty response");
            } else {
                log_info("http: missing end mark in respone headers");
            }
            goto err;
        }

        buffer->cnt += ret;

        if (strstr(buffer->buf, "\r\n\r\n")) {
            return 0;
        }
    }

err:
    log_info("http: read headers failed, uri='%s'", hev->uri);
    return -1;
}

static int http_save_file(http_event_t *hev)
{
    ssize_t ret = 0;
    char buf[256 * 1024];

    http_buffer_t *buffer = &hev->buffer;

    while (buffer->cnt < buffer->len) {
        memset(buf, '\0', sizeof(buf));

        if (hev->use_ssl) {
            ret = SSL_read(hev->ssl, buf, sizeof(buf));
        } else {
            ret = read(hev->fd, buf, sizeof(buf));
        }

        if (ret == -1) {
            if (errno != EAGAIN) {
                log_error("http: received body of '%s' error, %s", hev->uri, strerror(errno));
            }
            return errno == EAGAIN ? EAGAIN : -1;
        } else if (ret == 0) {
            goto done;
        }
        buffer->cnt += ret;

        if (ret != write(buffer->dst, buf, ret)) {
            log_error( "http: write '%s' in part", buffer->dst_file);
            return -1;
        }
    }

done:
    if (buffer->cnt != buffer->len) {
        log_error("http: body received in part(%ld|%ld|content-length %ld) of '%s'",
                  buffer->cnt, buffer->len, hev->headers_in.content_length, hev->uri);
        return -1;
    }
    return 0;
}

static int http_get_chunked_size(const char *hex, int *size)
{
    sscanf(hex, "%X", size);
}

static int http_save_chunked_file(http_event_t *hev)
{
    ssize_t ret = 0;
    char buf[256 * 1024];
    int i;

    http_buffer_t *buffer = &hev->buffer;

    for (;;) {
        memset(buf, '\0', sizeof(buf));

        if (hev->use_ssl) {
            ret = SSL_read(hev->ssl, buf, sizeof(buf));
        } else {
            ret = read(hev->fd, buf, sizeof(buf));
        }

        if (ret == -1) {
            if (errno != EAGAIN) {
                log_error("http: received body of '%s' error, %s", hev->uri, strerror(errno));
            }
            return errno == EAGAIN ? EAGAIN : -1;
        }

        if (ret != write(buffer->dst, buf, ret)) {
            log_error( "http: write '%s' in part", buffer->dst_file);
            return -1;
        }

        if (ret > 4 && 
                buf[ret - 4] == '\r' &&
                buf[ret - 3] == '\n' &&
                buf[ret - 2] == '\r' &&
                buf[ret - 1] == '\n') {
            log_debug("http: got the end of chunked data");
            return 0;
        }
    }

    return 0;
}

int http_parse_video_url(char *url, http_event_t *hev)
{
    char p[16] = {'\0'};
    char *p1, *p2, *proxy;
    unsigned short port;

    // todo: ignore https_proxy so far
    if ((proxy = getenv("http_proxy")) != NULL) {
        hev->use_ssl = 0;

        p1 = proxy + strlen("http://");
        p2 = strchr(p1, ':');
        if (p2) {
            memcpy(hev->ip, p1, p2 - p1);
            p1 = p2 + 1;
            p2 = proxy + strlen(proxy);
            memcpy(p, p1, p2 - p1);
            hev->port = atoi(p);
        } else {
            p2 = proxy + strlen(proxy);
            memcpy(hev->ip, p1, p2 - p1);
            hev->port = 80;
        }

        if (strstr(url, "https://") != NULL) {
            p2 = url + strlen("https://");
        } else if (strstr(url, "http://") != NULL) {
            p2 = url + strlen("http://");
        } else {
            log_error("-i '%s' without http(s)", url);
            return -1;
        }

        p1 = p2;
        while (*p2 != '/' && *p2 != '\0') {
            if (*p2 == ':') {
                memcpy(hev->host, p1, p2 - p1);
                p1 = p2 + 1;
            }
            ++p2;
        }

        if (strlen(hev->host) == 0) {
            memcpy(hev->host, p1, p2 - p1);
        }

        log_info("http: use proxy %s:%d, target host '%s'", hev->ip, hev->port, hev->host);

        // hev->uri is url if use proxy, such as http://host/path?k1=v1
        snprintf(hev->uri, sizeof(hev->uri), "%s", url);
    } else {
        if (strstr(url, "https://") != NULL) {
            p2 = url + strlen("https://");
            hev->use_ssl = 1;
        } else if (strstr(url, "http://") != NULL) {
            p2 = url + strlen("http://");
            hev->use_ssl = 0;
        } else {
            log_error("-i '%s' without http(s)", url);
            return -1;
        }

        p1 = p2;
        while (*p2 != '/' && *p2 != '\0') {
            if (*p2 == ':') {
                memcpy(hev->host, p1, p2 - p1);
                p1 = p2 + 1;
            }
            ++p2;
        }

        if (strlen(hev->host) == 0) {
            memcpy(hev->host, p1, p2 - p1);
            hev->port = (hev->use_ssl == 1) ? 443 : 80;
        } else {
            memcpy(p, p1, p2 - p1);
            hev->port = atoi(p);
        }

        // hev->uri include path and parameter
        snprintf(hev->uri, sizeof(hev->uri), "%s", p2);
    }

    p1 = strchr(url, '?');
    if (p1) {
        ++p1;
        p2 = url + strlen(url);
        memcpy(hev->parameter, p1, p2 - p1);

        p2 = p1 - 1;
        p1 = strrchr(url, '/');
        ++p1;
        memcpy(hev->buffer.dst_file, p1, p2 - p1);
    } else {
        p1 = strrchr(url, '/');
        ++p1;
        p2 = url + strlen(url);
        memcpy(hev->buffer.dst_file, p1, p2 - p1);
    }

    return 0;
}

void http_free_event(http_event_t *hev)
{
    http_buffer_t *buffer;

    buffer = &hev->buffer;

    if (hev->fd != -1) {
        if (hev->use_ssl) {
            SSL_shutdown(hev->ssl);
            SSL_free(hev->ssl);
            SSL_CTX_free(hev->ssl_ctx);
            hev->ssl = NULL;
            hev->ssl_ctx = NULL;
        }
        close(hev->fd);
        hev->fd = -1;
    }

    if (hev->done && hev->handler) {
        free(hev->handler);
        hev->handler = NULL;
    }

    for (int i = 0; i < HTTP_RESP_HEADERS_MAX && hev->resp_headers[i]; i++) {
        free(hev->resp_headers[i]);
        hev->resp_headers[i] = NULL;
    }

    if (buffer->dst != -1) {
        close(buffer->dst);
        buffer->dst = -1;
    }
}

int http_insert_header(header_t **hs, header_t *h)
{
    int i;
    for (i = 0; i < HTTP_RESP_HEADERS_MAX; i++) {
        if (!hs[i]) {
            break;
        }
    }

    if (i == HTTP_RESP_HEADERS_MAX) {
        log_error("http: response headers line more than %d", HTTP_READ_RESPONSE);
        return -1;
    }

    hs[i] = h;

    return 0;
}

char *http_find_header(header_t **hs, const char *key)
{
    char *value = NULL;

    for (int i = 0 ; i < HTTP_RESP_HEADERS_MAX && hs[i]; i++) {
        if (strcmp(key, hs[i]->key) == 0) {
            value = hs[i]->value;
            break;
        }
    }

    return value;
}

void http_print_header(header_t **hs)
{
    for (int i = 0; i < HTTP_RESP_HEADERS_MAX && hs[i]; i++) {
        printf("%s: %s\n", hs[i]->key, hs[i]->value);
    }
}

// return 0 if ts_list empty, or 1 on update done
int http_update_next_ts_uri(http_event_t *hev, ts_list_t *ts_list)
{
    char *ts;
    char file[266] = {'\0'};

    for (;;) {
        ts = ts_list->get_ts_name(ts_list);
        if (!ts) {
            return 0;
        }

        snprintf(file, sizeof(file) - 1, "%s/%s", hev->buffer.dir, ts);

        if (access(file, F_OK) == 0) {
            log_debug("'%s' already in disk", ts);
            util_show_progress("download ts files...", ++ts_list->success, ts_list->ts_cnt);
            memset(file, '\0', sizeof(file));
            continue;
        } else {
            memset(hev->buffer.dst_file, '\0', sizeof(hev->buffer.dst_file));
            memcpy(hev->buffer.dst_file, ts, strlen(ts));
            memset(hev->uri, '\0', sizeof(hev->uri));
            if (strlen(hev->parameter) > 0) {
                snprintf(hev->uri, sizeof(hev->uri) - 1, "%s/%s?%s", ts_list->base_uri, ts, hev->parameter);
            } else {
                snprintf(hev->uri, sizeof(hev->uri) - 1, "%s/%s", ts_list->base_uri, ts);
            }
            return 1;
        }
    }

    return 0;
}

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

// todo: Accept-Encoding: identity
#define REQUEST_HEAD \
        "GET %s HTTP/1.1 \r\n"                      \
        "User-Agent: Wget/1.20.3 (linux-gnu) \r\n"  \
        "Accept: */* \r\n"                          \
        "Accept-Encoding: identity \r\n"            \
        "Host: %s \r\n"                             \
        "Connection: Keep-Alive \r\n"               \
        "\r\n"                                      \

extern int errno;
extern int h_errno;

static int http_save_file(http_event_t *hev);
static int http_read_headers(http_event_t *hev);
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
    // todo: reuse fd?
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
        /* fix: clear socket received buffer */
        if (hev->reuse_fd) {
clear:
            if (hev->use_ssl) {
                ret = SSL_read(hev->ssl, buffer->buf, sizeof(buffer->buf));
            } else {
                ret = read(hev->fd, buffer->buf, sizeof(buffer->buf));
            }

            log_debug("http: clear socket received buffer(%ld bytes)", ret);

            if (ret > 0) {
                goto clear;
            }
        }

        memset(buffer->buf, '\0', sizeof(buffer->buf));
        snprintf(buffer->buf, sizeof(buffer->buf) - 1, REQUEST_HEAD, hev->uri, hev->host);
        buffer->len = strlen(buffer->buf);
        buffer->cnt = 0;
        buffer->dst = -1;

        hev->doing = 1;

        log_debug("\n\nhttp: request\n%s", buffer->buf);
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
        buffer->dst = -1;
        hev->doing = 1;
    }

    ret = http_read_headers(hev);
    if (ret == EAGAIN) {
        return EAGAIN;
    } else if (ret == -1) {
        goto err;
    }

    buffer->len = buffer->cnt;
    buffer->cnt = 0;

    while (buffer->cnt < buffer->len) {
        for (i = 0; buffer->cnt < buffer->len && buffer->buf[buffer->cnt] != '\r';
                ++i, ++buffer->cnt) {
            line[i] = buffer->buf[buffer->cnt];
        }

        line[i] = '\0';
        buffer->cnt += strlen("\r\n");

        log_debug("http: header '%s'", line);

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
        } else if ((mark = util_str_begin_with(line, "Content-Length: ", strlen("Content-Length: ")))) {
            mark += strlen("Content-Length: ");
            p = mark;
            while (*mark != '\r') {
                ++mark;
            }
            snprintf(buf, mark - p + 1, "%s", p);
            hev->headers_in.content_length = atoi(buf);
        } else if (!strstr(line, ": ")) {
            log_error("http: header format error");
            util_exit();
        }
    }

    if (end != 1) {
        log_error("http: parse header failed, not found the end of headers.");
        goto err;
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
    struct stat st;
    http_buffer_t *buffer = &hev->buffer;
    char path[256] = {'\0'};

    if (!hev->doing) {
        hev->doing = 1;
        buffer->pre_cnt = 0;

        if (hev->headers_in.content_length == 0) {
            log_error("http: Content-Length is 0");
            util_exit();
        }

        if (http_get_file_name(hev) != 0) {
            log_error("http: get file name failed, uri='%s'", hev->uri);
            return -1;
        }

        log_debug("http: saving to '%s', content length %ld bytes, fd=%d", 
            buffer->file, hev->headers_in.content_length, hev->fd);

        if (strlen(buffer->dir) != 0) {
            memcpy(path, buffer->dir, strlen(buffer->dir));
            memcpy(&path[strlen(path)], "/", 1);
            memcpy(&path[strlen(path)], buffer->file, strlen(buffer->file));
        } else {
            memcpy(path, buffer->file, strlen(buffer->file));
        }

        if (stat(path, &st) == 0 && st.st_size == hev->headers_in.content_length) {
            hev->doing = 0;
            buffer->dst = -1;
            return 0;
        }

        if ((buffer->dst = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644)) == -1) {
            log_error("http: open '%s' failed", path);
            goto err;
        }

        if (buffer->cnt < buffer->len) {
            while (buffer->cnt < buffer->len) {
                ret = write(buffer->dst, &buffer->buf[buffer->cnt], buffer->len - buffer->cnt);
                if (ret == -1) {
                    log_error("http: write to '%s' failed", path);
                    goto err;
                }
                buffer->cnt += ret;
            }
        }    

        buffer->cnt = 0;
        buffer->len = hev->headers_in.content_length - ret;
    }

    ret = http_save_file(hev);

    if (ret == 0) {
        log_debug("http: save '%s' done, fd=%d", buffer->file, hev->fd);

        hev->doing = 0;
        close(buffer->dst);
        buffer->dst = -1;
        return 0;        
    } else if (ret == EAGAIN) {
        return EAGAIN;
    }

err:
    log_error("http: download '%s' failed", buffer->file);

    hev->doing = 0;
    if (buffer->dst != -1) {
        close(buffer->dst);
        buffer->dst = -1;
    }
    return -1;
}

static int http_read_headers(http_event_t *hev)
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
            goto err;
        }
        
        if (ret == 0) {
            if (strstr(buffer->buf, "\r\n\r\n")) {
                return 0;
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
    char buf[1024];

    http_buffer_t *buffer = &hev->buffer;

    while (buffer->cnt < buffer->len) {
        memset(buf, '\0', sizeof(buf));

        if (hev->use_ssl) {
            ret = SSL_read(hev->ssl, buf, sizeof(buf));
        } else {
            ret = read(hev->fd, buf, sizeof(buf));
        }

        if (ret == -1) {
            return errno == EAGAIN ? EAGAIN : -1;
        } else if (ret == 0) {
            goto done;
        }
        buffer->cnt += ret;

        if (ret != write(buffer->dst, buf, ret)) {
            log_error( "http: write '%s' failed", buffer->file);
            return -1;
        }
    }

done:
    return buffer->cnt == buffer->len ? 0 : -1;
}

int http_get_file_name(http_event_t *hev)
{
    char *p, *mark;
    http_buffer_t *buffer;
    int name_len;

    if (strlen(hev->uri) == 0) {
        return -1;
    }

    buffer = &hev->buffer;

    p = hev->uri + strlen(hev->uri);
    mark = p;

    while (p != hev->uri) {
        if (*p == '?') {
            mark = p;
        } else if (*p == '/') {
            break;
        }
        --p;
    }

    ++p;

    name_len = mark - p + 1;
    if (name_len > buffer->filename_len) {
        if (buffer->file) {
            free(buffer->file);
        }

        buffer->file = util_calloc(sizeof(char), name_len);
        if (!buffer->file) {
            return -1;
        }
        buffer->filename_len = name_len;
    }

    snprintf(buffer->file, name_len, "%s", p);

    return 0;
}

int http_parse_url(char *url, http_event_t *hev)
{
    char p[16] = {'\0'};
    char *p1, *p2;
    unsigned short port;

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

    snprintf(hev->uri, sizeof(hev->uri), "%s", p2);

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

    if (buffer->dst != -1) {
        close(buffer->dst);
        buffer->dst = -1;
    }

    if (buffer->file) {
        free(buffer->file);
        buffer->file = NULL;
        buffer->filename_len = 0;
    }

}

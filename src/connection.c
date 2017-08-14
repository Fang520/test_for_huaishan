#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>


#include <nghttp2/nghttp2.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "token.h"
#include "verbose.h"
#include "connection.h"

enum { IO_NONE, WANT_READ, WANT_WRITE };

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV_CS(NAME, VALUE)                                                \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, strlen(VALUE),        \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

struct Connection
{
    SSL *ssl;
    nghttp2_session *session;
    int want_io;
};

struct Request
{
    char *host;
    char *path;
    char *hostport;
    int32_t stream_id;
    uint16_t port;
};

struct URI
{
    const char *host;
    const char *path;
    size_t pathlen;
    const char *hostport;
    size_t hostlen;
    size_t hostportlen;
    uint16_t port;
};

typedef struct {
    head_resp_cb_t head_resp_cb;
    body_resp_cb_t body_resp_cb;
} req_ctx_t;

static struct Connection connection;
static pthread_t pid_epoll;
static int epoll_thread_quit = 0;

static char *strcopy(const char *s, size_t len)
{
    char *dst;
    dst = malloc(len + 1);
    memcpy(dst, s, len);
    dst[len] = '\0';
    return dst;
}

static void die(const char *msg)
{
    fprintf(stderr, "FATAL: %s\n", msg);
    exit(EXIT_FAILURE);
}

static void dief(const char *func, const char *msg)
{
    fprintf(stderr, "FATAL: %s: %s\n", func, msg);
    exit(EXIT_FAILURE);
}

static void diec(const char *func, int error_code)
{
    fprintf(stderr, "FATAL: %s: error_code=%d, msg=%s\n", func, error_code,
            nghttp2_strerror(error_code));
    exit(EXIT_FAILURE);
}

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data)
{
    struct Connection *connection;
    int rv;
    (void)session;
    (void)flags;

    connection = (struct Connection *)user_data;
    connection->want_io = IO_NONE;
    ERR_clear_error();
    rv = SSL_write(connection->ssl, data, (int)length);
    if (rv <= 0)
    {
        int err = SSL_get_error(connection->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
        {
            connection->want_io =
                (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
            rv = NGHTTP2_ERR_WOULDBLOCK;
        }
        else
        {
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    return rv;
}

static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf,
                             size_t length, int flags, void *user_data)
{
    struct Connection *connection;
    int rv;
    (void)session;
    (void)flags;

    connection = (struct Connection *)user_data;
    connection->want_io = IO_NONE;
    ERR_clear_error();
    rv = SSL_read(connection->ssl, buf, (int)length);
    if (rv < 0)
    {
        int err = SSL_get_error(connection->ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
        {
            connection->want_io =
                (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
            rv = NGHTTP2_ERR_WOULDBLOCK;
        }
        else
        {
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    else if (rv == 0)
    {
        rv = NGHTTP2_ERR_EOF;
    }
    return rv;
}

static int on_frame_send_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data)
{
    size_t i;
    (void)user_data;
    nghttp2_nv* nva;

    switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:
        nva = frame->headers.nva;
        printf("[INFO] C ----------------------------> S (HEADERS)\n");
        for (i = 0; i < frame->headers.nvlen; ++i)
        {
            fwrite(nva[i].name, 1, nva[i].namelen, stdout);
            printf(": ");
            fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
            printf("\n");
        }
        break;
    case NGHTTP2_RST_STREAM:
        printf("[INFO] C ----------------------------> S (RST_STREAM)\n");
        break;
    case NGHTTP2_GOAWAY:
        printf("[INFO] C ----------------------------> S (GOAWAY)\n");
        break;
    }
    return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data)
{
    size_t i;
    (void)user_data;

    switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
        {
            const nghttp2_nv *nva = frame->headers.nva;
            printf("[INFO] C <---------------------------- S (HEADERS)\n");
            for (i = 0; i < frame->headers.nvlen; ++i)
            {
                fwrite(nva[i].name, 1, nva[i].namelen, stdout);
                printf(": ");
                fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
                printf("\n");
            }
            req_ctx_t* req_ctx = (req_ctx_t*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            if (req_ctx)
            {
                req_ctx->head_resp_cb(frame->headers.nva, frame->headers.nvlen);
            }
        }
        break;
    case NGHTTP2_RST_STREAM:
        printf("[INFO] C <---------------------------- S (RST_STREAM)\n");
        break;
    case NGHTTP2_GOAWAY:
        printf("[INFO] C <---------------------------- S (GOAWAY)\n");
        break;
    }
    return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data)
{
    (void)flags;
    (void)user_data;

    printf("[INFO] C <---------------------------- S (DATA chunk)\n"
           "%lu bytes\n",
           (unsigned long int)len);
    fwrite(data, 1, len, stdout);
    printf("\n");

    req_ctx_t* req_ctx = (req_ctx_t*)nghttp2_session_get_stream_user_data(session, stream_id);
    if (req_ctx)
    {
        req_ctx->body_resp_cb(data, len);
    }

    return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data)
{
    (void)error_code;
    (void)user_data;

    int rv;
    printf("=================== close\n");
    rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);

    if (rv != 0)
    {
        diec("nghttp2_session_terminate_session", rv);
    }
    return 0;
}

static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
}

static int select_next_proto_cb(SSL *ssl, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg)
{
    int rv;
    (void)ssl;
    (void)arg;

    rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
    if (rv <= 0)
    {
        die("Server did not advertise HTTP/2 protocol");
    }
    return SSL_TLSEXT_ERR_OK;
}

static void init_ssl_ctx(SSL_CTX *ssl_ctx)
{
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
}

static void ssl_handshake(SSL *ssl, int fd)
{
    int rv;
    if (SSL_set_fd(ssl, fd) == 0)
    {
        dief("SSL_set_fd", ERR_error_string(ERR_get_error(), NULL));
    }
    ERR_clear_error();
    rv = SSL_connect(ssl);
    if (rv <= 0)
    {
        dief("SSL_connect", ERR_error_string(ERR_get_error(), NULL));
    }
}

static int connect_to(const char *host, uint16_t port)
{
    struct addrinfo hints;
    int fd = -1;
    int rv;
    char service[NI_MAXSERV];
    struct addrinfo *res, *rp;
    snprintf(service, sizeof(service), "%u", port);
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rv = getaddrinfo(host, service, &hints, &res);
    if (rv != 0)
    {
        dief("getaddrinfo", gai_strerror(rv));
    }
    for (rp = res; rp; rp = rp->ai_next)
    {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
        {
            continue;
        }
        while ((rv = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
                errno == EINTR)
            ;
        if (rv == 0)
        {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static void make_non_block(int fd)
{
    int flags, rv;
    while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
        ;
    if (flags == -1)
    {
        dief("fcntl", strerror(errno));
    }
    while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
        ;
    if (rv == -1)
    {
        dief("fcntl", strerror(errno));
    }
}

static void set_tcp_nodelay(int fd)
{
    int val = 1;
    int rv;
    rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
    if (rv == -1)
    {
        dief("setsockopt", strerror(errno));
    }
}

static void request_init(struct Request *req, const struct URI *uri)
{
    req->host = strcopy(uri->host, uri->hostlen);
    req->port = uri->port;
    req->path = strcopy(uri->path, uri->pathlen);
    req->hostport = strcopy(uri->hostport, uri->hostportlen);
    req->stream_id = -1;
}

static void request_free(struct Request *req)
{
    free(req->host);
    free(req->path);
    free(req->hostport);
}

static int need_send_or_recv(int* send, int* recv)
{
    *send = 0;
    *recv = 0;
    if (nghttp2_session_want_read(connection.session) || connection.want_io == WANT_READ)
        *recv = 1;
    if (nghttp2_session_want_write(connection.session) || connection.want_io == WANT_WRITE)
        *send = 1;
    return *recv + *send;
}

static int parse_uri(struct URI *res, const char *uri)
{
    /* We only interested in https */
    size_t len, i, offset;
    int ipv6addr = 0;
    memset(res, 0, sizeof(struct URI));
    len = strlen(uri);
    if (len < 9 || memcmp("https://", uri, 8) != 0)
    {
        return -1;
    }
    offset = 8;
    res->host = res->hostport = &uri[offset];
    res->hostlen = 0;
    if (uri[offset] == '[')
    {
        /* IPv6 literal address */
        ++offset;
        ++res->host;
        ipv6addr = 1;
        for (i = offset; i < len; ++i)
        {
            if (uri[i] == ']')
            {
                res->hostlen = i - offset;
                offset = i + 1;
                break;
            }
        }
    }
    else
    {
        const char delims[] = ":/?#";
        for (i = offset; i < len; ++i)
        {
            if (strchr(delims, uri[i]) != NULL)
            {
                break;
            }
        }
        res->hostlen = i - offset;
        offset = i;
    }
    if (res->hostlen == 0)
    {
        return -1;
    }
    /* Assuming https */
    res->port = 443;
    if (offset < len)
    {
        if (uri[offset] == ':')
        {
            /* port */
            const char delims[] = "/?#";
            int port = 0;
            ++offset;
            for (i = offset; i < len; ++i)
            {
                if (strchr(delims, uri[i]) != NULL)
                {
                    break;
                }
                if ('0' <= uri[i] && uri[i] <= '9')
                {
                    port *= 10;
                    port += uri[i] - '0';
                    if (port > 65535)
                    {
                        return -1;
                    }
                }
                else
                {
                    return -1;
                }
            }
            if (port == 0)
            {
                return -1;
            }
            offset = i;
            res->port = (uint16_t)port;
        }
    }
    res->hostportlen = (size_t)(uri + offset + ipv6addr - res->host);
    for (i = offset; i < len; ++i)
    {
        if (uri[i] == '#')
        {
            break;
        }
    }
    if (i - offset == 0)
    {
        res->path = "/";
        res->pathlen = 1;
    }
    else
    {
        res->path = &uri[offset];
        res->pathlen = i - offset;
    }
    return 0;
}

static int down_channel_resp_cb(nghttp2_nv* nva, int nvlen)
{
    int i;
    
    printf("========= get down channel resp\n");
    for (i = 0; i < nvlen; i++)
    {
        fwrite(nva[i].name, 1, nva[i].namelen, stdout);
        printf(": ");
        fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
        printf("\n");
    }   
    return 0;
}

static int create_down_channel()
{
    int stream_id;
    
    nghttp2_nv http2_head[] = {MAKE_NV(":method", "GET"),
                               MAKE_NV(":scheme", "https"),
                               MAKE_NV_CS(":path", "/v20160207/directives"),
                               MAKE_NV_CS("authorization", get_token())};

    req_ctx_t* ctx = (req_ctx_t*)malloc(sizeof(req_ctx_t));
    ctx->head_resp_cb = down_channel_resp_cb;
    ctx->body_resp_cb = 0;

    stream_id = nghttp2_submit_request(connection.session, NULL, http2_head, 4, NULL, ctx);

    if (stream_id < 0)
    {
        diec("nghttp2_submit_request", stream_id);
    }

    return 0;
}

typedef struct {
    int len;
    char* data;
    int stream_id;
    int pos;
} http2_content_t;

ssize_t data_source_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
                                         uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    http2_content_t* content = (http2_content_t*)source->ptr;
    int copy_len, left_len;
    left_len = content->len - content->pos;
    if (left_len <= length)
    {
        copy_len = left_len;
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    else
    {
        copy_len = length;
    }
    memcpy(buf, content->data, copy_len);
    content->pos = content->len - copy_len;
    return copy_len;
}

http2_content_t* build_http2_content(char* event_json, char* state_json, char* audio_data, int audio_len)
{
    char* buf;
    char* pos;
    int len;
    http2_content_t* content;

    char* str1 = "--uniview-boundary\n"
                 "Content-Disposition: form-data; name=\"metadata\"\n"
                 "Content-Type: application/json; charset=UTF-8\n\n";

    char* str2 = "--uniview-boundary\n"
                 "Content-Disposition: form-data; name=\"audio\"\n"
                 "Content-Type: application/octet-stream\n\n";

    char* str3 = "--uniview-boundary--";


    if (event_json == 0)
        return 0;

    len= 0;
    if (event_json)
        len += strlen(event_json);
    if (state_json)
        len += strlen(state_json);
    len += audio_len;

    buf = (char*)malloc(len + 1024);
    pos = buf;
    
    strcpy(pos, str1);
    pos += strlen(str1);

    len = sprintf(pos, "{%s", event_json);
    pos += len;

    if (state_json)
    {
        len = sprintf(pos, ",%s}", state_json);
        pos += len;
    }
    else
    {
        pos[0] = '}';
        pos += 1;
    }

    if (audio_data)
    {
        strcpy(pos, str2);
        pos += strlen(str2);
        memcpy(pos, audio_data, audio_len);
        pos += audio_len;
    }       
    strcpy(pos, str3);
    pos += strlen(str3);

    content = (http2_content_t*)malloc(sizeof(http2_content_t));
    content->data = buf;
    content->len = pos - buf;
    content->pos = 0;
    
    return content;
}

int conn_send_request(char* event_json, char* state_json, char* audio_data, int audio_len,
                             head_resp_cb_t head_resp_cb, body_resp_cb_t body_resp_cb)
{
    int stream_id;
    
    nghttp2_nv http2_head[] = {MAKE_NV(":method", "POST"),
                        MAKE_NV(":scheme", "https"),
                        MAKE_NV_CS(":path", "/v20160207/directives"),
                        MAKE_NV_CS("authorization", get_token()),
                        MAKE_NV("content-type", "multipart/form-data; boundary=uniview-boundary")};

    http2_content_t* http2_content = build_http2_content(event_json, state_json, audio_data, audio_len);

    nghttp2_data_provider data_prd;

    data_prd.read_callback = data_source_read_callback;
    data_prd.source.ptr = (void*)http2_content;
    req_ctx_t* ctx = (req_ctx_t*)malloc(sizeof(req_ctx_t));
    ctx->head_resp_cb = head_resp_cb;
    ctx->body_resp_cb = body_resp_cb;

    stream_id = nghttp2_submit_request(connection.session, NULL, http2_head, 5, &data_prd, ctx);

    if (stream_id < 0)
    {
        diec("nghttp2_submit_request", stream_id);
    }

    http2_content->stream_id = stream_id;

    return 0;
}

static void epoll_thread(const struct URI *uri)
{
    nghttp2_session_callbacks *callbacks;
    int fd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    struct Request req;
    int rv;

    request_init(&req, uri);

    /* Establish connection and setup SSL */
    fd = connect_to(req.host, req.port);
    if (fd == -1)
    {
        die("Could not open file descriptor");
    }
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL)
    {
        dief("SSL_CTX_new", ERR_error_string(ERR_get_error(), NULL));
    }
    init_ssl_ctx(ssl_ctx);
    ssl = SSL_new(ssl_ctx);
    if (ssl == NULL)
    {
        dief("SSL_new", ERR_error_string(ERR_get_error(), NULL));
    }
    /* To simplify the program, we perform SSL/TLS handshake in blocking
       I/O. */
    ssl_handshake(ssl, fd);

    connection.ssl = ssl;
    connection.want_io = IO_NONE;

    /* Here make file descriptor non-block */
    make_non_block(fd);
    set_tcp_nodelay(fd);

    printf("[INFO] SSL/TLS handshake completed\n");

    rv = nghttp2_session_callbacks_new(&callbacks);

    if (rv != 0)
    {
        diec("nghttp2_session_callbacks_new", rv);
    }

    setup_nghttp2_callbacks(callbacks);

    rv = nghttp2_session_client_new(&connection.session, callbacks, &connection);

    nghttp2_session_callbacks_del(callbacks);

    if (rv != 0)
    {
        diec("nghttp2_session_client_new", rv);
    }

    rv = nghttp2_submit_settings(connection.session, NGHTTP2_FLAG_NONE, NULL, 0);

    if (rv != 0)
    {
        diec("nghttp2_submit_settings", rv);
    }

    create_down_channel();

    
    /* Event loop */
    struct pollfd pollfds[1];
    struct pollfd *pollfd = &pollfds[0];
    int nfds;
    int ret;
    pollfds[0].fd = fd;
    while (epoll_thread_quit == 0)
    {
        int send = 0;
        int recv = 0;
        if (need_send_or_recv(&send, &recv))
        {
            pollfd->events = 0;
            if (send)
                pollfd->events |= POLLOUT;
            if (recv)
                pollfd->events |= POLLIN;

            nfds = poll(pollfds, 1, -1);
            if (nfds == -1)
            {
                dief("poll", strerror(errno));
            }
            if (pollfds[0].revents & POLLOUT)
            {
                ret = nghttp2_session_send(connection.session);
                if (ret != 0)
                {
                    diec("nghttp2_session_send", ret);
                }               
            }   
            if (pollfds[0].revents & POLLIN)
            {
                ret = nghttp2_session_recv(connection.session);
                if (ret != 0)
                {
                    diec("nghttp2_session_recv", ret);
                }               
            }
            if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR))
            {
                die("Connection error");
            }           
        }
        else
        {
            pollfd->events = 0;
            pollfd->events = POLLIN;
            nfds = poll(pollfds, 1, 200);
            if (nfds == -1)
            {
                dief("poll in idle", strerror(errno));
            }
            else if (nfds > 0)
            {
                ret = nghttp2_session_recv(connection.session);
                if (ret != 0)
                {
                    diec("nghttp2_session_recv in idle", ret);
                }                   
            }
            else if ((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR))
            {
                die("Connection error in idle");
            }
        }
    }

    /* Resource cleanup */
    nghttp2_session_del(connection.session);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    shutdown(fd, SHUT_WR);
    close(fd);
    request_free(&req);
}

static struct URI uri;

int conn_open()
{
    struct sigaction act;
    int rv;
    int ret;

    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, 0);

    SSL_load_error_strings();
    SSL_library_init();

    rv = parse_uri(&uri, "https://avs-alexa-na.amazon.com");
    if (rv != 0)
    {
        die("parse_uri failed");
    }

    ret = pthread_create(&pid_epoll, NULL, (void*)epoll_thread, &uri);  
    if (ret != 0)   
    {  
        die("Create epoll pthread error");  
    }  

    return 0;
}

int conn_close()
{
    epoll_thread_quit = 1;
    pthread_join(pid_epoll, NULL);
    return 0;
}

#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

typedef struct
{
    head_resp_cb_t head_resp_cb;
    body_resp_cb_t body_resp_cb;
} req_ctx_t;

extern int g_send_audio;

static struct Connection connection;
static pthread_t pid_thread;
static int recv_thread_quit = 0;

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

extern int g_quit;

static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data)
{
    (void)flags;
    (void)user_data;
    printf("[INFO] C <---------------------------- S (DATA chunk)\n"
           "%lu bytes\n",
           (unsigned long int)len);
    //fwrite(data, 1, len, stdout);
    //printf("\n");
    //req_ctx_t* req_ctx = (req_ctx_t*)nghttp2_session_get_stream_user_data(session, stream_id);

    //if (req_ctx)
    //    req_ctx->body_resp_cb(data, len);

	printf("========= get audio body resp\n");
	FILE* f = fopen("audio.dat", "wb");
	if (f)
	{
		fwrite(data, 1, len, f);
		fclose(f);
	}

    g_quit = 1;


    return 0;
}


static int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    verbose_header(session, frame, name, namelen, value, valuelen, flags, user_data);
    return 0;
}

static int verbose_on_invalid_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, int lib_error_code, void *user_data)
{
    printf("----- verbose_on_invalid_frame_recv_callback\n");
    return 0;
}

static int verbose_error_callback(nghttp2_session *session, const char *msg, size_t len, void *user_data)
{
    printf("----- verbose_error_callback\n");
    return 0;
}


static int on_frame_not_send_callback(nghttp2_session *session, const nghttp2_frame *frame, int lib_error_code, void *user_data)
{
    printf("----- on_frame_not_send_callback\n");
    return 0;
}

int on_send_data_callback(nghttp2_session *session, nghttp2_frame *frame, const uint8_t *framehd, size_t length, nghttp2_data_source *source, void *user_data)
{
    printf("----- on_send_data_callback, %d\n", length);
    return 0;
}

static void setup_nghttp2_callbacks(nghttp2_session_callbacks *callbacks)
{
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, on_frame_send_callback);
    nghttp2_session_callbacks_set_send_data_callback(callbacks, on_send_data_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);

    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(callbacks, verbose_on_invalid_frame_recv_callback);
    nghttp2_session_callbacks_set_error_callback(callbacks, verbose_error_callback);   
    nghttp2_session_callbacks_set_on_frame_not_send_callback(callbacks, on_frame_not_send_callback);
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
        die("Server did not advertise HTTP/2 protocol");

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
        dief("SSL_set_fd", ERR_error_string(ERR_get_error(), NULL));

    ERR_clear_error();
    rv = SSL_connect(ssl);

    if (rv <= 0)
        dief("SSL_connect", ERR_error_string(ERR_get_error(), NULL));
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
        dief("getaddrinfo", gai_strerror(rv));

    for (rp = res; rp; rp = rp->ai_next)
    {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

        if (fd == -1)
            continue;

        while ((rv = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
                errno == EINTR)
            ;

        if (rv == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static void set_tcp_nodelay(int fd)
{
    int val = 1;
    int rv;
    rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));

    if (rv == -1)
        dief("setsockopt", strerror(errno));
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

static int parse_uri(struct URI *res, const char *uri)
{
    /* We only interested in https */
    size_t len, i, offset;
    int ipv6addr = 0;
    memset(res, 0, sizeof(struct URI));
    len = strlen(uri);

    if (len < 9 || memcmp("https://", uri, 8) != 0)
        return -1;

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
                break;
        }

        res->hostlen = i - offset;
        offset = i;
    }

    if (res->hostlen == 0)
        return -1;

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
                    break;

                if ('0' <= uri[i] && uri[i] <= '9')
                {
                    port *= 10;
                    port += uri[i] - '0';

                    if (port > 65535)
                        return -1;
                }
                else
                    return -1;
            }

            if (port == 0)
                return -1;

            offset = i;
            res->port = (uint16_t)port;
        }
    }

    res->hostportlen = (size_t)(uri + offset + ipv6addr - res->host);

    for (i = offset; i < len; ++i)
    {
        if (uri[i] == '#')
            break;
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

extern int api_system_sync_state();

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

    api_system_sync_state();

    return 0;
}

static int create_down_channel()
{
    int stream_id;
    nghttp2_nv http2_head[] = {MAKE_NV(":method", "GET"),
                               MAKE_NV(":scheme", "https"),
                               MAKE_NV_CS(":authority", "avs-alexa-na.amazon.com"),
                               MAKE_NV_CS(":path", "/v20160207/directives"),
                               MAKE_NV("content-type", "multipart/form-data; boundary=uniview-boundary"),
                               MAKE_NV_CS("authorization", get_token())
                               
                              };
    req_ctx_t* ctx = (req_ctx_t*)malloc(sizeof(req_ctx_t));
    ctx->head_resp_cb = down_channel_resp_cb;
    ctx->body_resp_cb = 0;

    printf("------------------------------- submit down channle request\n");
    stream_id = nghttp2_submit_request(connection.session, NULL, http2_head, 6, NULL, ctx);

    if (stream_id < 0)
        diec("nghttp2_submit_request", stream_id);

    return 0;
}

typedef struct
{
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
        copy_len = length;

    memcpy(buf, content->data + content->pos, copy_len);
    content->pos += copy_len;

    printf("=====================part size = %d\n", copy_len);
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
    char* str2 = "\n--uniview-boundary\n"
                 "Content-Disposition: form-data; name=\"audio\"\n"
                 "Content-Type: application/octet-stream\n\n";
    char* str3 = "--uniview-boundary--";

    if (event_json == 0)
        return 0;

    len = 0;

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
        *pos = 0;
        printf("%s\n", buf);

        memcpy(pos, audio_data, audio_len);
        for (int i=0; i<100; i++)
        {
            printf("%c", pos[i]);
        }
        printf("\n");
        
        pos += audio_len;

        
    }

    strcpy(pos, str3);
    pos += strlen(str3);

    content = (http2_content_t*)malloc(sizeof(http2_content_t));
    content->data = buf;
    content->len = pos - buf;
    content->pos = 0;


    printf("============================== total size: %d\n", content->len);
    
    return content;
}

int conn_send_request(char* event_json, char* state_json, char* audio_data, int audio_len,
                      head_resp_cb_t head_resp_cb, body_resp_cb_t body_resp_cb)
{
    int stream_id;
    nghttp2_nv http2_head[] = {MAKE_NV(":method", "POST"),
                               MAKE_NV(":scheme", "https"),
                               MAKE_NV_CS(":authority", "avs-alexa-na.amazon.com"),
                               MAKE_NV_CS(":path", "/v20160207/events"),
                               MAKE_NV("content-type", "multipart/form-data; boundary=uniview-boundary"),
                               MAKE_NV_CS("authorization", get_token())
                               
                              };
    http2_content_t* http2_content = build_http2_content(event_json, state_json, audio_data, audio_len);
    nghttp2_data_provider data_prd;
    data_prd.read_callback = data_source_read_callback;
    data_prd.source.ptr = (void*)http2_content;
    req_ctx_t* ctx = (req_ctx_t*)malloc(sizeof(req_ctx_t));
    ctx->head_resp_cb = head_resp_cb;
    ctx->body_resp_cb = body_resp_cb;
    stream_id = nghttp2_submit_request(connection.session, NULL, http2_head, 6, &data_prd, ctx);

    if (stream_id < 0)
        diec("nghttp2_submit_request", stream_id);

    http2_content->stream_id = stream_id;
    return 0;
}

static void recv_thread(const struct URI *uri)
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
        die("Could not open file descriptor");

    ssl_ctx = SSL_CTX_new(SSLv23_client_method());

    if (ssl_ctx == NULL)
        dief("SSL_CTX_new", ERR_error_string(ERR_get_error(), NULL));

    init_ssl_ctx(ssl_ctx);
    ssl = SSL_new(ssl_ctx);

    if (ssl == NULL)
        dief("SSL_new", ERR_error_string(ERR_get_error(), NULL));

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
        diec("nghttp2_session_callbacks_new", rv);

    setup_nghttp2_callbacks(callbacks);
    rv = nghttp2_session_client_new(&connection.session, callbacks, &connection);
    nghttp2_session_callbacks_del(callbacks);

    if (rv != 0)
        diec("nghttp2_session_client_new", rv);

    nghttp2_settings_entry iv[2] = {
                                       {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
                                       {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535},
                                   };
    rv = nghttp2_submit_settings(connection.session, NGHTTP2_FLAG_NONE, iv, 2);

    if (rv != 0)
        diec("nghttp2_submit_settings", rv);

    create_down_channel();

    fd_set fdset;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    while (recv_thread_quit == 0)
    {
        send_msg();
        
    
        if (nghttp2_session_want_write(connection.session) || connection.want_io == WANT_WRITE)
        {
            rv = nghttp2_session_send(connection.session);
            if (rv != 0)
                diec("nghttp2_session_send", rv);        
        }
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);
        rv = select(fd + 1, &fdset, NULL, NULL, &tv);
        if (rv < 0)
        {
            diec("select fail", rv);
        }
        if (rv == 0)
        {
            continue;            
        }

        if (g_send_audio)
        {
            printf("-------------- g_send_audio 1\n");
        }
        rv = nghttp2_session_recv(connection.session);
        if (rv != 0)
            diec("nghttp2_session_recv", rv);
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
        die("parse_uri failed");

    ret = pthread_create(&pid_thread, NULL, (void*)recv_thread, &uri);

    if (ret != 0)
        die("Create epoll pthread error");

    return 0;
}

int conn_close()
{
    recv_thread_quit = 1;
    pthread_join(pid_thread, NULL);
    return 0;
}

void send_msg()
{
    msg_t* msg = get_msg();
    if (msg)
    {
        int stream_id;
        nghttp2_nv http2_head[] = {MAKE_NV(":method", "GET"),
                                   MAKE_NV(":scheme", "https"),
                                   MAKE_NV_CS(":authority", "avs-alexa-na.amazon.com"),
                                   MAKE_NV_CS(":path", "/v20160207/directives"),
                                   MAKE_NV("content-type", "multipart/form-data; boundary=uniview-boundary"),
                                   MAKE_NV_CS("authorization", get_token())
                                   
                                  };
        req_ctx_t* ctx = (req_ctx_t*)malloc(sizeof(req_ctx_t));
        ctx->head_resp_cb = down_channel_resp_cb;
        ctx->body_resp_cb = 0;

        printf("------------------------------- submit down channle request\n");
        stream_id = nghttp2_submit_request(connection.session, NULL, http2_head, 6, NULL, ctx);

        if (stream_id < 0)
            diec("nghttp2_submit_request", stream_id); 



        int stream_id;
        nghttp2_nv http2_head[] = {MAKE_NV(":method", "POST"),
                                   MAKE_NV(":scheme", "https"),
                                   MAKE_NV_CS(":authority", "avs-alexa-na.amazon.com"),
                                   MAKE_NV_CS(":path", "/v20160207/events"),
                                   MAKE_NV("content-type", "multipart/form-data; boundary=uniview-boundary"),
                                   MAKE_NV_CS("authorization", get_token())
                                   
                                  };
        http2_content_t* http2_content = build_http2_content(event_json, state_json, audio_data, audio_len);
        nghttp2_data_provider data_prd;
        data_prd.read_callback = data_source_read_callback;
        data_prd.source.ptr = (void*)http2_content;
        req_ctx_t* ctx = (req_ctx_t*)malloc(sizeof(req_ctx_t));
        ctx->head_resp_cb = head_resp_cb;
        ctx->body_resp_cb = body_resp_cb;
        stream_id = nghttp2_submit_request(connection.session, NULL, http2_head, 6, &data_prd, ctx);

        if (stream_id < 0)
            diec("nghttp2_submit_request", stream_id);
            
    }
}


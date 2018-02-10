#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <errno.h>

#include <nghttp2/nghttp2.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "verbose.h"

#include "http2.h"

typedef struct
{
    char* body;
    int len;
    int pos;
} body_adapter_t;

static SSL_CTX *ssl_ctx;
static SSL *ssl;
static nghttp2_session *session;
static int sock;
http2_cb_t user_callback;

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
    int rv;
    ERR_clear_error();
    rv = SSL_write(ssl, data, (int)length);
    if (rv <= 0)
    {
        int err = SSL_get_error(ssl, rv);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
        {
            connection->want_io =
                (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
            rv = NGHTTP2_ERR_WOULDBLOCK;
        }
        else
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return rv;
}

static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf,
                             size_t length, int flags, void *user_data)
{
    struct Connection *connection;
    int rv;
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
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    else if (rv == 0)
        rv = NGHTTP2_ERR_EOF;

    return rv;
}

static int frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    verbose_recv_frame(session, frame);
    if (frame->hd.type == NGHTTP2_SETTINGS && frame->hd.flags = 0x01)
    {
        user_callback(EVENT_TYPE_INIT, frame->hd.stream_id, 0, 0);
    }
    return 0;
}

static int data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    user_callback(EVENT_TYPE_DATA, stream_id, data, len);
    return 0;
}

static int stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
{
    verbose_stream_close(session, stream_id, error_code);
    return 0;
}

static int header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    verbose_header(session, frame, name, namelen, value, valuelen, flags, user_data);
    if (strncasecmp(name, ":status", namelen) == 0)
    {
        user_callback(EVENT_TYPE_RESP_CODE, frame->hd.stream_id, value, valuelen);
    }
    return 0;
}

static int select_next_proto_cb(SSL *ssl, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    nghttp2_select_next_protocol(out, outlen, in, inlen);
    return SSL_TLSEXT_ERR_OK;
}

static ssize_t body_adapter_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
                                   uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    body_adapter_t* adapter = (body_adapter_t*)source->ptr;
    int copy_len, left_len;
    left_len = adapter->len - adapter->pos;
    if (left_len <= length)
    {
        copy_len = left_len;
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    else
        copy_len = length;

    memcpy(buf, adapter->data + adapter->pos, copy_len);
    adapter->pos += copy_len;

    return copy_len;
}

static body_adapter_t* body_adapter(char* data, int len)
{
    static body_adapter_t adapter;
    adapter->body = data;
    adapter->len = len;
    adapter->pos = 0;    
    return &adapter;
}

int http2_send_msg(http2_head_t[] head, int head_len, char* body, int body_len)
{
    int sid;
    
    nghttp2_nv* raw_head = (nghttp2_nv*)malloc(sizeof(nghttp2_nv) * head_len);
    for (int i=0; i<head_len; i++)
    {
        raw_head[i].name = head[i].name;
        raw_head[i].namelen = strlen(head[i].name);
        raw_head[i].value = head[i].value;
        raw_head[i].valuelen = strlen(head[i].value);
        raw_head[i].flags = NGHTTP2_NV_FLAG_NONE;
    }

    nghttp2_data_provider raw_body;
    raw_body.source.ptr = (void*)body_adapter(body, body_len);
    raw_body.read_callback = body_adapter_read_callback;

    sid = nghttp2_submit_request(session, 0, raw_head, head->count, &raw_body, 0);

    free(raw_head);

    return sid;
}

void http2_run()
{
    fd_set fdset;
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = 100000;

    if (nghttp2_session_want_write(session))
    {
        rv = nghttp2_session_send(session);
        if (rv != 0)
            diec("nghttp2_session_send", rv);        
    }

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    rv = select(sock + 1, &fdset, NULL, NULL, &tv);
    if (rv < 0)
    {
        diec("select fail", rv);
    }
    if (rv == 0)
    {
        continue;            
    }
    rv = nghttp2_session_recv(session);
    if (rv != 0)
        diec("nghttp2_session_recv", rv);
}

void http2_create(http2_cb_t cb)
{
    nghttp2_session_callbacks *callbacks;
    int flags, val;

    user_callback = cb;

    SSL_load_error_strings();
    SSL_library_init();
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, 0);    
    ssl = SSL_new(ssl_ctx);
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock, rp->ai_addr, rp->ai_addrlen);
    SSL_set_fd(ssl, sock);
    SSL_connect(ssl);

    flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    val = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));

    nghttp2_session_callbacks_new(&callbacks);
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, stream_close_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, header_callback);
    nghttp2_session_client_new(&session, callbacks, 0);
    nghttp2_session_callbacks_del(callbacks);

    nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, NULL, 0);
}

void http2_destroy()
{
    nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
    nghttp2_session_del(session);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    shutdown(sock, SHUT_WR);
    close(sock);
}


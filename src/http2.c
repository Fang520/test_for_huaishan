#include <stdio.h>
#include "http2.h"

SSL_CTX *ssl_ctx;
SSL *ssl;
nghttp2_session *session;
nghttp2_session_callbacks *callbacks;
int fd, flags, val;

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
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
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
            rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    else if (rv == 0)
        rv = NGHTTP2_ERR_EOF;

    return rv;
}

static int frame_recv_callback(nghttp2_session *session,
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

                verbose_recv_frame(session, frame);

                req_ctx_t* req_ctx = (req_ctx_t*)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

                if (req_ctx)
                    req_ctx->head_resp_cb(frame->headers.nva, frame->headers.nvlen);
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

static int data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
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
        req_ctx->body_resp_cb(data, len);

    return 0;
}

static int stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
{
    nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
    return 0;
}

static int header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    verbose_header(session, frame, name, namelen, value, valuelen, flags, user_data);
    return 0;
}

static int select_next_proto_cb(SSL *ssl, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    nghttp2_select_next_protocol(out, outlen, in, inlen);
    return SSL_TLSEXT_ERR_OK;
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
    rv = nghttp2_session_recv(session);
    if (rv != 0)
        diec("nghttp2_session_recv", rv);
}

void http2_send_msg()
{
    int stream_id;
    nghttp2_nv http2_head[] = {MAKE_NV(":method", "POST"),
                               MAKE_NV(":scheme", "https"),
                               MAKE_NV_CS(":path", "/v20160207/directives"),
                               MAKE_NV("content-type", "multipart/form-data; boundary=uniview-boundary"),
                               MAKE_NV_CS("authorization", get_token())};
    http2_content_t* http2_content = build_http2_content(event_json, state_json, audio_data, audio_len);
    nghttp2_data_provider data_prd;
    data_prd.read_callback = data_source_read_callback;
    data_prd.source.ptr = (void*)http2_content;
    req_ctx_t* ctx = (req_ctx_t*)malloc(sizeof(req_ctx_t));
    ctx->head_resp_cb = head_resp_cb;
    ctx->body_resp_cb = body_resp_cb;
    stream_id = nghttp2_submit_request(connection.session, NULL, http2_head, 5, &data_prd, ctx);

    if (stream_id < 0)
        diec("nghttp2_submit_request", stream_id);

    http2_content->stream_id = stream_id;
}

void create_http2(http2_cb_t cb)
{
    SSL_load_error_strings();
    SSL_library_init();
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, 0);    
    ssl = SSL_new(ssl_ctx);
    
    fd = socket(AF_INET, SOCK_STREAM, 0);
    connect(fd, rp->ai_addr, rp->ai_addrlen);
    SSL_set_fd(ssl, fd);
    SSL_connect(ssl);

    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));

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

void destroy_http2()
{
    nghttp2_submit_goaway(session);
    nghttp2_session_del(session);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    shutdown(fd, SHUT_WR);
    close(fd);
}

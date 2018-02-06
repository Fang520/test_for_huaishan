msg_t* build_create_downchannel_msg()
{
    int stream_id;
    nghttp2_nv http2_head[] = {MAKE_NV(":method", "GET"),
                               MAKE_NV(":scheme", "https"),
                               MAKE_NV_CS(":path", "/v20160207/directives"),
                               MAKE_NV_CS("authorization", get_token())
                              };
    req_ctx_t* ctx = (req_ctx_t*)malloc(sizeof(req_ctx_t));
    ctx->head_resp_cb = down_channel_resp_cb;
    ctx->body_resp_cb = 0;
    stream_id = nghttp2_submit_request(connection.session, NULL, http2_head, 4, NULL, ctx);

    if (stream_id < 0)
        diec("nghttp2_submit_request", stream_id);

    return 0;
}


#ifndef HTTP2_H
#define HTTP2_H

#define EVENT_TYPE_INIT 0
#define EVENT_TYPE_DATA 1
#define EVENT_TYPE_RESP_CODE 2

typedef void (*http2_cb_t)(char* type, int sid, char* data, int len);

typedef struct {
    char* name;
    char* value;
} http2_head_t;

void http2_create(http2_cb_t cb);
void http2_destroy();
void http2_run();
int http2_send_msg(http2_head_t[] head, int head_len, char* body, int body_len);

#endif


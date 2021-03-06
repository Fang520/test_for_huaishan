#ifndef HTTP2_H
#define HTTP2_H

#define EVENT_TYPE_INIT 0
#define EVENT_TYPE_DATA 1
#define EVENT_TYPE_RESP_CODE 2
#define EVENT_TYPE_CLOSE 3
#define EVENT_TYPE_BOUNDARY 4


typedef void (*http2_cb_t)(int type, int sid, const char* data, int len);

typedef struct {
    char* name;
    char* value;
} http2_head_t;

void http2_create(char* ip, int port, http2_cb_t cb);
void http2_destroy();
int http2_run();
int http2_send_msg(http2_head_t* head, int head_len, const char* body, int body_len);
void http2_send_close_msg();

#endif


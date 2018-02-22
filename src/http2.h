#ifndef HTTP2_H
#define HTTP2_H

#include <stdint.h>

#define EVENT_TYPE_INIT 0
#define EVENT_TYPE_DATA 1
#define EVENT_TYPE_RESP_CODE 2

typedef void (*http2_cb_t)(int type, int sid, uint8_t* data, int len);

typedef struct {
    char* name;
    char* value;
} http2_head_t;

void http2_create(char* ip, int port, http2_cb_t cb);
void http2_destroy();
int http2_run();
int http2_send_msg(http2_head_t* head, int head_len, uint8_t* body, int body_len);

#endif


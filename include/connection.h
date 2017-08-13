#ifndef CONNECTION_H
#define CONNECTION_H

#include <nghttp2/nghttp2.h>

typedef int (*head_resp_cb_t)(nghttp2_nv* nva, int nvlen);
typedef int (*body_resp_cb_t)(const uint8_t* buf, int len);

int conn_send_request(char* event_json, char* state_json, char* audio_data, int audio_len,
	                         head_resp_cb_t head_resp_cb, body_resp_cb_t body_resp_cb);
int conn_open();
int conn_close();

#endif

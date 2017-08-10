#ifndef CONNECTION_H
#define CONNECTION_H

typedef int (*probe_t)(char* buf, int len);
typedef int (*handle_t)(char* buf, int len);

typedef struct {
	probe_t probe;
	handle_t handle;
} conn_listener_t;

typedef struct {
	nghttp2_nv[] fields;
	int num;
} msg_header_t;

int conn_send_msg(msg_header_t* header, char* states, char* audio_data, int audio_len);
void conn_reg_listener(conn_listener_t listener);
int conn_open();
int conn_close();

#endif

#ifndef CONNECTION_H
#define CONNECTION_H

typedef int (*probe_t)(char* buf, int len);
typedef int (*handle_t)(char* buf, int len);

typedef struct {
	probe_t probe;
	handle_t handle;
} conn_listener_t;

int conn_send_msg(char* buf, int len);
void conn_reg_listener(conn_listener_t listener);
int conn_open();
int conn_close();

#endif

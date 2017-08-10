#include <stdio.h>
#include "connection.h"
#include "api_system.h"

static conn_listener_t listener;

int api_system_init()
{
	conn_listener(&listener);
	return 0;
}

int api_system_sync_state()
{
	msg_field_t header[2] = {{'namespace','System'},
	                         {'name','SynchronizeState'}};
    return conn_send_msg(header);
}

static int sync_state_resp(char* buf)
{
	
}

static int probe(char* buf)
{
	return 0;
}


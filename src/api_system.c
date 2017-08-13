#include <stdio.h>
#include "connection.h"
#include "state.h"
#include "api_system.h"

static int head_resp_cb(nghttp2_nv* nva, int nvlen)
{
	int i;
	
	printf("========= get system resp\n");
    for (i = 0; i < nvlen; i++)
    {
        fwrite(nva[i].name, 1, nva[i].namelen, stdout);
        printf(": ");
        fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
        printf("\n");
    }	
	return 0;
}

int api_system_sync_state()
{
	char* event_json =  "\"event\": {"
					    "    \"header\": {"
					    "        \"namespace\": \"System\","
					    "        \"name\": \"SynchronizeState\","
					    "        \"messageId\": \"api_system_sync_state\""
					    "    },"
					    "    \"payload\": {"
					    "    }"
					    "}";
	char* state_json = get_all_state_json_string();
    conn_send_request(event_json, state_json, 0, 0, head_resp_cb, 0);
	return 0;
}


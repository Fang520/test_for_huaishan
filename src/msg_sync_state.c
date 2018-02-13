#include <stdio.h>
#include <string.h>
#include "http2.h"
#include "token.h"
#include "state.h"
#include "msg_sync_state.h"

static char buf[102400];

int msg_sync_state_send()
{
    http2_head_t head[5];
    head[0].name = ":method";
    head[0].value = "POST";
    head[1].name = ":scheme";
    head[1].value = "https";
    head[2].name = ":path";
    head[2].value = "/v20160207/events";
    head[3].name = "content-type";
    head[3].value = "multipart/form-data; boundary=uniview-boundary";
    head[4].name = "authorization";
    head[4].value = get_token();

    char* s1 = "--uniview-boundary\n"
                 "Content-Disposition: form-data; name=\"metadata\"\n"
                 "Content-Type: application/json; charset=UTF-8\n\n";
    char* s2 = "--uniview-boundary--";

	char* event_json =  "\"event\": {"
					    "\"header\": {"
					    "\"namespace\": \"System\","
					    "\"name\": \"SynchronizeState\","
					    "\"messageId\": \"api_system_sync_state\""
					    "},"
					    "\"payload\": {"
					    "}"
					    "}";

	char* state_json = get_all_state_json_string();

    memset(buf, 0, sizeof(buf));
    sprintf(buf, "%s{%s,%s}%s", s1, event_json, state_json, s2);
	
    return http2_send_msg(head, 5, buf, strlen(buf));
}


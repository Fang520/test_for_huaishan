#include <stdio.h>
#include "http2.h"
#include "token.h"
#include "msg_downchannel.h"

int msg_downchannel_send()
{
    http2_head_t head[5];
    head[0].name = ":method";
    head[0].value = "GET";
    head[1].name = ":scheme";
    head[1].value = "https";
    head[2].name = ":path";
    head[2].value = "/v20160207/directives";
    head[3].name = "content-type";
    head[3].value = "multipart/form-data; boundary=uniview-boundary";
    head[4].name = "authorization";
    head[4].value = get_token();
    return http2_send_msg(head, 5, 0, 0);
}


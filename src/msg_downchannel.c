#include "http2.h"
#include "msg_downchannel.h"

int msg_downchannel_send()
{
    return 0;
}

#if 0
msg_t* build_create_downchannel_msg()
{
    nghttp2_nv head[] = {MAKE_NV(":method", "GET"),
                         MAKE_NV(":scheme", "https"),
                         MAKE_NV_CS(":path", "/v20160207/directives"),
                         MAKE_NV("content-type", "multipart/form-data; boundary=uniview-boundary"),
                         MAKE_NV_CS("authorization", get_token())};
    nghttp2_submit_request(session, 0, head, 5, 0, 0);
}
#endif


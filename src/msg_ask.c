#include "http2.h"
#include "msg_ask.h"
#if 0
http2_content_t* build_http2_content(char* event_json, char* state_json, char* audio_data, int audio_len)
{
    char* buf;
    char* pos;
    int len;
    http2_content_t* content;
    char* str1 = "--uniview-boundary\n"
                 "Content-Disposition: form-data; name=\"metadata\"\n"
                 "Content-Type: application/json; charset=UTF-8\n\n";
    char* str2 = "\n--uniview-boundary\n"
                 "Content-Disposition: form-data; name=\"audio\"\n"
                 "Content-Type: application/octet-stream\n\n";
    char* str3 = "--uniview-boundary--";

    if (event_json == 0)
        return 0;

    len = 0;

    if (event_json)
        len += strlen(event_json);

    if (state_json)
        len += strlen(state_json);

    len += audio_len;
    buf = (char*)malloc(len + 1024);
    pos = buf;
    strcpy(pos, str1);
    pos += strlen(str1);
    len = sprintf(pos, "{%s", event_json);
    pos += len;

    if (state_json)
    {
        len = sprintf(pos, ",%s}", state_json);
        pos += len;
    }
    else
    {
        pos[0] = '}';
        pos += 1;
    }

    if (audio_data)
    {
        strcpy(pos, str2);
        pos += strlen(str2);
        *pos = 0;
        printf("%s\n", buf);

        memcpy(pos, audio_data, audio_len);
        for (int i=0; i<100; i++)
        {
            printf("%c", pos[i]);
        }
        printf("\n");
        
        pos += audio_len;

        
    }

    strcpy(pos, str3);
    pos += strlen(str3);

    content = (http2_content_t*)malloc(sizeof(http2_content_t));
    content->data = buf;
    content->len = pos - buf;
    content->pos = 0;


    printf("============================== total size: %d\n", content->len);
    
    return content;
}
/*
nghttp2_nv http2_head[] = {MAKE_NV(":method", "POST"),
                           MAKE_NV(":scheme", "https"),
                           MAKE_NV_CS(":authority", "avs-alexa-na.amazon.com"),
                           MAKE_NV_CS(":path", "/v20160207/events"),
                           MAKE_NV("content-type", "multipart/form-data; boundary=uniview-boundary"),
                           MAKE_NV_CS("authorization", get_token())};


http2_content_t* http2_content = build_http2_content(event_json, state_json, audio_data, audio_len);
*/

msg_t* build_ask_msg()
{
    g_send_audio = 1;
	char* event_json =  "\"event\": {"
					    "\"header\": {"
					    "\"dialogRequestId\": \"avs-dialog-id-1502547094-1\","
					    "\"namespace\": \"SpeechRecognizer\","
					    "\"name\": \"Recognize\","
					    "\"messageId\": \"api_speech_recognizer\""
					    "},"
					    "\"payload\": {"
					    "\"profile\": \"NEAR_FIELD\","
					    "\"format\": \"AUDIO_L16_RATE_16000_CHANNELS_1\""
					    "}"
					    "}";
	char* state_json = get_all_state_json_string();
	printf("------------------------------- submit audio request\n");
    conn_send_request(event_json, state_json, audio, len, head_resp_cb, body_resp_cb);
	return 0;

}
#endif

int msg_ask_send()
{
    return 0;
}


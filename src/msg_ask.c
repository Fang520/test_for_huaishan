#include <stdio.h>
#include <string.h>
#include "http2.h"
#include "token.h"
#include "state.h"
#include "msg_ask.h"

static char buf[1024000];

int msg_ask_send(const char* pcm_buf, int pcm_len)
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

    char* boundary_1 = "\n--uniview-boundary\n"
                       "Content-Disposition: form-data; name=\"metadata\"\n"
                       "Content-Type: application/json; charset=UTF-8\n\n";
    char* boundary_2 = "\n--uniview-boundary\n"
                       "Content-Disposition: form-data; name=\"audio\"\n"
                       "Content-Type: application/octet-stream\n\n";
    char* boundary_end = "\n--uniview-boundary--";
    char* event_json = "\"event\": {"
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
    char* state_json = get_state_json();

    memset(buf, 0, sizeof(buf));
    sprintf(buf, "%s{%s,%s}%s", boundary_1, event_json, state_json, boundary_2);
    int len1 = strlen(buf);
    memcpy(buf + len1, pcm_buf, pcm_len);
    int len2 = sprintf(buf + len1 + pcm_len, "%s", boundary_end);
    return http2_send_msg(head, 5, buf, len1 + pcm_len + len2);
}


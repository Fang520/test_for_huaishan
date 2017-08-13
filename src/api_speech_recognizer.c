#include <stdio.h>
#include "connection.h"
#include "api_speech_recognizer.h"

static int head_resp_cb(nghttp2_nv* nva, int nvlen)
{
	int i;
	
	printf("========= get audio resp\n");
    for (i = 0; i < nvlen; i++)
    {
        fwrite(nva[i].name, 1, nva[i].namelen, stdout);
        printf(": ");
        fwrite(nva[i].value, 1, nva[i].valuelen, stdout);
        printf("\n");
    }
	return 0;
}

static int body_resp_cb(char* buf, int len)
{
	printf("========= get audio body resp\n");
	FILE* f = fopen("audio.dat", "wb");
	if (f)
	{
		fwrite(buf, 1, len, f);
		fclose(f);
	}
	return 0;
}

int api_speech_recognizer(char* audio, int len)
{
	char* event_json =  "\"event\": {"
					    "    \"header\": {"
					    "        \"dialogRequestId\": \"avs-dialog-id-1502547094-1\","
					    "        \"namespace\": \"SpeechRecognizer\","
					    "        \"name\": \"Recognize\","
					    "        \"messageId\": \"api_speech_recognizer\""
					    "    },"
					    "    \"payload\": {"
					    "        \"profile\": \"NEAR_FIELD\","
					    "        \"format\": \"AUDIO_L16_RATE_16000_CHANNELS_1\""
					    "    }"
					    "}";
	char* state_json = get_all_state_json_string();
    conn_send_request(event_json, state_json, audio, len, head_resp_cb, body_resp_cb);
}



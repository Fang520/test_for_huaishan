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

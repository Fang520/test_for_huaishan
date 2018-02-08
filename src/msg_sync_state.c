msg_t* build_sync_state_msg()
{
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
    conn_send_request(event_json, state_json, 0, 0, head_resp_cb, 0);
}
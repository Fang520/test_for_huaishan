#include <stdio.h>
#include "state.h"

static char buf[2048];

char* get_alerts_state_json_string()
{
	char* json =	"{"
					"\"header\": {"
					"\"namespace\": \"Alerts\","
					"\"name\": \"AlertsState\""
					"},"
					"\"payload\": {"
					"\"allAlerts\": [],"
					"\"activeAlerts\": []"
					"}"
					"}";
	return json;
}

char* get_volume_state_json_string()
{
	char* json =	"{"
					"\"header\": {"
					"\"namespace\": \"Speaker\","
					"\"name\": \"SpeakerState\""
					"},"
					"\"payload\": {"
					"\"volume\": 50,"
					"\"muted\": false"
					"}"
					"}";
	return json;
}

char* get_all_state_json_string()
{
	char* str1 = get_alerts_state_json_string();
	char* str2 = get_volume_state_json_string();
	sprintf(buf, "\"context\": [%s,%s]", str1, str2);
	return buf;
}


#if 0
char* get_recognizer_state_json_string()
{
	return 0;
/*	
	{
		"header": {
			"namespace": "SpeechRecognizer",
			"name": "RecognizerState"
		},
		"payload": {
			"wakeword": "ALEXA"
		}
	}
*/
}

char* get_playback_state_json_string(char* token, int offset, char* activity)
{
	return 0;
/*
	{
		"header": {
			"namespace": "AudioPlayer",
			"name": "PlaybackState"
		},
		"payload": {
			"token": "{{STRING}}",
			"offsetInMilliseconds": {{LONG}},
			"playerActivity": "{{STRING}}"
		}
	}
*/
}

char* get_speech_state_json_string(char* token, int offset, char* activity)
{
	return 0;
	/*
	{
		"header": {
			"namespace": "SpeechSynthesizer",
			"name": "SpeechState"
		},
		"payload": {
			"token": "{{STRING}}",
			"offsetInMilliseconds": {{LONG}},
			"playerActivity": "{{STRING}}"
		}
	}
*/
}

char* get_indicator_state_json_string(int is_enabled, int is_visual)
{
	return 0;
	/*
	{
		"header": {
			"namespace": "Notifications",
			"name": "IndicatorState"
		},
		"payload": {
			"isEnabled": {{BOOLEAN}},
			"isVisualIndicatorPersisted": {{BOOLEAN}}
		}
	}
*/
}
#endif

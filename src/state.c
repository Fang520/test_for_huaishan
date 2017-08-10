#include "state.h"

char* get_recognizer_state_json_string()
{
	{
		"header": {
			"namespace": "SpeechRecognizer",
			"name": "RecognizerState"
		},
		"payload": {
			"wakeword": "ALEXA"
		}
	}

}

char* get_playback_state_json_string(char* token, int offset, char* activity)
{
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

}

char* get_alerts_state_json_string(char* token, char* type, int time, char* token_act, char* type_act, int time_act)
{
	{
		"header": {
			"namespace": "Alerts",
			"name": "AlertsState"
		},
		"payload": {
			"allAlerts": [
							  {
					"token": "{{STRING}}",
					"type": "{{STRING}}",
					"scheduledTime": "{{STRING}}"
				}
			],
			"activeAlerts": [
							  {
					"token": "{{STRING}}",
					"type": "{{STRING}}",
					"scheduledTime": "{{STRING}}"
				}
			]
		}
	}

}

char* get_volume_state_json_string(int volume, int muted)
{
	{
		"header": {
			"namespace": "Speaker",
			"name": "VolumeState"
		},
		"payload": {
			"volume": {{LONG}},
			"muted": {{BOOLEAN}}
		}
	}

}

char* get_speech_state_json_string(char* token, int offset, char* activity)
{
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

}

char* get_indicator_state_json_string(int is_enabled, int is_visual)
{
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

}


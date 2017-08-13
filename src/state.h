#ifndef STATE_H
#define STATE_H

enum STATE_TYPE {
	RecognizerState,
	PlaybackState,
	AlertsState,
	VolumeState,
	SpeechState,
	IndicatorState
};

char* get_all_state_json_string();
char* get_recognizer_state_json_string();
char* get_playback_state_json_string(char* token, int offset, char* activity);
char* get_alerts_state_json_string(char* token, char* type, int time, char* token_act, char* type_act, int time_act);
char* get_volume_state_json_string(int volume, int muted);
char* get_speech_state_json_string(char* token, int offset, char* activity);
char* get_indicator_state_json_string(int is_enabled, int is_visual);


#endif


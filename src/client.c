#include <stdio.h>
#include "connection.h"
#include "client.h"
#include "api_system.h"

int client_open()
{
	int ret;

	api_alerts_init();
	api_audioplayer_init();
	api_playbackcontroller_init();
	api_speaker_init();
	api_speech_recognizer_init();
	api_speech_synthesizer_init();
	api_system_init();

	ret = conn_open();
	if (ret != 0)
		return ret;
	
	ret = api_system_sync_status();
	if (ret != 0)
		return ret;
		
 	return 0;
}

int client_close()
{
	conn_close();
	return 0;
}

int client_talk()
{
	return 0;
}



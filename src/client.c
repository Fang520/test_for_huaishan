#include <stdio.h>
#include <unistd.h>
#include "connection.h"
#include "api_system.h"
#include "api_speech_recognizer.h"
#include "client.h"

int client_open()
{
    conn_open();
    //api_system_sync_state();
    return 0;
}

int client_close()
{
    conn_close();
    return 0;
}

int client_talk(char* audio, int len)
{
    api_speech_recognizer(audio, len);
    return 0;
}

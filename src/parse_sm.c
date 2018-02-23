#include <stdio.h>
#include <string.h>
#include <time.h>
#include "parse_sm.h"

#define STATE_IDLE 0
#define STATE_AUDIO 1

static int state = STATE_IDLE;
static FILE* audio_fp = 0;
static char boundary[256] = {0};

void parse_sm_run(const char* data, int len)
{
    if (state == STATE_IDLE)
    {
        char* archor = "octet-stream\r\n\r\n";
        int archor_len = strlen(archor);
        char* p = memmem(data, len, archor, archor_len);
        if (p)
        {
            char name[32];
            sprintf(name, "audio_%d.mp3", time(0));
            audio_fp = fopen(name, "wb");
            state == STATE_AUDIO;
            p += archor_len;
            parse_sm_run(p, len - (p - data));
        }
    }
    else if (state == STATE_AUDIO)
    {
        int boundary_len = strlen(boundary);
        char* p = memmem(data, len, boundary, boundary_len);
        if (p)
        {
            if (audio_fp)
            {
                fwrite(data, 1, p - data, audio_fp);
                fclose(audio_fp);
                audio_fp = 0;
            }
            state = STATE_IDLE;
            p += boundary_len;
            parse_sm_run(p, len - (p - data));
        }
        else
        {
            if (audio_fp)
            {
                fwrite(data, 1, len, audio_fp);
            }        
        }
    }
}

void parse_sm_set_boundary(const char* str)
{
    sprintf(boundary, "\r\n--%s", str);
}

void parse_sm_clean()
{
    state = STATE_IDLE;
    if (audio_fp)
    {
        fclose(audio_fp);
        audio_fp = 0;
    }
}


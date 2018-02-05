#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "client.h"

int g_quit = 0;
char* g_audio_buf = 0;
int g_audio_len = 0;

int main(int argc, char** argv)
{
    FILE *pcm = fopen("test.pcm", "rb");
    if (!pcm)
    {
        printf("test.pcm does not exist\n");
        return -1;
    }
    fseek(pcm, 0, SEEK_END);
    int len = ftell(pcm);
    char *pcm_buf = (char*)malloc(len);
	fseek(pcm, 0, 0);
    int ret = fread(pcm_buf, 1, len, pcm);
    if (ret != len)
    {
        printf("read test.pcm error\n");
        free(pcm_buf);
        fclose(pcm);
        return -1;
    }

    g_audio_buf = pcm_buf;
    g_audio_len = len;

    client_open();
    while (g_quit == 0)
    {
        sleep(1);
    }

    printf("sleep 20s\n");
    sleep(20);
    
    client_close();

    free(pcm_buf);
	fclose(pcm);

    return 0;
}

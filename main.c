#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include "client.h"

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
    int ret = fread(pcm_buf, 1, len, pcm);
    if (ret != len)
    {
        printf("read test.pcm error\n");
        free(pcm_buf);
        fclose(pcm);
        return -1;
    }

    client_open();
    client_talk(pcm_buf, len);
	sleep(10);
    client_close();

    free(pcm_buf);
	fclose(pcm);

    return 0;
}

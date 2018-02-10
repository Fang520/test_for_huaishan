#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "http2.h"
#include "token.h"
#include "msg_ask.h"
#include "msg_downchannle.h"
#include "msg_sync_state.h"

static pthread_t pid_thread = 0;
static int quit_flag = 0;
static int sid_downchannel = 0;

static void on_data(char* data, int len)
{
    static int sn = 0;
    char name[32];
    sprintf(name, "data_%d.txt", sn);
    FILE* fp = fopen(name, "wb");
    if (fp)
    {
        fwrite(data, 1, len, fp);
        fclose(fp);
    }
    sn++;
}

static void http2_cb(char* type, int sid, char* data, int len)
{
    if (type == EVENT_TYPE_INIT)
    {
        sid_downchannel = msg_downchannel_send();
    }
    else if (type == EVENT_TYPE_RESP_CODE)
    {
        if (strncmp(data, "200", len) == 0)
        {
            if (sid == sid_downchannel)
            {
                msg_sync_state_send();
            }
        }
        else
        {
            quit_flag = 1;
        }
    }
    else if (type == EVENT_TYPE_DATA)
    {
        on_data(data, len);
    }
}

static void start_connection()
{
    get_token();
    http2_create(http2_cb);
    start_thread(thread);
}

static void stop_connection()
{
    quit_flag = 1;
    wait_for_safe_close();
    http2_destroy();
}

static void start_thread()
{
    pthread_create(&pid_thread, 0, (void*)thread, 0);
}

static void wait_for_safe_close()
{
    pthread_join(pid_thread, 0);
}

static void thread()
{
    while (quit_flag == 0)
    {
        http2_run();
    }
}

static char* load_pcm(char* name, int* len)
{
    char* buf = 0;
    int size = 0;
    FILE* fp = fopen(name, "rb");
    if (fp)
    {
        size = ftell(fp);
        rewind(fp);
        buf = (char*)malloc(size);
        fread(buf, 1, size, fp);
        fclose(fp);
    }
    *len = size;
    return buf;
}

static void test()
{
    int len;
    char* buf = load_pcm('test.pcm', &len);
    msg_ask_send(buf, len);
    free(buf);
}

int main(int argc, char** argv)
{
    start_connection();
    while (1)
    {
        char c = getchar();
        printf("input: %c\n", c);
        switch (c)
        {
            case '1': test();
            case 'q': break;
        }
    }
    stop_connection();
    printf("quit\n");
    return 0;
}


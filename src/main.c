#include <stdio.h>
#include "token.h"
#include "http2.h"

pthread_t pid_thread;
int avs_thread_quit_flag = 0;

void on_connected()
{
    http2_send_create_downchannel_msg();
}

void on_downchannel_resp()
{
    http2_send_sync_state_msg();
}

void on_reply_req(buf)
{
    playback(buf);
}

void on_timer()
{
    http2_send_sync_state_msg();
}

void http2_cb(char* head, char* body)
{
    msg_t* msg;
    if (head == 'connected')
    {
        on_connected();
    }
    if (head == 'sync')
    {
        on_sync_resp();
    }
    if (head == 'downchannel')
    {
        on_downchannel_created();
    }
    if (head == 'data')
    {
        on_reply();
    }
}

void start_connection()
{
    get_token();
    create_http2(http2_cb);
    start_thread(avs_thread);
}

void stop_connection()
{
    avs_thread_quit_flag = 1;
    wait_for_safe_close();
    destroy_http2();
}

void start_thread()
{
    pthread_create(&pid_thread, 0, (void*)avs_thread, 0);
}

void wait_for_safe_close()
{
    pthread_join(pid_thread, NULL);
}

void timer_process()
{
    on_timer();
}

void avs_thread()
{
    while (avs_thread_quit_flag == 0)
    {
        http2_process();
        timer_process();
    }
}

void test_1()
{
    int len;
    char* buf = load_pcm('1.pcm', &len);
    http2_send_ask_msg(buf, len);
}

void test_2()
{
    int len;
    char* buf = load_pcm('2.pcm', &len);
    http2_send_ask_msg(buf, len);
}

int main(int argc, char** argv)
{
    start_connection();
    while (1)
    {
        char c = getchar();
        printf("%s\n", c);
        switch (c)
        {
            case '1': test_1();
            case '2': test_2();
            case 'q': break;
        }
    }
    stop_connection();
    printf("quit\n");
    return 0;
}


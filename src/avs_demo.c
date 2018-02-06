#include <stdio.h>
#include "msgqueue.h"

pthread_t pid_thread;
int avs_thread_quit_flag = 0;
msg_queue_t* send_queue = 0;
msg_queue_t* recv_queue = 0;

void on_connected()
{
    msg_t* msg = build_create_downchannel_msg();
    add_msg_to_send_queue(msg);
}

void on_downchannel_created()
{
    msg_t* msg = build_sync_state_msg();
    add_msg_to_send_queue(msg);
}

void on_timer()
{
    msg_t* msg = build_sync_state_msg();
    add_msg_to_send_queue(msg);
}

void on_ask()
{
    msg_t* msg = build_ask_msg();
    add_msg_to_send_queue(msg);
}

void on_reply(buf)
{
    playback(buf);
}

void do_keeplive()
{
    printf("nothing\n");
}

void handle(msg_t* msg)
{
    if (msg->type == 'connected')
    {
        on_connected();
    }
    if (msg->type == 'downchannel_created')
    {
        on_downchannel_created();
    }
    if (msg->type == 'ask')
    {
        on_ask();
    }
    if (msg->type == 'keeplive')
    {
        do_keeplive();
    }
    if (msg->type == 'reply')
    {
        on_reply();
    }
    if (msg->type == 'timer')
    {
        on_timer();
    }
}

void avs_thread()
{
    while (avs_thread_quit_flag == 0)
    {
        http2_loop();
        if (msg_t* msg = get_msg_from_send_queue())
        {
            http2_send_msg(msg);
            free_msg(msg);
        }
        if (msg_t* msg = get_msg_from_recv_queue())
        {
            handle(msg);
            free_msg(msg);
        }
        if (get_timer())
        {
            on_timer();
        }
    }
}

void http2_cb(char* head, char* body)
{
    msg_t* msg;
    if (head == 'connected')
    {
        msg->type = 'connected';
    }
    if (head == 'sync')
    {
        msg->type = 'sync';
    }
    if (head == 'downchannel')
    {
        msg->type = 'downchannel';
    }
    if (head == 'data')
    {
        msg->type = 'reply';
        msg->data = body;
    }
    add_msg_to_recv_queue(msg);
}

void start_connection()
{
    create_send_queue();
    create_recv_queue();
    create_http2(http2_cb);
    start_thread(avs_thread);
}

void stop_connection()
{
    avs_thread_quit_flag = 1;
    wait_for_safe_close();
    destroy_http2();
    destroy_send_queue();
    destroy_recv_queue();
}

void start_thread()
{
    pthread_create(&pid_thread, 0, (void*)avs_thread, 0);
}

void wait_for_safe_close()
{
    pthread_join(pid_thread, NULL);
}

int get_timer()
{
    return 0;
}

void test_1()
{
    int len;
    char* buf = load_pcm('1.pcm', &len);
    msg_t* msg = build_ask_msg(buf, len);
    add_msg_to_send_queue(msg);
}

void test_2()
{
    int len;
    char* buf = load_pcm('2.pcm', &len);
    msg_t* msg = build_ask_msg(buf, len);
    add_msg_to_send_queue(msg);
}

void playback(char* buf, int len)
{
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


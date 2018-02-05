#include <stdio.h>
#include "msgqueue.h"

int avs_thread_quit_flag = 0;

void do_step1()
{
    msg_t* msg = build_msg('step2');
    add_msg_to_send_queue(msg);
}

void do_step2()
{
    msg_t* msg = build_msg('step3');
    add_msg_to_send_queue(msg);
}

void do_step3()
{
    msg_t* msg = build_msg('data');
    add_msg_to_send_queue(msg);
}

void do_keeplive()
{
    printf("nothing\n");
}

void do_timer()
{
    msg_t* msg = build_msg('keeplive');
    add_msg_to_send_queue(msg);  
}

void do_data(buf)
{
    playback(buf);
}


void handle(msg_t* msg)
{
    if (msg->type == 'step1')
    {
        do_step1();
    }
    if (msg->type == 'step2')
    {
        do_step2();
    }
    if (msg->type == 'step3')
    {
        do_step3();
    }
    if (msg->type == 'keeplive')
    {
        do_keeplive();
    }
    if (msg->type == 'data')
    {
        do_data();
    }
}

void avs_thread()
{
    while (avs_thread_quit_flag == 0)
    {
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
            do_timer();
        }
    }
}

void http2_cb(char* buf)
{
    msg_t* msg = build_msg(buf);
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

void create_send_queue()
{
}

void create_recv_queue()
{
}

void create_http2(http2_cb_t cb)
{
}

void start_thread()
{
}

void wait_for_safe_close()
{
}

void destroy_http2()
{
}

void send_1()
{
    char* buf = load_pcm('1.pcm');
    msg_t* msg = build_msg(buf);
    add_msg_to_send_queue(msg);
}

void send_2()
{
    char* buf = load_pcm('2.pcm');
    msg_t* msg = build_msg(buf);
    add_msg_to_queue(msg);
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
            case '1': send_1();
            case '2': send_2();
            case 'q': break;
        }
    }
    stop_connection();
    printf("quit\n");
    return 0;
}


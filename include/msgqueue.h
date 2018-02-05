#ifndef __SW_QUEUE_H__
#define __SW_QUEUE_H__

#include <semaphore.h>

typedef struct{	
    pthread_mutex_t lock;
    sem_t  sem;
    int read_off;
    int write_off;
    int msg_size;
    int max_msg;
    char msg[0];
}msg_queue_t;

extern msg_queue_t *CreateMsgQueue(unsigned int msgMax,unsigned int msgSize);

extern int DestoryMsgQueue(msg_queue_t *msgQueue);

extern int SendMsg(msg_queue_t *msgQueue,void *msg);

extern int RecvMsg(msg_queue_t *msgQueue,void *msg,int blocked);
    
#endif


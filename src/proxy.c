#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#define BUF_SIZE 1024
static char buf[BUF_SIZE]; 

int proxy(int sockfd, char* ip, int port)
{
    int n;
    
    memset(buf, 0, BUF_SIZE);

    sprintf(buf, "CONNECT %s:%s HTTP/1.1\r\n\r\n", ip, port);
    if (send(sockfd, buf, strlen(buf), 0) == -1)
    {
        printf("proxy send error\n");
        return -1;
    }

    n = recv(sockfd, buf, BUF_SIZE, 0);
    if (n == -1)
    {
        printf("proxy recv error\n");
        return -1;
    }
    
    buf[n] = '\0';
    if (strstr(buf, "HTTP/1.1 200") == 0)
    {
        printf("proxy resp error: %s\n", buf);
        return -1;
    }
    
    return 0;
}


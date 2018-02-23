#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#define BUF_SIZE 1024
static char buffer[BUF_SIZE]; 
static int proxy_flag = 0;

void enable_proxy()
{
    proxy_flag = 1;
}

int proxy_enabled()
{
    return proxy_flag;
}

char* proxy_ip()
{
    return "87.254.212.121";
}

int proxy_port()
{
    return 8080;
}

int establish_proxy(int sockfd, const char* ip, int port)
{
    int n;
    
    memset(buffer, 0, BUF_SIZE);

    sprintf(buffer, "CONNECT %s:%d HTTP/1.1\r\n\r\n", ip, port);
    if (send(sockfd, buffer, strlen(buffer), 0) == -1)
    {
        printf("proxy send error\n");
        return -1;
    }

    n = recv(sockfd, buffer, BUF_SIZE, 0);
    if (n == -1)
    {
        printf("proxy recv error\n");
        return -1;
    }
    
    buffer[n] = '\0';
    if (strstr(buffer, "HTTP/1.1 200") == 0)
    {
        printf("proxy resp error: %s\n", buffer);
        return -1;
    }
    
    return 0;
}


#ifndef PROXY_H
#define PROXY_H

void enable_proxy();
int proxy_enabled();
char* proxy_ip();
int proxy_port();
int establish_proxy(int sockfd, char* ip, int port);

#endif


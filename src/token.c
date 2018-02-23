#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "proxy.h"
#include "token.h"

#define BUF_SIZE 2048
static char buffer[BUF_SIZE];
static char* head          = "POST /auth/O2/token HTTP/1.1\r\n"
                             "Host: api.amazon.com\r\n"
                             "Content-Length: 737\r\n"
                             "Content-Type: application/x-www-form-urlencoded\r\n\r\n";
static char* body          = "client_secret=4728a27034104095d2c959a3980f6782941386f352692131b22562aeee87b7a6&grant_type=refresh_token&refresh_token=Atzr%7CIwEBIHQqL8L3UCU4veFSosf94GuJCUhysYHN8UL_qNXme9QipOnbVfnGjKlkoenwVkmFSKfHZOwi-NDWWzgu6HDk0MzIoL-rYZsNVzrmdhQQ9fRnkTIiXRFo5hwDV3hYpevhHUaV_CRjzTrA3Pc-RUQsv6Qde7LzjJTs4Y1q8nol8BIEPZx1OozyGxBkTzn8yafyKDLpR20IxXnRvCAKYy0pHx-a9QwW3krcmV4A9NK9UptuqFe_cfCVMYgLaV4MFQAUdgN6G4FLjEKGy0E2wwzJgNxNVn-84v_gUC1YI_DeW6TWPhVHV8vUmBAEsIfv-wGHotNolSXb2EmQZLkBWRT8Bd8BTWHob728CVX5rE8JnBG9myTQNcxed2y3io-YM93gCwrKlAJ4aNYhUN19WtGEu9d0cvWdiSBo0RTPUJUmxy_t72-eriBsby--kozloCbn47YEYUcnoVwzhcy_6qquMuZkvqOHD1sTAI5RIk95H-ZW3rEq4CufuSmhnzrLJQvh_iy4l4JsyOz5iRrR7t4SVgW-&client_id=amzn1.application-oa2-client.3d7b8ee6e47b40aeb2ecfcd3c7c26c3b";
static char* client_id     = "amzn1.application-oa2-client.3d7b8ee6e47b40aeb2ecfcd3c7c26c3b";
static char* client_secret = "4728a27034104095d2c959a3980f6782941386f352692131b22562aeee87b7a6";
static char* refresh_token = "Atzr|IwEBIHQqL8L3UCU4veFSosf94GuJCUhysYHN8UL_qNXme9QipOnbVfnGjKlkoenwVkmFSKfHZOwi-NDWWzgu6HDk0MzIoL-rYZsNVzrmdhQQ9fRnkTIiXRFo5hwDV3hYpevhHUaV_CRjzTrA3Pc-RUQsv6Qde7LzjJTs4Y1q8nol8BIEPZx1OozyGxBkTzn8yafyKDLpR20IxXnRvCAKYy0pHx-a9QwW3krcmV4A9NK9UptuqFe_cfCVMYgLaV4MFQAUdgN6G4FLjEKGy0E2wwzJgNxNVn-84v_gUC1YI_DeW6TWPhVHV8vUmBAEsIfv-wGHotNolSXb2EmQZLkBWRT8Bd8BTWHob728CVX5rE8JnBG9myTQNcxed2y3io-YM93gCwrKlAJ4aNYhUN19WtGEu9d0cvWdiSBo0RTPUJUmxy_t72-eriBsby--kozloCbn47YEYUcnoVwzhcy_6qquMuZkvqOHD1sTAI5RIk95H-ZW3rEq4CufuSmhnzrLJQvh_iy4l4JsyOz5iRrR7t4SVgW-";
static char* token_server_ip = "54.239.29.128";
static int token_server_port = 443;
static char* token = 0;
static SSL_CTX* ssl_ctx = 0;
static SSL *ssl = 0;
static int sockfd = -1;
static int socket_conn_flag = 0;
static int ssl_conn_flag = 0;

static void clean()
{
    if (ssl_conn_flag) SSL_shutdown(ssl);
    if (socket_conn_flag) shutdown(sockfd, SHUT_WR);
    if (sockfd != -1) close(sockfd);
    if (ssl) SSL_free(ssl);
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
}

char* get_token()
{
    if (token)
    {
        return token;
    }

    SSL_library_init();
    ssl_ctx = SSL_CTX_new (SSLv23_client_method());

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
    {
        printf("get_token: create socket error\n");
        clean();
        return 0;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (proxy_enabled())
    {
        addr.sin_port = htons(proxy_port());
        addr.sin_addr.s_addr = inet_addr(proxy_ip());
    }
    else
    {
        addr.sin_port = htons(token_server_port);
        addr.sin_addr.s_addr = inet_addr(token_server_ip);
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
    {
        printf("get_token: socket connect error\n");
        clean();
        return 0;
    }
    socket_conn_flag = 1;

    if (proxy_enabled())
    {
        if (establish_proxy(sockfd, token_server_ip, token_server_port) == -1)
        {
            printf("get_token: proxy error\n");
            clean();
            return 0;
        }
    }

    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0)
    {
        printf("get_token: SSL_connect error\n");
        clean();
        return 0;
    }
    ssl_conn_flag = 1;

    memset(buffer, 0, BUF_SIZE);
    sprintf(buffer, "%s%s", head, body);
    if (SSL_write(ssl, buffer, strlen(buffer)) <= 0)
    {
        printf("get_token: SSL_write error\n");
        clean();
        return 0;
    }

    memset(buffer, 0, BUF_SIZE);
    int len = SSL_read(ssl, buffer, BUF_SIZE - 1);
    if (len <= 0)
    {
        printf("get_token: SSL_read error\n");
        clean();
        return 0;
    }

    buffer[len] = '\0'; // {"access_token":"...","refresh_token":"...","token_type":"bearer","expires_in":3600}
    const char* anchor1 = "access_token\":\"";
    const char* anchor2 = "\",\"refresh_token";
    const char* addition = "Bearer ";
    char* p1 = strstr(buffer, anchor1);
    char* p2 = strstr(buffer, anchor2);
    if (p1 == 0 || p2 == 0)
    {
        printf("get_token: token format error\n");
        clean();
        return 0; 
    }
    p1 += strlen(anchor1);
    p1 -= strlen(addition);
    memcpy(p1, addition, strlen(addition));
    *p2 = '\0';

    token = p1;

    printf("got token: %s\n", token);

    clean();

    return token;
}


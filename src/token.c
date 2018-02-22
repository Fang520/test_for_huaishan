#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "proxy.h"
#include "token.h"

const char* DEST_IP = "54.239.29.128";
const int DEST_PORT = 443;
const char* PROXY_IP = "87.254.212.121";
const int PROXY_PORT = 8080;
const char* REQUEST = "POST /auth/O2/token HTTP/1.1\r\n"
                      "Host: api.amazon.com\r\n"
                      "Content-Length: 737\r\n"
                      "Content-Type: application/x-www-form-urlencoded\r\n\r\n";
const char* BODY    = "client_secret=4728a27034104095d2c959a3980f6782941386f352692131b22562aeee87b7a6&grant_type=refresh_token&refresh_token=Atzr%7CIwEBIHQqL8L3UCU4veFSosf94GuJCUhysYHN8UL_qNXme9QipOnbVfnGjKlkoenwVkmFSKfHZOwi-NDWWzgu6HDk0MzIoL-rYZsNVzrmdhQQ9fRnkTIiXRFo5hwDV3hYpevhHUaV_CRjzTrA3Pc-RUQsv6Qde7LzjJTs4Y1q8nol8BIEPZx1OozyGxBkTzn8yafyKDLpR20IxXnRvCAKYy0pHx-a9QwW3krcmV4A9NK9UptuqFe_cfCVMYgLaV4MFQAUdgN6G4FLjEKGy0E2wwzJgNxNVn-84v_gUC1YI_DeW6TWPhVHV8vUmBAEsIfv-wGHotNolSXb2EmQZLkBWRT8Bd8BTWHob728CVX5rE8JnBG9myTQNcxed2y3io-YM93gCwrKlAJ4aNYhUN19WtGEu9d0cvWdiSBo0RTPUJUmxy_t72-eriBsby--kozloCbn47YEYUcnoVwzhcy_6qquMuZkvqOHD1sTAI5RIk95H-ZW3rEq4CufuSmhnzrLJQvh_iy4l4JsyOz5iRrR7t4SVgW-&client_id=amzn1.application-oa2-client.3d7b8ee6e47b40aeb2ecfcd3c7c26c3b";
const char* client_id     = "amzn1.application-oa2-client.3d7b8ee6e47b40aeb2ecfcd3c7c26c3b";
const char* client_secret = "4728a27034104095d2c959a3980f6782941386f352692131b22562aeee87b7a6";
const char* refresh_token = "Atzr|IwEBIHQqL8L3UCU4veFSosf94GuJCUhysYHN8UL_qNXme9QipOnbVfnGjKlkoenwVkmFSKfHZOwi-NDWWzgu6HDk0MzIoL-rYZsNVzrmdhQQ9fRnkTIiXRFo5hwDV3hYpevhHUaV_CRjzTrA3Pc-RUQsv6Qde7LzjJTs4Y1q8nol8BIEPZx1OozyGxBkTzn8yafyKDLpR20IxXnRvCAKYy0pHx-a9QwW3krcmV4A9NK9UptuqFe_cfCVMYgLaV4MFQAUdgN6G4FLjEKGy0E2wwzJgNxNVn-84v_gUC1YI_DeW6TWPhVHV8vUmBAEsIfv-wGHotNolSXb2EmQZLkBWRT8Bd8BTWHob728CVX5rE8JnBG9myTQNcxed2y3io-YM93gCwrKlAJ4aNYhUN19WtGEu9d0cvWdiSBo0RTPUJUmxy_t72-eriBsby--kozloCbn47YEYUcnoVwzhcy_6qquMuZkvqOHD1sTAI5RIk95H-ZW3rEq4CufuSmhnzrLJQvh_iy4l4JsyOz5iRrR7t4SVgW-";

#define buffer_len 2048
static char buffer[buffer_len];
static char* token = 0;

char* get_token()
{
    if (token)
    {
        return token;
    }

    SSL_load_error_strings();
    SSL_library_init();
    SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method());
    int sockfd = socket(PF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
    {
        perror("Unable to create socket");
        return 0;
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if (proxy_enabled())
    {
        dest_addr.sin_port = htons(proxy_port());
        dest_addr.sin_addr.s_addr = inet_addr(proxy_ip());
    }
    else
    {
        dest_addr.sin_port = htons(DEST_PORT);
        dest_addr.sin_addr.s_addr = inet_addr(DEST_IP);
    }
    memset(&(dest_addr.sin_zero), '\0', 8);

    int status = connect(sockfd, (struct sockaddr*) &dest_addr, sizeof(struct sockaddr_in));

    if (status == -1)
    {
        perror("Unable to connect to the server");
        close(sockfd);
        return 0;
    }

    if (proxy_enabled())
    {
        if (establish_proxy(sockfd, DEST_IP, DEST_PORT) == -1)
        {
            perror("proxy error");
            close(sockfd);
            return 0;
        }
    }

    SSL *conn = SSL_new(ssl_ctx);
    SSL_set_fd(conn, sockfd);
    SSL_connect(conn);

    memset(buffer, 0, buffer_len);
    sprintf(buffer, "%s%s", REQUEST, BODY);
    ssize_t sendsize = SSL_write(conn, buffer, strlen(buffer));

    if (sendsize == -1)
    {
        perror("Unable to send to the server");
        {
            char buf[256];
            u_long err;

            while ((err = ERR_get_error()) != 0)
            {
                ERR_error_string_n(err, buf, sizeof(buf));
                printf("*** %s\n", buf);
            }
        }
        SSL_shutdown(conn);
        SSL_free(conn);
        close(sockfd);
        return 0;
    }

    memset(buffer, 0, buffer_len);
    ssize_t recsize = SSL_read(conn, buffer, buffer_len - 1);

    if (recsize == -1)
    {
        perror("Unable to send to the server");
        SSL_shutdown(conn);
        SSL_free(conn);
        close(sockfd);
        return 0;
    }

    buffer[recsize] = '\0';
    char* p1 = strstr(buffer, "access_token");
    p1 += 15;
    char* p2 = strstr(buffer, "refresh_token");
    p2 -= 3;
    *p2 = '\0';

    SSL_shutdown(conn);
    SSL_free(conn);
    SSL_CTX_free(ssl_ctx);
    shutdown(sockfd, SHUT_WR);
    close(sockfd);    

    memcpy(p1 - 7, "Bearer ", 7);
    token = p1 - 7;

    printf("===== got token\n");

    return p1 - 7;
}

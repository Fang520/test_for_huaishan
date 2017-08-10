/* SOCKET TIME */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "token.h"

// destination IP address
const char* DEST_IP = "54.239.29.128";

// destination IP port
const int DEST_PORT = 443;

// request to send to the destination
const char* REQUEST = "POST /auth/O2/token HTTP/1.1\nHost: api.amazon.com\nContent-Length: 737\nContent-Type: application/x-www-form-urlencoded\n\n";
char* data="client_secret=4728a27034104095d2c959a3980f6782941386f352692131b22562aeee87b7a6&grant_type=refresh_token&refresh_token=Atzr%7CIwEBIHQqL8L3UCU4veFSosf94GuJCUhysYHN8UL_qNXme9QipOnbVfnGjKlkoenwVkmFSKfHZOwi-NDWWzgu6HDk0MzIoL-rYZsNVzrmdhQQ9fRnkTIiXRFo5hwDV3hYpevhHUaV_CRjzTrA3Pc-RUQsv6Qde7LzjJTs4Y1q8nol8BIEPZx1OozyGxBkTzn8yafyKDLpR20IxXnRvCAKYy0pHx-a9QwW3krcmV4A9NK9UptuqFe_cfCVMYgLaV4MFQAUdgN6G4FLjEKGy0E2wwzJgNxNVn-84v_gUC1YI_DeW6TWPhVHV8vUmBAEsIfv-wGHotNolSXb2EmQZLkBWRT8Bd8BTWHob728CVX5rE8JnBG9myTQNcxed2y3io-YM93gCwrKlAJ4aNYhUN19WtGEu9d0cvWdiSBo0RTPUJUmxy_t72-eriBsby--kozloCbn47YEYUcnoVwzhcy_6qquMuZkvqOHD1sTAI5RIk95H-ZW3rEq4CufuSmhnzrLJQvh_iy4l4JsyOz5iRrR7t4SVgW-&client_id=amzn1.application-oa2-client.3d7b8ee6e47b40aeb2ecfcd3c7c26c3b";
//https://api.amazon.com/auth/o2/token

char* client_id = "amzn1.application-oa2-client.3d7b8ee6e47b40aeb2ecfcd3c7c26c3b";
char* client_secret = "4728a27034104095d2c959a3980f6782941386f352692131b22562aeee87b7a6";
char* refresh_token = "Atzr|IwEBIHQqL8L3UCU4veFSosf94GuJCUhysYHN8UL_qNXme9QipOnbVfnGjKlkoenwVkmFSKfHZOwi-NDWWzgu6HDk0MzIoL-rYZsNVzrmdhQQ9fRnkTIiXRFo5hwDV3hYpevhHUaV_CRjzTrA3Pc-RUQsv6Qde7LzjJTs4Y1q8nol8BIEPZx1OozyGxBkTzn8yafyKDLpR20IxXnRvCAKYy0pHx-a9QwW3krcmV4A9NK9UptuqFe_cfCVMYgLaV4MFQAUdgN6G4FLjEKGy0E2wwzJgNxNVn-84v_gUC1YI_DeW6TWPhVHV8vUmBAEsIfv-wGHotNolSXb2EmQZLkBWRT8Bd8BTWHob728CVX5rE8JnBG9myTQNcxed2y3io-YM93gCwrKlAJ4aNYhUN19WtGEu9d0cvWdiSBo0RTPUJUmxy_t72-eriBsby--kozloCbn47YEYUcnoVwzhcy_6qquMuZkvqOHD1sTAI5RIk95H-ZW3rEq4CufuSmhnzrLJQvh_iy4l4JsyOz5iRrR7t4SVgW-";

/*
POST /auth/o2/token HTTP/1.1
Host: 127.0.0.1
Connection: keep-alive
Accept-Encoding: gzip, deflate
Accept:
User-Agent: python-requests/2.18.1
Content-Length: 737
Content-Type: application/x-www-form-urlencoded

client_secret=4728a27034104095d2c959a3980f6782941386f352692131b22562aeee87b7a6&grant_type=refresh_token&refresh_token=Atzr%7CIwEBIHQqL8L3UCU4veFSosf94GuJCUhysYHN8UL_qNXme9QipOnbVfnGjKlkoenwVkmFSKfHZOwi-NDWWzgu6HDk0MzIoL-rYZsNVzrmdhQQ9fRnkTIiXRFo5hwDV3hYpevhHUaV_CRjzTrA3Pc-RUQsv6Qde7LzjJTs4Y1q8nol8BIEPZx1OozyGxBkTzn8yafyKDLpR20IxXnRvCAKYy0pHx-a9QwW3krcmV4A9NK9UptuqFe_cfCVMYgLaV4MFQAUdgN6G4FLjEKGy0E2wwzJgNxNVn-84v_gUC1YI_DeW6TWPhVHV8vUmBAEsIfv-wGHotNolSXb2EmQZLkBWRT8Bd8BTWHob728CVX5rE8JnBG9myTQNcxed2y3io-YM93gCwrKlAJ4aNYhUN19WtGEu9d0cvWdiSBo0RTPUJUmxy_t72-eriBsby--kozloCbn47YEYUcnoVwzhcy_6qquMuZkvqOHD1sTAI5RIk95H-ZW3rEq4CufuSmhnzrLJQvh_iy4l4JsyOz5iRrR7t4SVgW-&client_id=amzn1.application-oa2-client.3d7b8ee6e47b40aeb2ecfcd3c7c26c3b
*/
#define RESPONSE_SIZE 2048
static char response[RESPONSE_SIZE];
char* get_token() {

  // Initialize ssl libraries and error messages
  SSL_load_error_strings();
  SSL_library_init();
  SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method());
  
  // create a socket
  int sockfd = socket(PF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    perror("Unable to create socket");
    return 0;
  }

  // destination info
  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;       // host byte order
  dest_addr.sin_port = htons(DEST_PORT);    // short, network port
  dest_addr.sin_addr.s_addr = inet_addr(DEST_IP); // destination address
  memset(&(dest_addr.sin_zero), '\0', 8);         // zero out the rest of the struct

  // connect to the server
  int status = connect(sockfd, (struct sockaddr*) &dest_addr, sizeof(struct sockaddr_in));
  if (status == -1) {
    perror("Unable to connect to the server");
    close(sockfd);
    return 0;
  }

  // create SSL connection and attach it to the socket
  SSL *conn = SSL_new(ssl_ctx);
  SSL_set_fd(conn, sockfd);
  SSL_connect(conn);

  // send an encrypted message
  char buf[2048];
  memset(buf, 0, 2048);
  sprintf(buf, "%s%s", REQUEST, data);
//'client_id': self._auth.client_id,
//'client_secret': self._auth.client_secret,
//'refresh_token': self._auth.refresh_token,
//'grant_type': 'refresh_token',

  ssize_t sendsize = SSL_write(conn, buf, strlen(buf));
  if (sendsize == -1) {
    perror("Unable to send to the server");
    {
      char buf[256];
      u_long err;

      while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        printf("*** %s\n", buf);
      }
    }
    SSL_shutdown(conn);
    SSL_free(conn);
    close(sockfd);
    return 0;
  }
  

    // receive the response
    memset(response, 0, 2048);
    ssize_t recsize = SSL_read(conn, response, RESPONSE_SIZE-1);
    if (recsize == -1) {
      perror("Unable to send to the server");
      SSL_shutdown(conn);
      SSL_free(conn);
      close(sockfd);
      return 0;
    }

        
    response[recsize] = '\0';

    char* p1 = strstr(response, "access_token");
    p1 += 15;
    char* p2 = strstr(response, "refresh_token");
    p2 -= 3;
   
    *p2 = '\0';

    printf("%s\n", p1);

    SSL_shutdown(conn);
    SSL_free(conn);  
 
  close(sockfd);

  return p1;
}

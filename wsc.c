#include "wsc.h"
#include <stdio.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#define MAX_PORT 65535
#define WS_KEY_BUF_SIZE 25 // 16 -> 24 + 1 for null terminator

int wsc_client_init(wsc_client_t *client) {
  if (!client->host || client->port <= 0 || client->port > MAX_PORT) {
    return -1;
  }

  client->sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (client->sockfd < 0) {
    perror("socket");
    return -1;
  }

  struct sockaddr_in s_addr;
  memset(&s_addr, 0, sizeof(s_addr));
  s_addr.sin_family = AF_INET;
  s_addr.sin_port = htons(client->port);

  inet_pton(AF_INET, client->host, &s_addr.sin_addr);

  if (connect(client->sockfd, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
    perror("connect");
    close(client->sockfd);
    return -1;
  }

  return 0;
}

int wsc_handshake(wsc_client_t *client, const char *request_path) {
  sbuf_t ws_req;
  sbuf_init(&ws_req);

  char ws_key[32];
  wsc_generate_hs_key(ws_key);

  sbuf_printf(&ws_req, "GET %s HTTP/1.1\r\n", request_path);
  sbuf_printf(&ws_req, "Host: %s:%d\r\n", client->host, client->port);
  sbuf_append(&ws_req, "Upgrade: websocket\r\n");
  sbuf_append(&ws_req, "Connection: Upgrade\r\n");
  sbuf_printf(&ws_req, "Sec-WebSocket-Key: %s\r\n", ws_key);
  sbuf_printf(&ws_req, "Sec-WebSocket-Version: 13\r\n\r\n");

  ssize_t sent = send(client->sockfd, ws_req.data, ws_req.len, 0);
  if (sent < 0) {
    perror("send failed");
    sbuf_free(&ws_req);
    return -1;
  }

  sbuf_free(&ws_req);

  char response[512]; 
  ssize_t n = recv(client->sockfd, response, sizeof(response)-1, 0);
  if (n < 0) {
    perror("recv failed");
    return -1;
  }

  response[n] = '\0';

  if (strncmp(response, "HTTP/1.1 101", 12) == 0) {
    return 0;
  }

  return -1;
}

void wsc_generate_hs_key(char *key) {
  if (WS_KEY_BUF_SIZE < 25) return;

  unsigned char random_bytes[16];
  srand(time(NULL));

  for (size_t i = 0; i < 16; i++)
    random_bytes[i] = rand() & 0xFF;

  base64_encode(random_bytes, 16, key, WS_KEY_BUF_SIZE);
}

void wsc_client_deinit(wsc_client_t *client) {
  if (!client) return;
  if (client->sockfd >= 0) close(client->sockfd);
  client->sockfd = -1;
}



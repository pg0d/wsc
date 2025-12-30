#include "wsc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stdint.h>

#define MAX_PORT 65535
#define WSC_KEY_BUF_SIZE 25 // 16 -> 24 + 1 for null terminator

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
  sbuf_t wsc_req;
  sbuf_init(&wsc_req);

  char ws_key[32];
  wsc_generate_hs_key(ws_key);

  sbuf_printf(&wsc_req, "GET %s HTTP/1.1\r\n", request_path);
  sbuf_printf(&wsc_req, "Host: %s:%d\r\n", client->host, client->port);
  sbuf_append(&wsc_req, "Upgrade: websocket\r\n");
  sbuf_append(&wsc_req, "Connection: Upgrade\r\n");
  sbuf_printf(&wsc_req, "Sec-WebSocket-Key: %s\r\n", ws_key);
  sbuf_append(&wsc_req, "Sec-WebSocket-Version: 13\r\n\r\n");

  ssize_t sent = send(client->sockfd, wsc_req.data, wsc_req.len, 0);
  if (sent < 0) {
    perror("send failed");
    sbuf_free(&wsc_req);
    return -1;
  }

  sbuf_free(&wsc_req);

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
  if (WSC_KEY_BUF_SIZE < 25) return;

  unsigned char random_bytes[16];
  srand(time(NULL));

  for (size_t i = 0; i < 16; i++)
    random_bytes[i] = rand() & 0xFF;

  base64_encode(random_bytes, 16, key, WSC_KEY_BUF_SIZE);
}

void wsc_client_deinit(wsc_client_t *client) {
  if (!client) return;
  if (client->sockfd >= 0) close(client->sockfd);
  client->sockfd = -1;
}

void wsc_event_loop(wsc_client_t *client) {
  fd_set readfds;
  char buffer[1024];

  while (1) {
    FD_ZERO(&readfds);
    FD_SET(client->sockfd, &readfds);
    FD_SET(STDIN_FILENO, &readfds);

    int max_fd = (client->sockfd > STDIN_FILENO ? client->sockfd : STDIN_FILENO) + 1;

    int activity = select(max_fd, &readfds, NULL, NULL, NULL);
    if (activity < 0) {
      perror("select");
      break;
    }

    if (FD_ISSET(client->sockfd, &readfds)) {
      int n = recv(client->sockfd, buffer, sizeof(buffer), 0);
      if (n == 0) {
        perror("server closed connection");
        break;
      } else if (n < 0) {
        perror("recv error");
        break;
      }
      
      wsc_handle_incoming(client, buffer, n);
    }

    if (FD_ISSET(STDIN_FILENO, &readfds)) {
    }
  }
}

void wsc_handle_incoming(wsc_client_t *client, const char *buf, size_t len) {
  if (len < 2) return;

  unsigned char b0 = buf[0];
  unsigned char b1 = buf[1];

  int optcode = b0 & 0x0F;
  size_t payload_len = b1 & 0x7F;
  size_t pos = 2;

  if (payload_len == 126) {
    if (len < 4) return;
    payload_len = (buf[2] << 8) | buf[3];
    pos += 2;
  } else if (payload_len == 127) {
    return;
  }

  if (b1 & 0x80) {
    perror("Error: masked server frame\n");
    return;
  }

  if (pos + payload_len > len) return;
  const char *payload = buf + pos;

  if (optcode == 0x1 && client->on_message) {
    client->on_message(payload, payload_len);
  }
}

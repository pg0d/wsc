#ifndef WSC_H
#define WSC_H

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

typedef struct wsc_client wsc_client_t;
typedef struct wsc_options wsc_options_t;

typedef enum wsc_event_type {
  WSC_EVENT_OPEN,
  WSC_EVENT_MESSAGE,
  WSC_EVENT_CLOSE,
  WSC_EVENT_ERROR,
 } wsc_event_type_t;

struct wsc_options {
  int connect_timeout_sec;
  int recv_timeout_sec;
  int send_timeout_sec;
  int keep_alive;
};

typedef void (*wsc_on_message_cb)(const char *msg, size_t len);

struct wsc_client {
  int   sockfd;
  char  *host;
  int   port;
  wsc_on_message_cb on_message;
};

int   wsc_client_init(wsc_client_t *client);
void  wsc_client_deinit(wsc_client_t *client);

int   wsc_handshake(wsc_client_t *client, const char *request_path);
void  wsc_generate_hs_key(char *key); // Generate Handshake Key

void  wsc_event_loop(wsc_client_t *client);
void  wsc_handle_incoming(wsc_client_t *client, const char *buf, size_t len);

// ==== sbuf_t helper ====
typedef struct {
  char *data;
  size_t len;
  size_t cap;
} sbuf_t;

static inline void sbuf_init(sbuf_t *b) {
  b->data = NULL; b->len = 0; b->cap = 0;
}

static inline int sbuf_reserve(sbuf_t *b, size_t needed) {
  if (needed <= b->cap) return 0;
  size_t new_cap = b->cap ? b->cap*2 : 256;
  while(new_cap < needed) new_cap *= 2;
  char *p = (char *)realloc(b->data, new_cap);
  if (!p) return -1;
  b->data = p; b->cap = new_cap;
  return 0;
}

static inline int sbuf_append_n(sbuf_t *b, const void *data, size_t n) {
  if (sbuf_reserve(b, b->len + n + 1) < 0) return -1;
  memcpy(b->data + b->len, data, n);
  b->len += n;
  b->data[b->len] = '\0';
  return 0;
}

static inline int sbuf_append(sbuf_t *b, const char *s) { return sbuf_append_n(b, s, strlen(s)); }

static inline int sbuf_printf(sbuf_t *b, const char *fmt, ...) {
  va_list ap; va_start(ap, fmt);
  va_list ap2; va_copy(ap2, ap);
  int n = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (n < 0) { va_end(ap2); return -1; }
  if (sbuf_reserve(b, b->len + (size_t)n + 1) < 0) { va_end(ap2); return -1; }
  vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap2);
  va_end(ap2);
  b->len += (size_t)n;
  return 0;
}

static inline void sbuf_free(sbuf_t *b) {
  if (b->data) free(b->data);
  b->data = NULL; b->len = 0; b->cap = 0;
}

static inline int base64_encode(const unsigned char *in, size_t len, char *out, size_t out_size) {
    const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t required_size = 4 * ((len + 2) / 3) + 1;
    if (out_size < required_size) return -1; // not enough space

    size_t i = 0, j = 0;
    while (i < len) {
        unsigned int a = i < len ? in[i++] : 0;
        unsigned int b = i < len ? in[i++] : 0;
        unsigned int c = i < len ? in[i++] : 0;
        unsigned int triple = (a << 16) | (b << 8) | c;

        out[j++] = b64chars[(triple >> 18) & 0x3F];
        out[j++] = b64chars[(triple >> 12) & 0x3F];
        out[j++] = b64chars[(triple >> 6)  & 0x3F];
        out[j++] = b64chars[triple & 0x3F];
    }

    int mod = len % 3;
    if (mod) {
        out[j - 1] = '=';
        if (mod == 1) out[j - 2] = '=';
    }

    out[j] = '\0';
    return 0;
}

#endif

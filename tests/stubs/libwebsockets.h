#ifndef TTYD_TESTS_STUBS_LIBWEBSOCKETS_H
#define TTYD_TESTS_STUBS_LIBWEBSOCKETS_H

#ifndef LIBWEBSOCKET_H_3060898B846849FF9F88F5DB59B5950C
#define LIBWEBSOCKET_H_3060898B846849FF9F88F5DB59B5950C

#include <stddef.h>
#include <stdint.h>

struct lws_context {
  int dummy;
};

struct lws {
  void *user;
  int closed;
};

enum lws_callback_reasons {
  LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION = 0,
  LWS_CALLBACK_ESTABLISHED,
  LWS_CALLBACK_SERVER_WRITEABLE,
  LWS_CALLBACK_RECEIVE,
  LWS_CALLBACK_CLOSED
};

enum lws_close_status {
  LWS_CLOSE_STATUS_NOSTATUS = 0,
  LWS_CLOSE_STATUS_NORMAL = 1000,
  LWS_CLOSE_STATUS_GOINGAWAY = 1001,
  LWS_CLOSE_STATUS_PROTOCOL_ERR = 1002,
  LWS_CLOSE_STATUS_UNACCEPTABLE_OPCODE = 1003,
  LWS_CLOSE_STATUS_POLICY_VIOLATION = 1008,
  LWS_CLOSE_STATUS_UNEXPECTED_CONDITION = 1011
};

enum lws_token_indexes {
  WSI_TOKEN_GET_URI,
  WSI_TOKEN_HOST,
  WSI_TOKEN_ORIGIN,
  WSI_TOKEN_HTTP_AUTHORIZATION,
  WSI_TOKEN_HTTP_COLON_PATH,
  WSI_TOKEN_HTTP_URI_ARGS,
  WSI_TOKEN_HTTP_METHOD,
  WSI_TOKEN_HTTP_URI
};

enum lws_write_protocol {
  LWS_WRITE_TEXT = 0,
  LWS_WRITE_BINARY = 1
};

#define LWS_PRE 0

#define lwsl_notice(...)
#define lwsl_err(...)
#define lwsl_warn(...)
#define lwsl_debug(...)

int lws_hdr_copy(struct lws *wsi, char *buf, int len, enum lws_token_indexes token);
int lws_parse_uri(char *in, const char **prot, const char **address, int *port, const char **path);
int lws_callback_on_writable(struct lws *wsi);
void lws_cancel_service(struct lws_context *context);
void lws_close_reason(struct lws *wsi, enum lws_close_status status, unsigned char *buf, size_t len);
void *lws_wsi_user(struct lws *wsi);
int lws_get_peer_simple(struct lws *wsi, char *name, size_t len);
unsigned long lws_remaining_packet_payload(struct lws *wsi);
int lws_is_final_fragment(struct lws *wsi);
int lws_hdr_copy_fragment(struct lws *wsi, char *buf, int len, enum lws_token_indexes token, int fragment);
int lws_hdr_custom_copy(struct lws *wsi, char *buf, int len, const char *name, int namelen);
struct lws *lws_get_network_wsi(struct lws *wsi);
int lws_write(struct lws *wsi, unsigned char *buf, size_t len, enum lws_write_protocol protocol);

#endif  // LIBWEBSOCKET_H_3060898B846849FF9F88F5DB59B5950C

#endif  // TTYD_TESTS_STUBS_LIBWEBSOCKETS_H

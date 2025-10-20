#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "stubs/libwebsockets.h"

static void test_exit(int code);
#define exit(code) test_exit(code)

#include "../src/protocol.c"

#undef exit

volatile bool force_exit = false;
struct lws_context *context = NULL;
struct server *server = NULL;
struct endpoints endpoints;

// ---------------------------------------------------------------------------
// Stub implementations and helpers
// ---------------------------------------------------------------------------

struct writable_call {
  struct lws *wsi;
};

struct close_reason_call {
  struct lws *wsi;
  enum lws_close_status status;
  char reason[128];
  size_t len;
};

static int writable_call_count = 0;
static struct writable_call writable_calls[16];
static int cancel_service_calls = 0;
static int close_reason_call_count = 0;
static struct close_reason_call close_reason_calls[16];
static int pty_resume_call_count = 0;
static int pty_kill_call_count = 0;
static int exit_call_count = 0;
static int exit_last_code = -1;
static int buf_free_count = 0;
static int pty_resize_set_call_count = 0;
static uint16_t last_resize_set_cols = 0;
static uint16_t last_resize_set_rows = 0;
static unsigned char last_write_cmd = 0;
static char last_write_payload[1024];
static size_t last_write_payload_len = 0;

static void reset_stub_state(void) {
  writable_call_count = 0;
  cancel_service_calls = 0;
  close_reason_call_count = 0;
  pty_resume_call_count = 0;
  pty_kill_call_count = 0;
  exit_call_count = 0;
  exit_last_code = -1;
  buf_free_count = 0;
  pty_resize_set_call_count = 0;
  last_resize_set_cols = 0;
  last_resize_set_rows = 0;
  force_exit = false;
  last_write_cmd = 0;
  last_write_payload_len = 0;
  last_write_payload[0] = '\0';
}

static void test_exit(int code) {
  exit_call_count++;
  exit_last_code = code;
}

int lws_hdr_copy(struct lws *wsi, char *buf, int len, enum lws_token_indexes token) {
  (void)wsi;
  (void)buf;
  (void)len;
  (void)token;
  return 0;
}

int lws_parse_uri(char *in, const char **prot, const char **address, int *port, const char **path) {
  (void)in;
  if (prot != NULL) *prot = "http";
  if (address != NULL) *address = "localhost";
  if (port != NULL) *port = 80;
  if (path != NULL) *path = "/";
  return 0;
}

int lws_callback_on_writable(struct lws *wsi) {
  if (writable_call_count < (int)(sizeof(writable_calls) / sizeof(writable_calls[0]))) {
    writable_calls[writable_call_count++].wsi = wsi;
  }
  return 0;
}

void lws_cancel_service(struct lws_context *ctx) {
  (void)ctx;
  cancel_service_calls++;
}

void lws_close_reason(struct lws *wsi, enum lws_close_status status, unsigned char *buf, size_t len) {
  if (close_reason_call_count < (int)(sizeof(close_reason_calls) / sizeof(close_reason_calls[0]))) {
    struct close_reason_call *rec = &close_reason_calls[close_reason_call_count++];
    rec->wsi = wsi;
    rec->status = status;
    rec->len = len;
    size_t copy_len = len < sizeof(rec->reason) - 1 ? len : sizeof(rec->reason) - 1;
    if (buf != NULL && copy_len > 0) {
      memcpy(rec->reason, buf, copy_len);
    }
    rec->reason[copy_len] = '\0';
  }
  if (wsi != NULL) wsi->closed = 1;
}

void *lws_wsi_user(struct lws *wsi) { return wsi->user; }

int lws_get_peer_simple(struct lws *wsi, char *name, size_t len) {
  (void)wsi;
  if (len > 0) snprintf(name, len, "peer");
  return 0;
}

unsigned long lws_remaining_packet_payload(struct lws *wsi) {
  (void)wsi;
  return 0;
}

int lws_is_final_fragment(struct lws *wsi) {
  (void)wsi;
  return 1;
}

int lws_hdr_copy_fragment(struct lws *wsi, char *buf, int len, enum lws_token_indexes token, int fragment) {
  (void)wsi;
  (void)buf;
  (void)len;
  (void)token;
  (void)fragment;
  return 0;
}

int lws_hdr_custom_copy(struct lws *wsi, char *buf, int len, const char *name, int namelen) {
  (void)wsi;
  (void)buf;
  (void)len;
  (void)name;
  (void)namelen;
  return 0;
}

struct lws *lws_get_network_wsi(struct lws *wsi) { return wsi; }

int lws_write(struct lws *wsi, unsigned char *buf, size_t len, enum lws_write_protocol protocol) {
  (void)wsi;
  (void)protocol;
  if (len > 0 && buf != NULL) {
    last_write_cmd = buf[0];
    size_t payload_len = len > 0 ? len - 1 : 0;
    if (payload_len >= sizeof(last_write_payload)) {
      payload_len = sizeof(last_write_payload) - 1;
    }
    if (payload_len > 0) {
      memcpy(last_write_payload, (const char *)(buf + 1), payload_len);
    }
    last_write_payload[payload_len] = '\0';
    last_write_payload_len = payload_len;
  } else {
    last_write_cmd = 0;
    last_write_payload_len = 0;
    last_write_payload[0] = '\0';
  }
  return (int)len;
}

int uv_write(uv_write_t *req, uv_stream_t *handle, const uv_buf_t bufs[], unsigned int nbufs, uv_write_cb cb) {
  (void)req;
  (void)handle;
  (void)bufs;
  (void)nbufs;
  (void)cb;
  return 0;
}

const char *uv_strerror(int err) {
  (void)err;
  return "stub";
}

const char *uv_err_name(int err) {
  (void)err;
  return "stub";
}

void *xmalloc(size_t size) {
  void *ptr = malloc(size);
  if (ptr == NULL) {
    fprintf(stderr, "xmalloc failed\n");
    abort();
  }
  return ptr;
}

void *xrealloc(void *p, size_t size) {
  void *ptr = realloc(p, size);
  if (ptr == NULL) {
    fprintf(stderr, "xrealloc failed\n");
    abort();
  }
  return ptr;
}

pty_buf_t *pty_buf_init(char *base, size_t len) {
  pty_buf_t *buf = malloc(sizeof(pty_buf_t));
  buf->base = base;
  buf->len = len;
  buf->ref_count = 1;
  return buf;
}

void pty_buf_free(pty_buf_t *buf) {
  if (buf == NULL) return;
  free(buf->base);
  free(buf);
  buf_free_count++;
}

pty_buf_t *pty_buf_retain(pty_buf_t *buf) {
  if (buf == NULL) return NULL;
  buf->ref_count++;
  return buf;
}

void pty_buf_release(pty_buf_t *buf) {
  if (buf == NULL) return;
  buf->ref_count--;
  if (buf->ref_count <= 0) {
    pty_buf_free(buf);
  }
}

pty_process *process_init(void *ctx, uv_loop_t *loop, char *argv[], char *envp[]) {
  (void)argv;
  (void)envp;
  pty_process *process = calloc(1, sizeof(pty_process));
  process->ctx = ctx;
  process->loop = loop;
  return process;
}

bool process_running(pty_process *process) {
  return process != NULL && process->pid > 0;
}

void process_free(pty_process *process) {
  if (process == NULL) return;
  free(process->cwd);
  free(process);
}

int pty_spawn(pty_process *process, pty_read_cb read_cb, pty_exit_cb exit_cb) {
  process->read_cb = read_cb;
  process->exit_cb = exit_cb;
  process->pid = 123;
  return 0;
}

void pty_pause(pty_process *process) {
  (void)process;
}

void pty_resume(pty_process *process) {
  (void)process;
  pty_resume_call_count++;
}

int pty_write(pty_process *process, pty_buf_t *buf) {
  (void)process;
  (void)buf;
  return 0;
}

bool pty_resize(pty_process *process) {
  (void)process;
  return true;
}

bool pty_resize_set(pty_process *process, uint16_t columns, uint16_t rows) {
  pty_resize_set_call_count++;
  last_resize_set_cols = columns;
  last_resize_set_rows = rows;
  if (process != NULL) {
    process->columns = columns;
    process->rows = rows;
  }
  return true;
}

bool pty_kill(pty_process *process, int sig) {
  (void)process;
  (void)sig;
  pty_kill_call_count++;
  return true;
}

// ---------------------------------------------------------------------------
// Helper utilities for constructing test state
// ---------------------------------------------------------------------------

static void teardown_server(void) {
  if (server == NULL) return;
  free(server->client_wsi_list);
  free(server->first_client_user);
  free(server);
  server = NULL;
}

static void init_server(int capacity) {
  teardown_server();
  server = calloc(1, sizeof(struct server));
  server->shared_pty_mode = true;
  server->client_wsi_capacity = capacity;
  server->client_wsi_list = calloc((size_t)capacity, sizeof(struct lws *));
  server->session_columns = 120;
  server->session_rows = 32;
  server->snapshot_enabled = true;
}

static struct lws *make_client(struct pss_tty *pss, int slot, bool initialized) {
  struct lws *wsi = calloc(1, sizeof(struct lws));
  memset(pss, 0, sizeof(*pss));
  pss->initialized = initialized;
  pss->client_index = slot;
  pss->wsi = wsi;
  pss->is_primary_client = (slot == 0);
  wsi->user = pss;
  if (slot >= 0 && slot < server->client_wsi_capacity) {
    server->client_wsi_list[slot] = wsi;
  }
  server->active_client_count++;
  return wsi;
}

static void free_client(struct pss_tty *pss) {
  if (pss->pty_buf != NULL) {
    pty_buf_release(pss->pty_buf);
    pss->pty_buf = NULL;
  }
  free(pss->wsi);
  pss->wsi = NULL;
}

static pty_process *make_shared_process(struct server *srv, pty_ctx_t **out_ctx) {
  pty_ctx_t *ctx = xmalloc(sizeof(pty_ctx_t));
  memset(ctx, 0, sizeof(*ctx));
  ctx->server = srv;
  ctx->shared_mode = true;
  pty_process *process = calloc(1, sizeof(pty_process));
  process->ctx = ctx;
  srv->shared_process = process;
  if (out_ctx != NULL) *out_ctx = ctx;
  return process;
}

static void free_shared_process(pty_process *process, bool ctx_already_freed) {
  if (process == NULL) return;
  if (!ctx_already_freed && process->ctx != NULL) {
    free(process->ctx);
  }
  free(process);
  if (server != NULL && server->shared_process == process) {
    server->shared_process = NULL;
  }
}

// ---------------------------------------------------------------------------
// Tiny assertion helpers
// ---------------------------------------------------------------------------

#define ASSERT_TRUE(cond, msg)                                                               \
  do {                                                                                       \
    if (!(cond)) {                                                                           \
      fprintf(stderr, "Assertion failed (%s:%d): %s\n", __FILE__, __LINE__, (msg));          \
      return false;                                                                          \
    }                                                                                        \
  } while (0)

#define ASSERT_INT_EQ(actual, expected, msg)                                                 \
  do {                                                                                       \
    int _a = (int)(actual);                                                                  \
    int _e = (int)(expected);                                                                \
    if (_a != _e) {                                                                          \
      fprintf(stderr, "Assertion failed (%s:%d): %s (got %d expected %d)\n",                 \
              __FILE__, __LINE__, (msg), _a, _e);                                            \
      return false;                                                                          \
    }                                                                                        \
  } while (0)

#define ASSERT_PTR_EQ(actual, expected, msg)                                                 \
  do {                                                                                       \
    if ((actual) != (expected)) {                                                            \
      fprintf(stderr, "Assertion failed (%s:%d): %s\n", __FILE__, __LINE__, (msg));          \
      return false;                                                                          \
    }                                                                                        \
  } while (0)

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

static bool test_shared_read_resumes_after_broadcast(void) {
  reset_stub_state();
  init_server(2);
  server->active_client_count = 0;

  struct pss_tty pss_a;
  struct pss_tty pss_b;
  struct lws *wsi_a = make_client(&pss_a, 0, true);
  struct lws *wsi_b = make_client(&pss_b, 1, true);
  (void)wsi_a;
  (void)wsi_b;

  pty_ctx_t *ctx = NULL;
  pty_process *process = make_shared_process(server, &ctx);

  char *payload1 = strdup("chunk1");
  pty_buf_t *buf1 = pty_buf_init(payload1, strlen(payload1));

  ASSERT_INT_EQ(server->active_client_count, 2, "active client count seeded");
  shared_process_read_cb(process, buf1, false);

  ASSERT_INT_EQ(pty_resume_call_count, 0, "pty paused until clients flush");
  ASSERT_INT_EQ(writable_call_count, 2, "both clients scheduled writable");
  ASSERT_PTR_EQ(pss_a.pty_buf, buf1, "primary client received buffer");
  ASSERT_PTR_EQ(pss_b.pty_buf, buf1, "secondary client received buffer");
  ASSERT_INT_EQ(buf1->ref_count, 2, "buffer retains two references");

  int write_rc = callback_tty(pss_a.wsi, LWS_CALLBACK_SERVER_WRITEABLE, &pss_a, NULL, 0);
  ASSERT_INT_EQ(write_rc, 0, "primary client flush handled");
  ASSERT_INT_EQ(pty_resume_call_count, 0, "pty remains paused until all clients drain");
  ASSERT_TRUE(pss_a.pty_buf == NULL, "primary client cleared buffer");
  ASSERT_INT_EQ(buf1->ref_count, 1, "buffer still retained by secondary client");

  write_rc = callback_tty(pss_b.wsi, LWS_CALLBACK_SERVER_WRITEABLE, &pss_b, NULL, 0);
  ASSERT_INT_EQ(write_rc, 0, "secondary client flush handled");
  ASSERT_INT_EQ(pty_resume_call_count, 1, "pty resumed after all clients drained");
  ASSERT_TRUE(pss_b.pty_buf == NULL, "secondary client cleared buffer");
  ASSERT_INT_EQ(buf_free_count, 1, "buffer released after both clients flush");

  char *payload2 = strdup("chunk2");
  pty_buf_t *buf2 = pty_buf_init(payload2, strlen(payload2));

  shared_process_read_cb(process, buf2, false);
  ASSERT_INT_EQ(pty_resume_call_count, 1, "pty paused until second flush");
  ASSERT_INT_EQ(writable_call_count, 4, "both clients received second writable");
  ASSERT_PTR_EQ(pss_a.pty_buf, buf2, "primary received second buffer");
  ASSERT_PTR_EQ(pss_b.pty_buf, buf2, "secondary received second buffer");
  ASSERT_INT_EQ(buf2->ref_count, 2, "second buffer retains two references");

  write_rc = callback_tty(pss_a.wsi, LWS_CALLBACK_SERVER_WRITEABLE, &pss_a, NULL, 0);
  ASSERT_INT_EQ(write_rc, 0, "primary client flushed second buffer");
  ASSERT_INT_EQ(pty_resume_call_count, 1, "pty still paused until second client drains");
  ASSERT_TRUE(pss_a.pty_buf == NULL, "primary cleared second buffer");
  ASSERT_INT_EQ(buf2->ref_count, 1, "second buffer retained by secondary");

  write_rc = callback_tty(pss_b.wsi, LWS_CALLBACK_SERVER_WRITEABLE, &pss_b, NULL, 0);
  ASSERT_INT_EQ(write_rc, 0, "secondary client flushed second buffer");
  ASSERT_INT_EQ(pty_resume_call_count, 2, "pty resumed after secondary drained second buffer");
  ASSERT_TRUE(pss_b.pty_buf == NULL, "secondary cleared second buffer");
  ASSERT_INT_EQ(buf_free_count, 2, "second buffer released after both clients flush");

  free_client(&pss_a);
  free_client(&pss_b);
  free_shared_process(process, false);
  teardown_server();
  return true;
}

static bool test_shared_buffer_released_on_close(void) {
  reset_stub_state();
  init_server(2);
  server->active_client_count = 0;
  server->client_count = 2;

  struct pss_tty pss_a;
  struct pss_tty pss_b;
  make_client(&pss_a, 0, true);
  make_client(&pss_b, 1, true);

  char *payload = strdup("payload");
  pty_buf_t *shared = pty_buf_init(payload, strlen(payload));
  pss_a.pty_buf = pty_buf_retain(shared);
  pss_b.pty_buf = pty_buf_retain(shared);
  pty_buf_release(shared);  // simulate producer releasing original handle

  pty_ctx_t *ctx = NULL;
  pty_process *process = make_shared_process(server, &ctx);
  (void)process;

  int result = callback_tty(pss_a.wsi, LWS_CALLBACK_CLOSED, &pss_a, NULL, 0);
  ASSERT_INT_EQ(result, 0, "callback closed returned OK");
  ASSERT_TRUE(pss_a.pty_buf == NULL, "first client buffer cleared");
  ASSERT_INT_EQ(buf_free_count, 0, "buffer not freed while second client holds reference");
  ASSERT_INT_EQ(server->active_client_count, 1, "active client count decremented");
  ASSERT_TRUE(server->client_wsi_list[0] == NULL, "client removed from list");
  ASSERT_PTR_EQ(pss_b.pty_buf, shared, "second client still owns buffer");

  pty_buf_release(pss_b.pty_buf);
  pss_b.pty_buf = NULL;
  ASSERT_INT_EQ(buf_free_count, 1, "buffer released after final client");

  free_client(&pss_a);
  free_client(&pss_b);
  free_shared_process(process, false);
  teardown_server();
  return true;
}

static bool test_shared_resume_on_close_when_last_buffer_dropped(void) {
  reset_stub_state();
  init_server(1);
  server->active_client_count = 0;
  server->client_count = 1;

  struct pss_tty pss;
  make_client(&pss, 0, true);

  pty_ctx_t *ctx = NULL;
  pty_process *process = make_shared_process(server, &ctx);

  char *payload = strdup("chunk");
  pty_buf_t *buf = pty_buf_init(payload, strlen(payload));
  pss.pty_buf = buf;

  int result = callback_tty(pss.wsi, LWS_CALLBACK_CLOSED, &pss, NULL, 0);
  ASSERT_INT_EQ(result, 0, "closed callback succeeds");
  ASSERT_TRUE(pss.pty_buf == NULL, "pending buffer cleared on close");
  ASSERT_INT_EQ(buf_free_count, 1, "buffer freed when final reference dropped");
  ASSERT_INT_EQ(pty_resume_call_count, 1, "pty resumed after last buffer released on close");

  free_client(&pss);
  free_shared_process(process, false);
  teardown_server();
  return true;
}

static bool test_snapshot_preserves_whitespace(void) {
  reset_stub_state();
  init_server(1);
  server->snapshot_enabled = true;
  server->scrollback_size = 1000;

  ASSERT_TRUE(init_tsm_screen(server, 80, 24), "tsm screen initialized");

  static const char *box_lines[] = {
      "╭────────────────────────────────────────────────────╮",
      "│ ✨ Update available! 0.46.0 -> 0.47.0.             │",
      "│                                                    │",
      "│ See full release notes:                            │",
      "│                                                    │",
      "│ https://github.com/openai/codex/releases/latest    │",
      "│                                                    │",
      "│ Run npm install -g @openai/codex@latest to update. │",
      "╰────────────────────────────────────────────────────╯",
  };

  for (size_t i = 0; i < sizeof(box_lines) / sizeof(box_lines[0]); i++) {
    size_t len = strlen(box_lines[i]);
    char *line = malloc(len + 3);
    memcpy(line, box_lines[i], len);
    line[len] = '\r';
    line[len + 1] = '\n';
    line[len + 2] = '\0';
    tsm_vte_input(server->tsm_vte, line, len + 2);
    free(line);
  }

  char *snapshot_json = serialize_snapshot(server, 80, 24);
  ASSERT_TRUE(snapshot_json != NULL, "snapshot json generated");

  struct json_object *snapshot = json_tokener_parse(snapshot_json);
  ASSERT_TRUE(snapshot != NULL, "snapshot json parsed");

  struct json_object *lines = NULL;
  ASSERT_TRUE(json_object_object_get_ex(snapshot, "lines", &lines), "snapshot contains lines array");
  ASSERT_TRUE(json_object_get_type(lines) == json_type_array, "lines is an array");

  // Second line contains the headline text we care about
  struct json_object *line = json_object_array_get_idx(lines, 1);
  ASSERT_TRUE(line != NULL, "line extracted");
  const char *rendered = json_object_get_string(line);
  ASSERT_TRUE(rendered != NULL, "line string obtained");
  ASSERT_TRUE(strstr(rendered, "Update available!") != NULL, "headline retains spacing");
  ASSERT_TRUE(strstr(rendered, "See full release notes") == NULL, "line limited to headline content");

  json_object_put(snapshot);
  free(snapshot_json);
  cleanup_tsm_screen(server);
  teardown_server();
  return true;
}

static bool test_remove_client_without_initialization(void) {
  reset_stub_state();
  init_server(1);
  server->active_client_count = 0;
  server->client_count = 1;

  struct pss_tty pss;
  struct lws *wsi = make_client(&pss, 0, false);
  (void)wsi;

  int result = callback_tty(pss.wsi, LWS_CALLBACK_CLOSED, &pss, NULL, 0);
  ASSERT_INT_EQ(result, 0, "callback closed returned OK");
  ASSERT_INT_EQ(server->active_client_count, 0, "active count stays at zero");
  ASSERT_TRUE(server->client_wsi_list[0] == NULL, "stale client removed from list");

  free_client(&pss);
  teardown_server();
  return true;
}

static bool test_active_client_count_reset_on_process_exit(void) {
  reset_stub_state();
  init_server(2);
  server->active_client_count = 0;
  server->client_count = 2;

  struct pss_tty pss_a;
  struct pss_tty pss_b;
  make_client(&pss_a, 0, true);
  make_client(&pss_b, 1, true);

  pty_ctx_t *ctx = NULL;
  pty_process *process = make_shared_process(server, &ctx);
  process->exit_code = 0;
  process->pid = 321;

  shared_process_exit_cb(process);

  ASSERT_INT_EQ(close_reason_call_count, 2, "two clients received close reasons");
  ASSERT_INT_EQ(server->active_client_count, 0, "active client count cleared on exit");
  ASSERT_TRUE(server->client_wsi_list[0] == NULL && server->client_wsi_list[1] == NULL,
              "client list cleared");
  ASSERT_INT_EQ(pss_a.client_index, -1, "client index reset for first client");
  ASSERT_INT_EQ(pss_b.client_index, -1, "client index reset for second client");
  ASSERT_TRUE(server->shared_process == NULL, "shared process cleared");

  // Subsequent close should not underflow active client count
  int result = callback_tty(pss_a.wsi, LWS_CALLBACK_CLOSED, &pss_a, NULL, 0);
  ASSERT_INT_EQ(result, 0, "first client close after exit succeeds");
  result = callback_tty(pss_b.wsi, LWS_CALLBACK_CLOSED, &pss_b, NULL, 0);
  ASSERT_INT_EQ(result, 0, "second client close after exit succeeds");
  ASSERT_INT_EQ(server->active_client_count, 0, "active client count remains zero");

  free_client(&pss_a);
  free_client(&pss_b);
  process->ctx = NULL;
  free_shared_process(process, true);
  teardown_server();
  return true;
}

static bool test_once_flag_triggers_teardown(void) {
  reset_stub_state();
  init_server(1);
  server->once = true;
  server->sig_code = 9;
  server->client_count = 1;
  server->active_client_count = 0;

  struct pss_tty pss;
  make_client(&pss, 0, true);

  pty_ctx_t *ctx = NULL;
  pty_process *process = make_shared_process(server, &ctx);

  int result = callback_tty(pss.wsi, LWS_CALLBACK_CLOSED, &pss, NULL, 0);
  ASSERT_INT_EQ(result, 0, "callback closed returned OK");
  ASSERT_INT_EQ(pty_kill_call_count, 1, "pty_kill invoked for --once");
  ASSERT_INT_EQ(cancel_service_calls, 1, "service cancellation requested");
  ASSERT_INT_EQ(exit_call_count, 1, "exit called once");
  ASSERT_INT_EQ(exit_last_code, 0, "exit called with code 0");
  ASSERT_TRUE(force_exit, "force_exit flag set");

  free_client(&pss);
  free_shared_process(process, false);
  teardown_server();
  return true;
}

static bool test_fixed_geometry_sent_on_handshake(void) {
  reset_stub_state();
  init_server(1);
  server->session_columns = 132;
  server->session_rows = 43;
  server->snapshot_enabled = false;

  struct pss_tty pss;
  struct lws *wsi = make_client(&pss, 0, false);
  (void)wsi;

  pty_ctx_t *ctx = NULL;
  pty_process *process = make_shared_process(server, &ctx);
  server->shared_process = process;

  pss.initial_cmd_index = sizeof(initial_cmds);
  pss.pending_session_resize = true;
  pss.resize_sent = false;
  pss.client_index = 0;

  int rc = callback_tty(pss.wsi, LWS_CALLBACK_SERVER_WRITEABLE, &pss, NULL, 0);
  ASSERT_INT_EQ(rc, 0, "handshake writable succeeded");
  ASSERT_INT_EQ(last_write_cmd, SESSION_RESIZE, "session resize frame sent first");

  struct json_object *obj = json_tokener_parse(last_write_payload);
  ASSERT_TRUE(obj != NULL, "resize payload parsed");
  struct json_object *cols = NULL;
  struct json_object *rows = NULL;
  ASSERT_TRUE(json_object_object_get_ex(obj, "columns", &cols), "columns present");
  ASSERT_TRUE(json_object_object_get_ex(obj, "rows", &rows), "rows present");
  ASSERT_INT_EQ(json_object_get_int(cols), server->session_columns, "columns enforced");
  ASSERT_INT_EQ(json_object_get_int(rows), server->session_rows, "rows enforced");
  json_object_put(obj);

  ASSERT_TRUE(pss.resize_sent, "resize marked as sent");
  ASSERT_TRUE(!pss.pending_session_resize, "pending resize cleared");
  ASSERT_TRUE(!pss.initialized, "snapshot pending stage not yet marked initialized");

  free_shared_process(process, false);
  free_client(&pss);
  teardown_server();
  return true;
}

static bool test_client_resize_request_reasserts_geometry(void) {
  reset_stub_state();
  init_server(1);
  server->session_columns = 100;
  server->session_rows = 40;

  struct pss_tty pss;
  make_client(&pss, 0, true);
  pss.client_index = 0;
  pss.initialized = true;
  pss.resize_sent = true;
  pss.pending_session_resize = false;

  pty_ctx_t *ctx = NULL;
  pty_process *process = make_shared_process(server, &ctx);
  server->shared_process = process;

  const char *resize_json = "{\"columns\":200,\"rows\":55}";
  size_t payload_len = strlen(resize_json);
  char *payload = malloc(payload_len + 2);
  payload[0] = RESIZE_TERMINAL;
  memcpy(payload + 1, resize_json, payload_len);

  int rc = callback_tty(pss.wsi, LWS_CALLBACK_RECEIVE, &pss, payload, payload_len + 1);
  ASSERT_INT_EQ(rc, 0, "resize message processed");
  free(payload);

  ASSERT_TRUE(pss.pending_session_resize, "server queued session resize");
  ASSERT_INT_EQ(server->session_columns, 100, "session width unchanged");
  ASSERT_INT_EQ(server->session_rows, 40, "session height unchanged");

  rc = callback_tty(pss.wsi, LWS_CALLBACK_SERVER_WRITEABLE, &pss, NULL, 0);
  ASSERT_INT_EQ(rc, 0, "writable after resize processed");
  ASSERT_INT_EQ(last_write_cmd, SESSION_RESIZE, "session resize resent");
  ASSERT_TRUE(!pss.pending_session_resize, "pending flag cleared");

  struct json_object *obj = json_tokener_parse(last_write_payload);
  ASSERT_TRUE(obj != NULL, "resize payload parsed");
  struct json_object *cols = NULL;
  struct json_object *rows = NULL;
  ASSERT_TRUE(json_object_object_get_ex(obj, "columns", &cols), "columns present");
  ASSERT_TRUE(json_object_object_get_ex(obj, "rows", &rows), "rows present");
  ASSERT_INT_EQ(json_object_get_int(cols), server->session_columns, "columns enforced after resize");
  ASSERT_INT_EQ(json_object_get_int(rows), server->session_rows, "rows enforced after resize");
  json_object_put(obj);

  free_shared_process(process, false);
  free_client(&pss);
  teardown_server();
  return true;
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

int main(void) {
  struct {
    const char *name;
    bool (*fn)(void);
  } tests[] = {
      {"shared_read_resumes_after_broadcast", test_shared_read_resumes_after_broadcast},
      {"shared_buffer_released_on_close", test_shared_buffer_released_on_close},
      {"shared_resume_on_close_when_last_buffer_dropped", test_shared_resume_on_close_when_last_buffer_dropped},
      {"snapshot_preserves_whitespace", test_snapshot_preserves_whitespace},
      {"remove_client_without_initialization", test_remove_client_without_initialization},
      {"active_client_count_reset_on_process_exit", test_active_client_count_reset_on_process_exit},
      {"fixed_geometry_sent_on_handshake", test_fixed_geometry_sent_on_handshake},
      {"client_resize_request_reasserts_geometry", test_client_resize_request_reasserts_geometry},
      {"once_flag_triggers_teardown", test_once_flag_triggers_teardown},
  };

  size_t passed = 0;
  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    reset_stub_state();
    if (tests[i].fn()) {
      passed++;
    } else {
      fprintf(stderr, "Test failed: %s\n", tests[i].name);
      return 1;
    }
  }

  printf("All %zu shared PTY regression tests passed\n", passed);
  return 0;
}

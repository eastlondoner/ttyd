#include <errno.h>
#include <json.h>
#include <libwebsockets.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pty.h"
#include "server.h"
#include "utils.h"

// Buffer overflow protection - max buffer size per client
#define MAX_CLIENT_BUFFER_SIZE (1024 * 1024)  // 1MB per client
#define SOFT_DROP_THRESHOLD (MAX_CLIENT_BUFFER_SIZE * 4 / 10)  // 40% of max (400KB)

// initial message list
static char initial_cmds[] = {SET_WINDOW_TITLE, SET_PREFERENCES};

struct pending_shared_buffer {
  pty_buf_t *buf;
  struct pending_shared_buffer *next;
};

static void shared_client_buffers_init(struct pss_tty *pss) {
  if (pss == NULL) return;
  pss->pending_pty_head = NULL;
  pss->pending_pty_tail = NULL;
  pss->pending_pty_bytes = 0;
  pss->pty_buf = NULL;
  pss->soft_dropped_bytes = 0;
}

static void shared_client_buffers_enqueue(struct pss_tty *pss, pty_buf_t *buf) {
  if (pss == NULL || buf == NULL) return;

  struct pending_shared_buffer *node = xmalloc(sizeof(struct pending_shared_buffer));
  node->buf = pty_buf_retain(buf);
  node->next = NULL;

  if (pss->pending_pty_tail != NULL) {
    pss->pending_pty_tail->next = node;
  } else {
    pss->pending_pty_head = node;
  }

  pss->pending_pty_tail = node;
  pss->pending_pty_bytes += buf->len;
  pss->pty_buf = pss->pending_pty_head != NULL ? pss->pending_pty_head->buf : NULL;
  
  // Update global pending bytes counter (only for non-snapshot_pending clients)
  if (!pss->snapshot_pending && server != NULL) {
    server->global_pending_bytes += buf->len;
  }
}

static void shared_client_buffers_pop(struct pss_tty *pss) {
  if (pss == NULL || pss->pending_pty_head == NULL) return;

  struct pending_shared_buffer *node = pss->pending_pty_head;
  size_t buf_len = node->buf->len;
  
  pss->pending_pty_head = node->next;
  if (pss->pending_pty_head == NULL) {
    pss->pending_pty_tail = NULL;
  }

  if (pss->pending_pty_bytes >= buf_len) {
    pss->pending_pty_bytes -= buf_len;
  } else {
    pss->pending_pty_bytes = 0;
  }

  // Update global pending bytes counter (guard against underflow)
  if (server != NULL && server->global_pending_bytes >= buf_len) {
    server->global_pending_bytes -= buf_len;
  } else if (server != NULL) {
    server->global_pending_bytes = 0;
  }

  pty_buf_release(node->buf);
  free(node);

  pss->pty_buf = pss->pending_pty_head != NULL ? pss->pending_pty_head->buf : NULL;
}

static void shared_client_buffers_clear(struct pss_tty *pss) {
  if (pss == NULL) return;
  while (pss->pending_pty_head != NULL) {
    shared_client_buffers_pop(pss);
  }
  pss->pending_pty_bytes = 0;
}

static int send_initial_message(struct lws *wsi, int index) {
  unsigned char message[LWS_PRE + 1 + 4096];
  unsigned char *p = &message[LWS_PRE];
  char buffer[128];
  int n = 0;

  char cmd = initial_cmds[index];
  switch (cmd) {
    case SET_WINDOW_TITLE:
      gethostname(buffer, sizeof(buffer) - 1);
      n = sprintf((char *)p, "%c%s (%s)", cmd, server->command, buffer);
      break;
    case SET_PREFERENCES:
      n = sprintf((char *)p, "%c%s", cmd, server->prefs_json);
      break;
    default:
      break;
  }

  return lws_write(wsi, p, (size_t)n, LWS_WRITE_BINARY);
}

static json_object *parse_window_size(const char *buf, size_t len, uint16_t *cols, uint16_t *rows) {
  json_tokener *tok = json_tokener_new();
  json_object *obj = json_tokener_parse_ex(tok, buf, len);
  struct json_object *o = NULL;

  if (json_object_object_get_ex(obj, "columns", &o)) *cols = (uint16_t)json_object_get_int(o);
  if (json_object_object_get_ex(obj, "rows", &o)) *rows = (uint16_t)json_object_get_int(o);

  json_tokener_free(tok);
  return obj;
}

static bool check_host_origin(struct lws *wsi) {
  char buf[256];
  memset(buf, 0, sizeof(buf));
  int len = lws_hdr_copy(wsi, buf, (int)sizeof(buf), WSI_TOKEN_ORIGIN);
  if (len <= 0) return false;

  const char *prot, *address, *path;
  int port;
  if (lws_parse_uri(buf, &prot, &address, &port, &path)) return false;
  if (port == 80 || port == 443) {
    sprintf(buf, "%s", address);
  } else {
    sprintf(buf, "%s:%d", address, port);
  }

  char host_buf[256];
  memset(host_buf, 0, sizeof(host_buf));
  len = lws_hdr_copy(wsi, host_buf, (int)sizeof(host_buf), WSI_TOKEN_HOST);

  return len > 0 && strcasecmp(buf, host_buf) == 0;
}

// NEW: Client tracking for shared PTY mode
static inline struct pss_tty *get_pss_from_wsi(struct lws *wsi) {
  return (struct pss_tty *)lws_wsi_user(wsi);
}

static bool send_session_resize(struct server *server, struct pss_tty *pss, struct lws *wsi);

static void add_client_to_list(struct server *server, struct lws *wsi) {
  // Resize array if needed (start at 8, double when full)
  if (server->active_client_count >= server->client_wsi_capacity) {
    int new_capacity = (server->client_wsi_capacity == 0) ? 8 : server->client_wsi_capacity * 2;
    struct lws **new_list = realloc(server->client_wsi_list,
                                     new_capacity * sizeof(struct lws *));
    if (new_list == NULL) {
      lwsl_err("Failed to allocate client list\n");
      return;
    }

    // Initialize new slots to NULL
    for (int i = server->client_wsi_capacity; i < new_capacity; i++) {
      new_list[i] = NULL;
    }

    server->client_wsi_list = new_list;
    server->client_wsi_capacity = new_capacity;
  }

  // Find empty slot or append
  for (int i = 0; i < server->client_wsi_capacity; i++) {
    if (server->client_wsi_list[i] == NULL) {
      server->client_wsi_list[i] = wsi;
      server->active_client_count++;

      struct pss_tty *pss = get_pss_from_wsi(wsi);
      pss->client_index = i;

      lwsl_notice("Client added to slot %d (total: %d)\n",
                  i, server->active_client_count);
      return;
    }
  }
}

static void remove_client_from_list(struct server *server, struct lws *wsi) {
  struct pss_tty *pss = get_pss_from_wsi(wsi);
  int slot = pss->client_index;

  if (slot >= 0 && slot < server->client_wsi_capacity) {
    if (server->client_wsi_list[slot] == wsi) {
      server->client_wsi_list[slot] = NULL;
      if (server->active_client_count > 0) {
        server->active_client_count--;
      } else {
        lwsl_warn("Attempted to remove client from empty list\n");
        server->active_client_count = 0;
      }

      lwsl_notice("Client removed from slot %d (remaining: %d)\n",
                  slot, server->active_client_count);

      // If this was the primary client and others remain, designate new primary
      if (pss->is_primary_client && server->active_client_count > 0) {
        for (int i = 0; i < server->client_wsi_capacity; i++) {
          if (server->client_wsi_list[i] != NULL) {
            struct pss_tty *new_primary = get_pss_from_wsi(server->client_wsi_list[i]);
            new_primary->is_primary_client = true;
            lwsl_notice("Client %d promoted to primary\n", i);
            break;
          }
        }
      }
    } else {
      lwsl_debug("WSI mismatch when removing client from slot %d\n", slot);
    }
  }

  pss->client_index = -1;
  pss->is_primary_client = false;
  pss->pending_session_resize = false;
  pss->resize_sent = false;
  pss->snapshot_pending = false;

  if (server->active_client_count == 0) {
    if (server->shared_process != NULL && (server->exit_no_conn || server->once)) {
      lwsl_notice("No clients remaining, killing shared process\n");
      pty_kill(server->shared_process, server->sig_code);
      // Will trigger shared_process_exit_cb
    }

    if (server->once) {
      lwsl_notice("Exiting server due to --once option.\n");
      force_exit = true;
      lws_cancel_service(context);
      exit(0);
    }
  }
}

static bool send_session_resize(struct server *server, struct pss_tty *pss, struct lws *wsi) {
  if (server == NULL || pss == NULL || wsi == NULL) return false;
  if (!server->shared_pty_mode) return false;

  if (server->session_columns == 0 || server->session_rows == 0) {
    lwsl_err("Session geometry is unset; cannot send resize to client %s\n", pss->address);
    return false;
  }

  json_object *resize = json_object_new_object();
  json_object_object_add(resize, "columns", json_object_new_int(server->session_columns));
  json_object_object_add(resize, "rows", json_object_new_int(server->session_rows));

  const char *json_str = json_object_to_json_string(resize);
  size_t json_len = strlen(json_str);
  unsigned char *message = xmalloc(LWS_PRE + 1 + json_len);
  unsigned char *p = &message[LWS_PRE];
  p[0] = SESSION_RESIZE;
  memcpy(p + 1, json_str, json_len);

  int written = lws_write(wsi, p, 1 + json_len, LWS_WRITE_BINARY);
  bool success = written >= 0;
  if (!success) {
    lwsl_err("failed to send session resize to client %s\n", pss->address);
  } else {
    lwsl_notice("Sent session resize %ux%u to client %s\n",
                server->session_columns,
                server->session_rows,
                pss->address);
  }

  free(message);
  json_object_put(resize);
  return success;
}

static bool shared_session_has_pending_buffers(struct server *server) {
  if (server == NULL || server->client_wsi_list == NULL) return false;

  for (int i = 0; i < server->client_wsi_capacity; i++) {
    if (server->client_wsi_list[i] == NULL) continue;
    struct pss_tty *pss = get_pss_from_wsi(server->client_wsi_list[i]);
    if (pss != NULL && pss->pty_buf != NULL) {
      return true;
    }
  }

  return false;
}

static pty_ctx_t *pty_ctx_init(struct pss_tty *pss) {
  pty_ctx_t *ctx = xmalloc(sizeof(pty_ctx_t));
  ctx->pss = pss;
  ctx->server = NULL;
  ctx->ws_closed = false;
  ctx->shared_mode = false;
  return ctx;
}

static void pty_ctx_free(pty_ctx_t *ctx) { free(ctx); }

static void process_read_cb(pty_process *process, pty_buf_t *buf, bool eof) {
  pty_ctx_t *ctx = (pty_ctx_t *)process->ctx;
  if (ctx->ws_closed) {
    pty_buf_free(buf);
    return;
  }

  if (eof && !process_running(process))
    ctx->pss->lws_close_status = process->exit_code == 0 ? 1000 : 1006;
  else
    ctx->pss->pty_buf = buf;
  lws_callback_on_writable(ctx->pss->wsi);
}

static void process_exit_cb(pty_process *process) {
  pty_ctx_t *ctx = (pty_ctx_t *)process->ctx;
  if (ctx->ws_closed) {
    lwsl_notice("process killed with signal %d, pid: %d\n", process->exit_signal, process->pid);
    goto done;
  }

  lwsl_notice("process exited with code %d, pid: %d\n", process->exit_code, process->pid);
  ctx->pss->process = NULL;
  ctx->pss->lws_close_status = process->exit_code == 0 ? 1000 : 1006;
  lws_callback_on_writable(ctx->pss->wsi);

done:
  pty_ctx_free(ctx);
}

// NEW: Shared mode callbacks and functions
static void shared_process_read_cb(pty_process *process, pty_buf_t *buf, bool eof);
static void shared_process_exit_cb(pty_process *process);
static void snapshot_timeout_cb(uv_timer_t *timer);
static char **build_args_from_server(struct server *server);
static char **build_env_from_server(struct server *server);

// libtsm helpers for snapshot support
static void tsm_log_cb(void *data, const char *file, int line, const char *fn,
                       const char *subs, unsigned int sev, const char *format,
                       va_list args);
static void tsm_write_cb(struct tsm_vte *vte, const char *u8, size_t len, void *data);
static bool init_tsm_screen(struct server *server, uint16_t columns, uint16_t rows);
static void cleanup_tsm_screen(struct server *server);
static char *serialize_snapshot(struct server *server, uint16_t cols, uint16_t rows);

// Timer callback to check for snapshot ACK timeouts
static void snapshot_timeout_cb(uv_timer_t *timer) {
  struct server *server = timer->data;
  uint64_t now = uv_now(server->loop);
  
  // Early exit if no clients or list not initialized
  if (server->client_wsi_capacity <= 0 || server->client_wsi_list == NULL) {
    return;
  }
  
  // Use a fixed-size stack array for efficiency (covers 99% of cases)
  // If more timeouts occur, process them in batches
  #define TIMEOUT_BATCH_SIZE 64
  struct lws *timed_out[TIMEOUT_BATCH_SIZE];
  int timed_out_count = 0;
  int total_timed_out = 0;
  
  for (int i = 0; i < server->client_wsi_capacity; i++) {
    if (server->client_wsi_list[i] == NULL) continue;
    
    struct pss_tty *pss = get_pss_from_wsi(server->client_wsi_list[i]);
    if (pss == NULL) continue;
    
    if (pss->snapshot_pending) {
      uint64_t elapsed = now - pss->snapshot_sent_at_ms;
      if (elapsed > server->snapshot_ack_timeout_ms) {
        uint64_t idle_ms = pss->last_activity_at_ms > 0 ? now - pss->last_activity_at_ms : elapsed;
        lwsl_warn("Client %d (%s) snapshot ACK timeout (%llu ms), idle for %llu ms, disconnecting\n",
                  pss->client_index, pss->address, (unsigned long long)elapsed, (unsigned long long)idle_ms);
        
        timed_out[timed_out_count++] = server->client_wsi_list[i];
        
        // If batch is full, process it immediately and continue scanning
        if (timed_out_count >= TIMEOUT_BATCH_SIZE) {
          for (int j = 0; j < timed_out_count; j++) {
            lws_close_reason(timed_out[j], 
                            LWS_CLOSE_STATUS_POLICY_VIOLATION,
                            (unsigned char *)"Snapshot ACK timeout", 20);
            lws_callback_on_writable(timed_out[j]);
          }
          total_timed_out += timed_out_count;
          timed_out_count = 0;
        }
      }
    }
  }
  
  // Close any remaining timed-out clients
  for (int i = 0; i < timed_out_count; i++) {
    lws_close_reason(timed_out[i], 
                    LWS_CLOSE_STATUS_POLICY_VIOLATION,
                    (unsigned char *)"Snapshot ACK timeout", 20);
    lws_callback_on_writable(timed_out[i]);
  }
  
  total_timed_out += timed_out_count;
  if (total_timed_out > 0) {
    lwsl_notice("Disconnected %d client(s) due to snapshot ACK timeout\n", total_timed_out);
  }
  
  #undef TIMEOUT_BATCH_SIZE
}

// Create shared PTY process (called for first client only)
static bool create_shared_process(struct server *server, struct pss_tty *first_pss) {
  if (server->shared_process != NULL) {
    lwsl_warn("Shared process already exists\n");
    return true;  // Already exists
  }

  uint16_t columns = server->session_columns;
  uint16_t rows = server->session_rows;
  if (columns == 0 || rows == 0) {
    lwsl_err("Session geometry must be non-zero (got %ux%u)\n", columns, rows);
    return false;
  }

  // Save first client's username for TTYD_USER
  if (first_pss->authenticated && strlen(first_pss->user) > 0) {
    server->first_client_user = strdup(first_pss->user);
  }

  // Create context pointing to server
  pty_ctx_t *ctx = xmalloc(sizeof(pty_ctx_t));
  ctx->pss = NULL;
  ctx->server = server;
  ctx->ws_closed = false;
  ctx->shared_mode = true;

  // Build args and env from server config
  char **args = build_args_from_server(server);
  char **envp = build_env_from_server(server);

  // Initialize process
  pty_process *process = process_init((void *)ctx, server->loop, args, envp);
  if (process == NULL) {
    lwsl_err("process_init failed\n");
    free(ctx);
    return false;
  }

  // Set process parameters
  process->columns = columns;
  process->rows = rows;
  if (server->cwd != NULL) {
    process->cwd = strdup(server->cwd);
  }

  // Initialize libtsm screen for snapshots (required in shared mode)
  if (!init_tsm_screen(server, columns, rows)) {
    lwsl_err("Failed to initialize libtsm screen\n");
    process_free(process);
    free(ctx);
    return false;
  }

  // Spawn the process with shared callbacks
  if (pty_spawn(process, shared_process_read_cb, shared_process_exit_cb) != 0) {
    lwsl_err("pty_spawn failed: %d (%s)\n", errno, strerror(errno));
    cleanup_tsm_screen(server);
    process_free(process);
    free(ctx);
    return false;
  }

  server->shared_process = process;

  lwsl_notice("Shared PTY process created (PID: %d, size: %dx%d)\n",
              process->pid, columns, rows);

  // Initialize global cap if not configured
  if (server->max_global_pending_bytes == 0) {
    server->max_global_pending_bytes = 8 * 1024 * 1024;  // 8 MB default
  }
  server->global_pending_bytes = 0;
  lwsl_notice("Global pending bytes cap: %zu bytes\n", server->max_global_pending_bytes);

  // Initialize and start snapshot ACK timeout timer
  if (server->snapshot_ack_timeout_ms == 0) {
    server->snapshot_ack_timeout_ms = 10000;  // 10 seconds default if not configured
  }
  uv_timer_init(server->loop, &server->snapshot_timer);
  server->snapshot_timer.data = server;
  uv_timer_start(&server->snapshot_timer, snapshot_timeout_cb, 1000, 1000);  // Check every 1 second
  server->snapshot_timer_active = true;
  lwsl_notice("Snapshot ACK timeout timer started (timeout: %u ms)\n", server->snapshot_ack_timeout_ms);

  // Resume the shared PTY process to start reading output
  pty_resume(process);

  return true;
}

// Broadcast PTY output to all connected clients (with reference counting)
static void shared_process_read_cb(pty_process *process, pty_buf_t *buf, bool eof) {
  pty_ctx_t *ctx = (pty_ctx_t *)process->ctx;
  struct server *server = ctx->server;

  if (eof) {
    lwsl_notice("PTY process reached EOF\n");
    pty_buf_free(buf);
    return;
  }

  size_t buf_len = buf->len;
  int delivered = 0;
  int skipped_pending = 0;
  int disconnected_overflow = 0;

  // Check for buffer overflow protection
  if (buf_len > MAX_CLIENT_BUFFER_SIZE) {
    lwsl_warn("PTY output buffer overflow (%zu bytes), dropping data\n", buf_len);
    pty_buf_free(buf);
    return;
  }

  // Feed PTY output to libtsm VTE for snapshot support
  if (server->tsm_vte != NULL && buf->base != NULL && buf_len > 0) {
    tsm_vte_input(server->tsm_vte, buf->base, buf_len);
    lwsl_debug("Fed %zu bytes to libtsm VTE\n", buf_len);
  }

  // Check if we would exceed global cap with this broadcast
  size_t projected_global = server->global_pending_bytes + (buf_len * (server->active_client_count - skipped_pending));
  bool global_cap_pressure = projected_global > server->max_global_pending_bytes;
  int soft_dropped = 0;
  
  // Broadcast to ALL connected clients using reference counting
  for (int i = 0; i < server->client_wsi_capacity; i++) {
    struct lws *client_wsi = server->client_wsi_list[i];
    if (client_wsi == NULL) continue;

    struct pss_tty *pss = get_pss_from_wsi(client_wsi);
    if (pss == NULL) continue;

    // Skip enqueuing to clients waiting for snapshot ACK
    if (pss->snapshot_pending) {
      skipped_pending++;
      lwsl_debug("Skipping enqueue to client %d - snapshot pending\n", pss->client_index);
      continue;
    }

    size_t pending_bytes = pss->pending_pty_bytes;
    size_t projected_bytes = pending_bytes + buf_len;

    // Check if this client already has too much buffered data queued
    if (pending_bytes > MAX_CLIENT_BUFFER_SIZE / 2 || projected_bytes > MAX_CLIENT_BUFFER_SIZE) {
      disconnected_overflow++;
      lwsl_warn("Client %d buffer overflow (pending=%zu, incoming=%zu), disconnecting\n",
                pss->client_index, pending_bytes, buf_len);
      shared_client_buffers_clear(pss);
      lws_close_reason(client_wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION,
                       (unsigned char *)"Buffer overflow", 15);
      continue;  // Skip this client
    }

    // Soft drop: skip clients above soft-drop threshold if global cap pressure
    if (global_cap_pressure && pending_bytes > SOFT_DROP_THRESHOLD) {
      soft_dropped++;
      pss->soft_dropped_bytes += buf_len;
      lwsl_debug("Soft drop: client %d above threshold (pending=%zu > %zu), skipping %zu bytes\n",
                 pss->client_index, pending_bytes, SOFT_DROP_THRESHOLD, buf_len);
      continue;
    }

    // Retain buffer for this client (increments ref_count) even if handshake pending.
    shared_client_buffers_enqueue(pss, buf);
    lws_callback_on_writable(client_wsi);
    delivered++;
  }

  // Release the original reference (buffer will be freed when all clients finish)
  pty_buf_release(buf);
  
  // Always resume PTY to maintain continuous read (independent of client drain state)
  pty_resume(server->shared_process);
  
  // Log broadcast results
  if (global_cap_pressure || soft_dropped > 0) {
    lwsl_notice("Broadcast %zu bytes: delivered=%d, soft_dropped=%d (global: %zu/%zu bytes), skipped_pending=%d, overflow=%d, active=%d\n",
                buf_len, delivered, soft_dropped, server->global_pending_bytes, 
                server->max_global_pending_bytes, skipped_pending, disconnected_overflow, server->active_client_count);
  } else {
    lwsl_debug("Broadcast %zu bytes: delivered=%d, skipped_pending=%d, overflow=%d, active=%d, global=%zu/%zu, PTY resumed\n", 
               buf_len, delivered, skipped_pending, disconnected_overflow, server->active_client_count,
               server->global_pending_bytes, server->max_global_pending_bytes);
  }

}

// Handle shared PTY process exit - affects all clients
static void shared_process_exit_cb(pty_process *process) {
  pty_ctx_t *ctx = (pty_ctx_t *)process->ctx;
  struct server *server = ctx->server;

  lwsl_notice("Shared PTY process exited: code=%d signal=%d\n",
              process->exit_code, process->exit_signal);

  // Build close reason message
  char reason[64];
  if (process->exit_signal > 0) {
    snprintf(reason, sizeof(reason), "Process killed by signal %d", process->exit_signal);
  } else {
    snprintf(reason, sizeof(reason), "Process exited with code %d", process->exit_code);
  }

  // Close ALL connected WebSocket clients
  int closed = 0;
  for (int i = 0; i < server->client_wsi_capacity; i++) {
    if (server->client_wsi_list[i] != NULL) {
      struct lws *client_wsi = server->client_wsi_list[i];
      struct pss_tty *pss = get_pss_from_wsi(client_wsi);

      if (pss->initialized) {
        pss->lws_close_status = process->exit_code == 0 ? 1000 : 1006;
        lws_close_reason(client_wsi,
                         process->exit_code == 0 ? 1000 : 1006,
                         (unsigned char *)reason,
                         strlen(reason));
        lws_callback_on_writable(client_wsi);
        closed++;
      }

      pss->client_index = -1;
      pss->is_primary_client = false;
      server->client_wsi_list[i] = NULL;
    }
  }

  lwsl_notice("Closing %d client connections\n", closed);

  // Clean up libtsm screen and VTE
  cleanup_tsm_screen(server);

  // Stop and close snapshot timer
  if (server->snapshot_timer_active) {
    uv_timer_stop(&server->snapshot_timer);
    uv_close((uv_handle_t *)&server->snapshot_timer, NULL);
    server->snapshot_timer_active = false;
    lwsl_notice("Snapshot timer stopped and closed\n");
  }

  // Clean up shared process
  server->shared_process = NULL;  // Clear before freeing to prevent race
  server->active_client_count = 0;

  // Exit server if -o (once) flag is set
  if (server->once) {
    lwsl_notice("Exiting server due to -o flag\n");
    force_exit = true;
    lws_cancel_service(context);
  }

  pty_ctx_free(ctx);
}

static char **build_args(struct pss_tty *pss) {
  int i, n = 0;
  char **argv = xmalloc((server->argc + pss->argc + 1) * sizeof(char *));

  for (i = 0; i < server->argc; i++) {
    argv[n++] = server->argv[i];
  }

  for (i = 0; i < pss->argc; i++) {
    argv[n++] = pss->args[i];
  }

  argv[n] = NULL;

  return argv;
}

static char **build_env(struct pss_tty *pss) {
  int i = 0, n = 2;
  char **envp = xmalloc(n * sizeof(char *));

  // TERM
  envp[i] = xmalloc(36);
  snprintf(envp[i], 36, "TERM=%s", server->terminal_type);
  i++;

  // TTYD_USER
  if (strlen(pss->user) > 0) {
    envp = xrealloc(envp, (++n) * sizeof(char *));
    envp[i] = xmalloc(40);
    snprintf(envp[i], 40, "TTYD_USER=%s", pss->user);
    i++;
  }

  envp[i] = NULL;

  return envp;
}

// NEW: Build args from server config only (shared mode - no URL args)
static char **build_args_from_server(struct server *server) {
  int argc = server->argc;
  char **args = xmalloc((argc + 1) * sizeof(char *));

  for (int i = 0; i < argc; i++) {
    args[i] = strdup(server->argv[i]);
  }
  args[argc] = NULL;

  return args;
}

// NEW: Build environment from server config (shared mode)
static char **build_env_from_server(struct server *server) {
  int i = 0, n = 2;
  char **envp = xmalloc(n * sizeof(char *));

  // TERM
  envp[i] = xmalloc(36);
  snprintf(envp[i], 36, "TERM=%s", server->terminal_type);
  i++;

  // TTYD_USER (use first_client_user if set)
  if (server->first_client_user != NULL && strlen(server->first_client_user) > 0) {
    envp = xrealloc(envp, (++n) * sizeof(char *));
    envp[i] = xmalloc(40);
    snprintf(envp[i], 40, "TTYD_USER=%s", server->first_client_user);
    i++;
  }

  envp[i] = NULL;

  return envp;
}

// libtsm logging callback
static void tsm_log_cb(void *data, const char *file, int line, const char *fn,
                       const char *subs, unsigned int sev, const char *format,
                       va_list args) {
  // Forward libtsm logs to lwsl
  // Severity: 0=debug, 1=info, 2=notice, 3=warning, 4=error, 5=critical, 6=alert, 7=fatal
  if (sev >= 3) {  // Only log warnings and above
    lwsl_warn("libtsm: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
  }
}

// libtsm write callback - sends data back to PTY (e.g., for responses to queries)
static void tsm_write_cb(struct tsm_vte *vte, const char *u8, size_t len, void *data) {
  // NOTE: We intentionally do NOT write VTE responses back to the PTY.
  // libtsm is only used server-side for snapshot generation, not for terminal emulation.
  // The actual terminal emulation happens in the browser via xterm.js.
  //
  // If we wrote VTE responses (e.g., OSC color query responses like "10;rgb:d2d2/d2d2/d2d2")
  // back to the PTY, they would get broadcast to all connected clients, causing weird
  // escape sequences to appear in everyone's terminal.
  //
  // Therefore, this callback is intentionally a no-op.
  (void)vte;
  (void)u8;
  (void)len;
  (void)data;
}

// Initialize libtsm screen and VTE for snapshot support
static bool init_tsm_screen(struct server *server, uint16_t columns, uint16_t rows) {
  // Create screen
  int ret = tsm_screen_new(&server->tsm_screen, tsm_log_cb, server);
  if (ret < 0) {
    lwsl_err("Failed to create tsm_screen: %d\n", ret);
    return false;
  }

  // Set scrollback limit
  tsm_screen_set_max_sb(server->tsm_screen, server->scrollback_size);

  // Resize screen to match terminal
  ret = tsm_screen_resize(server->tsm_screen, columns, rows);
  if (ret < 0) {
    lwsl_err("Failed to resize tsm_screen: %d\n", ret);
    tsm_screen_unref(server->tsm_screen);
    server->tsm_screen = NULL;
    return false;
  }

  // Create VTE
  ret = tsm_vte_new(&server->tsm_vte, server->tsm_screen, tsm_write_cb, server, tsm_log_cb, server);
  if (ret < 0) {
    lwsl_err("Failed to create tsm_vte: %d\n", ret);
    tsm_screen_unref(server->tsm_screen);
    server->tsm_screen = NULL;
    return false;
  }

  lwsl_notice("Initialized libtsm screen: %dx%d, scrollback: %d lines\n",
              columns, rows, server->scrollback_size);

  return true;
}

// Cleanup libtsm screen and VTE
static void cleanup_tsm_screen(struct server *server) {
  if (server->tsm_vte != NULL) {
    tsm_vte_unref(server->tsm_vte);
    server->tsm_vte = NULL;
  }

  if (server->tsm_screen != NULL) {
    tsm_screen_unref(server->tsm_screen);
    server->tsm_screen = NULL;
  }

  lwsl_debug("Cleaned up libtsm screen\n");
}

// Context for tsm_screen_draw callback
struct snapshot_ctx {
  json_object *lines_array;
  char **line_bufs;          // Array of line buffers (one per row) with ANSI codes
  unsigned int *line_pos;    // Current position in each line (for padding)
  struct tsm_screen_attr *last_attr; // Track last attributes per line for SGR optimization
  unsigned int width;
  unsigned int height;
};

// Helper: Compare two attributes to see if SGR codes need to change
static bool attrs_equal(const struct tsm_screen_attr *a, const struct tsm_screen_attr *b) {
  if (a == NULL || b == NULL) return false;
  return a->fccode == b->fccode && a->bccode == b->bccode &&
         a->fr == b->fr && a->fg == b->fg && a->fb == b->fb &&
         a->br == b->br && a->bg == b->bg && a->bb == b->bb &&
         a->bold == b->bold && a->italic == b->italic &&
         a->underline == b->underline && a->inverse == b->inverse &&
         a->blink == b->blink;
}

// Helper: Append ANSI SGR codes to buffer based on attributes
static void append_sgr(char *buf, size_t *len, const struct tsm_screen_attr *attr,
                       const struct tsm_screen_attr *last) {
  // If attrs haven't changed, do nothing
  if (attrs_equal(attr, last)) return;

  const int fg_code = attr->fccode;
  const int bg_code = attr->bccode;
  const bool fg_is_default = (fg_code == TSM_COLOR_FOREGROUND);
  const bool bg_is_default = (bg_code == TSM_COLOR_BACKGROUND);

  // Reset to default first if switching attributes
  if (last != NULL) {
    buf[(*len)++] = '\x1b';
    buf[(*len)++] = '[';
    buf[(*len)++] = '0';
    buf[(*len)++] = 'm';
  }

  // Apply new attributes
  buf[(*len)++] = '\x1b';
  buf[(*len)++] = '[';
  bool first = true;

  if (attr->bold) {
    *len += snprintf(buf + *len, 16, "%s1", first ? "" : ";");
    first = false;
  }
  if (attr->italic) {
    *len += snprintf(buf + *len, 16, "%s3", first ? "" : ";");
    first = false;
  }
  if (attr->underline) {
    *len += snprintf(buf + *len, 16, "%s4", first ? "" : ";");
    first = false;
  }
  if (attr->blink) {
    *len += snprintf(buf + *len, 16, "%s5", first ? "" : ";");
    first = false;
  }
  if (attr->inverse) {
    *len += snprintf(buf + *len, 16, "%s7", first ? "" : ";");
    first = false;
  }

  // Foreground color (30-37 for standard, 90-97 for bright)
  if (fg_code >= 0 && fg_code < 16) {
    int fg = fg_code < 8 ? 30 + fg_code : 90 + (fg_code - 8);
    *len += snprintf(buf + *len, 16, "%s%d", first ? "" : ";", fg);
    first = false;
  } else if (fg_code >= 16 && fg_code < TSM_COLOR_NUM && !fg_is_default) {
    *len += snprintf(buf + *len, 16, "%s38;5;%d", first ? "" : ";", fg_code);
    first = false;
  } else if (fg_code < 0) {
    *len += snprintf(buf + *len, 32, "%s38;2;%u;%u;%u", first ? "" : ";",
                     (unsigned int)attr->fr, (unsigned int)attr->fg, (unsigned int)attr->fb);
    first = false;
  }

  // Background color (40-47 for standard, 100-107 for bright)
  if (bg_code >= 0 && bg_code < 16) {
    int bg = bg_code < 8 ? 40 + bg_code : 100 + (bg_code - 8);
    *len += snprintf(buf + *len, 16, "%s%d", first ? "" : ";", bg);
    first = false;
  } else if (bg_code >= 16 && bg_code < TSM_COLOR_NUM && !bg_is_default) {
    *len += snprintf(buf + *len, 16, "%s48;5;%d", first ? "" : ";", bg_code);
    first = false;
  } else if (bg_code < 0) {
    *len += snprintf(buf + *len, 32, "%s48;2;%u;%u;%u", first ? "" : ";",
                     (unsigned int)attr->br, (unsigned int)attr->bg, (unsigned int)attr->bb);
    first = false;
  }

  if (first) {
    // No attributes set, just reset
    buf[(*len)++] = '0';
  }

  buf[(*len)++] = 'm';
}

// Callback for tsm_screen_draw - accumulates characters with ANSI formatting
static int snapshot_draw_cb(struct tsm_screen *con, uint64_t id,
                            const uint32_t *ch, size_t len,
                            unsigned int width, unsigned int posx,
                            unsigned int posy, const struct tsm_screen_attr *attr,
                            tsm_age_t age, void *data) {
  struct snapshot_ctx *ctx = (struct snapshot_ctx *)data;

  if (posy >= ctx->height || posx >= ctx->width) return 0;

  // Ensure line buffer exists (with extra space for ANSI codes)
  if (ctx->line_bufs[posy] == NULL) {
    ctx->line_bufs[posy] = xmalloc(ctx->width * 64);  // Larger buffer for ANSI + UTF-8
    ctx->line_bufs[posy][0] = '\0';
    ctx->line_pos[posy] = 0;
  }

  char *line = ctx->line_bufs[posy];
  size_t line_len = strlen(line);

  // Pad with spaces if there's a gap before this cell position
  while (ctx->line_pos[posy] < posx && ctx->line_pos[posy] < ctx->width) {
    line[line_len++] = ' ';
    ctx->line_pos[posy]++;
  }

  // Emit SGR codes if attributes changed
  append_sgr(line, &line_len, attr, &ctx->last_attr[posy]);
  ctx->last_attr[posy] = *attr;

  if (len == 0) {
    // Blank cells still need explicit spaces so layout is preserved
    for (unsigned int i = 0; i < width && ctx->line_pos[posy] < ctx->width; i++) {
      line[line_len++] = ' ';
      ctx->line_pos[posy]++;
    }
    line[line_len] = '\0';
    return 0;
  }

  // Write the character(s) at this position
  for (size_t i = 0; i < len && ctx->line_pos[posy] < ctx->width; i++) {
    uint32_t codepoint = ch[i];
    if (codepoint == 0) codepoint = ' ';

    // Convert Unicode codepoint to UTF-8
    if (codepoint < 0x80) {
      line[line_len++] = (char)codepoint;
    } else if (codepoint < 0x800) {
      line[line_len++] = (char)(0xC0 | (codepoint >> 6));
      line[line_len++] = (char)(0x80 | (codepoint & 0x3F));
    } else if (codepoint < 0x10000) {
      line[line_len++] = (char)(0xE0 | (codepoint >> 12));
      line[line_len++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
      line[line_len++] = (char)(0x80 | (codepoint & 0x3F));
    } else {
      line[line_len++] = (char)(0xF0 | (codepoint >> 18));
      line[line_len++] = (char)(0x80 | ((codepoint >> 12) & 0x3F));
      line[line_len++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
      line[line_len++] = (char)(0x80 | (codepoint & 0x3F));
    }
  }

  line[line_len] = '\0';

  // Advance position by the reported width (handles double-width chars)
  ctx->line_pos[posy] += width;

  return 0;
}

// Serialize terminal snapshot to JSON
static char *serialize_snapshot(struct server *server, uint16_t cols, uint16_t rows) {
  if (server->tsm_screen == NULL) {
    return NULL;
  }

  // Get cursor position
  unsigned int cursor_x = tsm_screen_get_cursor_x(server->tsm_screen);
  unsigned int cursor_y = tsm_screen_get_cursor_y(server->tsm_screen);

  // Get terminal dimensions from screen
  unsigned int screen_width = tsm_screen_get_width(server->tsm_screen);
  unsigned int screen_height = tsm_screen_get_height(server->tsm_screen);

  // Use requested dimensions if provided, otherwise use screen dimensions
  if (cols == 0) cols = screen_width;
  if (rows == 0) rows = screen_height;

  lwsl_debug("Serializing snapshot: screen=%ux%u, requested=%ux%u, cursor=%u,%u\n",
             screen_width, screen_height, cols, rows, cursor_x, cursor_y);

  // Prepare snapshot context
  struct snapshot_ctx ctx;
  ctx.lines_array = json_object_new_array();
  ctx.width = cols;
  ctx.height = rows;
  ctx.line_bufs = calloc(rows, sizeof(char *));
  ctx.line_pos = calloc(rows, sizeof(unsigned int));
  ctx.last_attr = calloc(rows, sizeof(struct tsm_screen_attr));

  // Use tsm_screen_draw to extract screen content
  tsm_screen_draw(server->tsm_screen, snapshot_draw_cb, &ctx);

  // Build JSON array from line buffers (with ANSI codes included)
  for (unsigned int i = 0; i < rows; i++) {
    if (ctx.line_bufs[i] != NULL) {
      // Don't trim trailing spaces as they might be after ANSI codes
      // Add a reset at the end of each line to prevent bleed-over
      size_t len = strlen(ctx.line_bufs[i]);
      ctx.line_bufs[i] = realloc(ctx.line_bufs[i], len + 5);  // Room for \x1b[0m
      strcpy(ctx.line_bufs[i] + len, "\x1b[0m");

      json_object_array_add(ctx.lines_array, json_object_new_string(ctx.line_bufs[i]));
      free(ctx.line_bufs[i]);
    } else {
      json_object_array_add(ctx.lines_array, json_object_new_string(""));
    }
  }
  free(ctx.line_bufs);
  free(ctx.line_pos);
  free(ctx.last_attr);

  // Build snapshot JSON
  json_object *snapshot = json_object_new_object();
  json_object_object_add(snapshot, "lines", ctx.lines_array);
  json_object_object_add(snapshot, "cursor_x", json_object_new_int(cursor_x));
  json_object_object_add(snapshot, "cursor_y", json_object_new_int(cursor_y));
  json_object_object_add(snapshot, "width", json_object_new_int(cols));
  json_object_object_add(snapshot, "height", json_object_new_int(rows));
  if (server->tsm_screen != NULL) {
    unsigned int screen_flags = tsm_screen_get_flags(server->tsm_screen);
    json_object_object_add(snapshot, "screen_flags", json_object_new_int((int)screen_flags));
  }
  if (server->tsm_vte != NULL) {
    unsigned int vte_flags = tsm_vte_get_flags(server->tsm_vte);
    json_object_object_add(snapshot, "vte_flags", json_object_new_int((int)vte_flags));
  }

  // Convert to string
  const char *json_str = json_object_to_json_string(snapshot);
  char *result = strdup(json_str);

  // Clean up
  json_object_put(snapshot);

  lwsl_debug("Snapshot serialized: %zu bytes, %u lines\n", strlen(result), rows);

  return result;
}

static bool spawn_process(struct pss_tty *pss, uint16_t columns, uint16_t rows) {
  pty_process *process = process_init((void *)pty_ctx_init(pss), server->loop, build_args(pss), build_env(pss));
  if (server->cwd != NULL) process->cwd = strdup(server->cwd);
  if (columns > 0) process->columns = columns;
  if (rows > 0) process->rows = rows;
  if (pty_spawn(process, process_read_cb, process_exit_cb) != 0) {
    lwsl_err("pty_spawn: %d (%s)\n", errno, strerror(errno));
    process_free(process);
    return false;
  }
  lwsl_notice("started process, pid: %d\n", process->pid);
  pss->process = process;
  lws_callback_on_writable(pss->wsi);

  return true;
}

static void wsi_output(struct lws *wsi, pty_buf_t *buf) {
  if (buf == NULL) return;
  char *message = xmalloc(LWS_PRE + 1 + buf->len);
  char *ptr = message + LWS_PRE;

  *ptr = OUTPUT;
  memcpy(ptr + 1, buf->base, buf->len);
  size_t n = buf->len + 1;

  if (lws_write(wsi, (unsigned char *)ptr, n, LWS_WRITE_BINARY) < n) {
    lwsl_err("write OUTPUT to WS\n");
  }

  free(message);
}

static bool check_auth(struct lws *wsi, struct pss_tty *pss) {
  if (server->auth_header != NULL) {
    return lws_hdr_custom_copy(wsi, pss->user, sizeof(pss->user), server->auth_header, strlen(server->auth_header)) > 0;
  }

  if (server->credential != NULL) {
    char buf[256];
    size_t n = lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_AUTHORIZATION);
    return n >= 7 && strstr(buf, "Basic ") && !strcmp(buf + 6, server->credential);
  }

  return true;
}

int callback_tty(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
  struct pss_tty *pss = (struct pss_tty *)user;
  char buf[256];
  size_t n = 0;

  switch (reason) {
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
      if (server->once && server->client_count > 0) {
        lwsl_warn("refuse to serve WS client due to the --once option.\n");
        return 1;
      }
      if (server->max_clients > 0 && server->client_count == server->max_clients) {
        lwsl_warn("refuse to serve WS client due to the --max-clients option.\n");
        return 1;
      }
      if (!check_auth(wsi, pss)) return 1;

      n = lws_hdr_copy(wsi, pss->path, sizeof(pss->path), WSI_TOKEN_GET_URI);
#if defined(LWS_ROLE_H2)
      if (n <= 0) n = lws_hdr_copy(wsi, pss->path, sizeof(pss->path), WSI_TOKEN_HTTP_COLON_PATH);
#endif
      if (strncmp(pss->path, endpoints.ws, n) != 0) {
        lwsl_warn("refuse to serve WS client for illegal ws path: %s\n", pss->path);
        return 1;
      }

      if (server->check_origin && !check_host_origin(wsi)) {
        lwsl_warn(
            "refuse to serve WS client from different origin due to the "
            "--check-origin option.\n");
        return 1;
      }
      break;

    case LWS_CALLBACK_ESTABLISHED:
      pss->initialized = false;
      pss->authenticated = false;
      pss->wsi = wsi;
      pss->lws_close_status = LWS_CLOSE_STATUS_NOSTATUS;

      // NEW: Initialize shared mode fields
      pss->is_primary_client = false;
      pss->client_index = -1;
      pss->pending_session_resize = false;
      pss->resize_sent = false;
      pss->snapshot_pending = false;
      pss->snapshot_sent_at_ms = 0;
      pss->last_activity_at_ms = 0;
      pss->soft_dropped_bytes = 0;
      shared_client_buffers_init(pss);

      if (server->url_arg) {
        while (lws_hdr_copy_fragment(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_URI_ARGS, n++) > 0) {
          if (strncmp(buf, "arg=", 4) == 0) {
            pss->args = xrealloc(pss->args, (pss->argc + 1) * sizeof(char *));
            pss->args[pss->argc] = strdup(&buf[4]);
            pss->argc++;
          }
        }
      }

      server->client_count++;

      lws_get_peer_simple(lws_get_network_wsi(wsi), pss->address, sizeof(pss->address));
      lwsl_notice("WS   %s - %s, clients: %d\n", pss->path, pss->address, server->client_count);
      break;

    case LWS_CALLBACK_SERVER_WRITEABLE:
      if (!pss->initialized) {
        // Send initial messages (window title, preferences)
        if (pss->initial_cmd_index < sizeof(initial_cmds)) {
          if (send_initial_message(wsi, pss->initial_cmd_index) < 0) {
            lwsl_err("failed to send initial message, index: %d\n", pss->initial_cmd_index);
            lws_close_reason(wsi, LWS_CLOSE_STATUS_UNEXPECTED_CONDITION, NULL, 0);
            return -1;
          }
          pss->initial_cmd_index++;
          lws_callback_on_writable(wsi);
          break;
        }

        // Send SESSION_RESIZE before snapshot so the client adopts the session geometry
        if (server->shared_pty_mode && !pss->resize_sent) {
          bool sent = send_session_resize(server, pss, wsi);
          pss->resize_sent = sent || pss->resize_sent;
          pss->pending_session_resize = false;
          lws_callback_on_writable(wsi);
          break;  // Exit this callback, snapshot will be sent next time
        }

        // After initial messages and resize, send snapshot if in shared mode
        if (server->shared_pty_mode && server->tsm_screen != NULL &&
            pss->client_index >= 0 && !pss->snapshot_pending) {
          uint16_t snapshot_cols = server->session_columns;
          uint16_t snapshot_rows = server->session_rows;
          // Generate snapshot sized to the shared session geometry
          char *snapshot_json = serialize_snapshot(server, snapshot_cols, snapshot_rows);
          if (snapshot_json != NULL) {
            size_t json_len = strlen(snapshot_json);
            unsigned char *message = xmalloc(LWS_PRE + 1 + json_len);
            unsigned char *p = &message[LWS_PRE];

            // Send snapshot message: SNAPSHOT + JSON
            p[0] = SNAPSHOT;
            memcpy(p + 1, snapshot_json, json_len);

            int n = lws_write(wsi, p, 1 + json_len, LWS_WRITE_BINARY);
            free(message);
            free(snapshot_json);

            if (n < 0) {
              lwsl_err("failed to send snapshot\n");
              return -1;
            }

            // Mark snapshot as pending - block PTY output until acknowledged
            pss->snapshot_pending = true;
            if (server->loop != NULL) {
              pss->snapshot_sent_at_ms = uv_now(server->loop);
            } else {
              // Defensive: in production, loop should never be NULL in shared mode
              // In test environments without proper loop setup, skip timeout tracking
              lwsl_warn("server->loop is NULL when setting snapshot timestamp - timeout disabled for this client\n");
              pss->snapshot_sent_at_ms = UINT64_MAX;  // Never timeout
            }
            lwsl_notice("Sent snapshot to client %s (%d bytes), blocking PTY output\n", pss->address, (int)json_len);
          }
        }

        // Now mark as initialized
        pss->initialized = true;

        // Only resume in non-shared mode (pss->process is NULL in shared mode)
        if (!server->shared_pty_mode && pss->process != NULL) {
          pty_resume(pss->process);
        }

        // Queue another writable callback if there's PTY data waiting
        if (pss->pty_buf != NULL) {
          lws_callback_on_writable(wsi);
        }
        break;
      }

      if (pss->lws_close_status > LWS_CLOSE_STATUS_NOSTATUS) {
        lws_close_reason(wsi, pss->lws_close_status, NULL, 0);
        return 1;
      }

      // Handle any pending session resize for already-initialized clients
      if (server->shared_pty_mode && pss->pending_session_resize) {
        send_session_resize(server, pss, wsi);
        pss->pending_session_resize = false;
        // Queue another writable callback if there's PTY data waiting
        if (pss->pty_buf != NULL) {
          lws_callback_on_writable(wsi);
        }
        break;
      }

      if (pss->pty_buf != NULL) {
        // Block PTY output if snapshot is pending (race condition prevention)
        if (pss->snapshot_pending) {
          lwsl_debug("Blocking PTY output for client %s - snapshot pending\n", pss->address);
          // Don't write, don't free - will retry on next writable callback
          break;
        }

        wsi_output(wsi, pss->pty_buf);

        // Update activity timestamp on successful output
        if (server->shared_pty_mode && server->loop) {
          pss->last_activity_at_ms = uv_now(server->loop);
        }

        // Use reference counting in shared mode, direct free in non-shared mode
        if (server->shared_pty_mode) {
          shared_client_buffers_pop(pss);
          if (pss->pty_buf != NULL) {
            // More data queued for this client, keep draining
            lws_callback_on_writable(wsi);
          }
        } else {
          pty_buf_free(pss->pty_buf);
          pss->pty_buf = NULL;
        }

        // Resume PTY to continue reading
        if (!server->shared_pty_mode && pss->process != NULL) {
          pty_resume(pss->process);
        }
        // In shared mode, PTY is continuously resumed in shared_process_read_cb
      }
      break;

    case LWS_CALLBACK_RECEIVE:
      if (pss->buffer == NULL) {
        pss->buffer = xmalloc(len);
        pss->len = len;
        memcpy(pss->buffer, in, len);
      } else {
        pss->buffer = xrealloc(pss->buffer, pss->len + len);
        memcpy(pss->buffer + pss->len, in, len);
        pss->len += len;
      }

      const char command = pss->buffer[0];

      // check auth
      if (server->credential != NULL && !pss->authenticated && command != JSON_DATA) {
        lwsl_warn("WS client not authenticated\n");
        return 1;
      }

      // check if there are more fragmented messages
      if (lws_remaining_packet_payload(wsi) > 0 || !lws_is_final_fragment(wsi)) {
        return 0;
      }

      switch (command) {
        case INPUT:
          lwsl_debug("Received INPUT command, writable=%d, shared_mode=%d, initialized=%d\n",
                     server->writable, server->shared_pty_mode, pss->initialized);
          if (!server->writable) break;

          // NEW: Shared mode - write to shared process
          if (server->shared_pty_mode) {
            if (server->shared_process != NULL) {
              lwsl_debug("Writing %zu bytes to shared process\n", pss->len - 1);
              int err = pty_write(server->shared_process, pty_buf_init(pss->buffer + 1, pss->len - 1));
              if (err) {
                lwsl_err("uv_write to shared process: %s (%s)\n", uv_err_name(err), uv_strerror(err));
                return -1;
              }
              pss->last_activity_at_ms = server->loop ? uv_now(server->loop) : 0;
            } else {
              lwsl_warn("No shared process available for input\n");
            }
          } else {
            // OLD: Per-client mode
            int err = pty_write(pss->process, pty_buf_init(pss->buffer + 1, pss->len - 1));
            if (err) {
              lwsl_err("uv_write: %s (%s)\n", uv_err_name(err), uv_strerror(err));
              return -1;
            }
          }
          break;
        case RESIZE_TERMINAL:
          if (!server->shared_pty_mode && pss->process == NULL) break;

          if (server->shared_pty_mode) {
            uint16_t req_cols = 0, req_rows = 0;
            json_object_put(parse_window_size(pss->buffer + 1, pss->len - 1, &req_cols, &req_rows));
            lwsl_notice("Client %s attempted resize to %ux%u; enforcing session geometry %ux%u\n",
                        pss->address, req_cols, req_rows,
                        server->session_columns, server->session_rows);
            pss->pending_session_resize = true;
            lws_callback_on_writable(wsi);
          } else {
            json_object_put(
                parse_window_size(pss->buffer + 1, pss->len - 1, &pss->process->columns, &pss->process->rows));
            pty_resize(pss->process);
          }
          break;
        case PAUSE:
          // Only allow pause in non-shared mode (would affect all clients in shared mode)
          if (!server->shared_pty_mode && pss->process != NULL) {
            pty_pause(pss->process);
          }
          break;
        case RESUME:
          // Only allow resume in non-shared mode (would affect all clients in shared mode)
          if (!server->shared_pty_mode && pss->process != NULL) {
            pty_resume(pss->process);
          }
          break;
        case SNAPSHOT_ACK:
          // Client has finished applying snapshot, unblock PTY output
          if (server->shared_pty_mode && pss->snapshot_pending) {
            pss->snapshot_pending = false;
            pss->last_activity_at_ms = server->loop ? uv_now(server->loop) : 0;
            lwsl_notice("Snapshot acknowledged by client %s, unblocking PTY output\n", pss->address);
            // Trigger writable callback to flush any pending PTY output
            if (pss->pty_buf != NULL) {
              lws_callback_on_writable(wsi);
            }
          }
          break;
        case JSON_DATA:
          if (pss->process != NULL && !server->shared_pty_mode) break;
          if (pss->initialized && server->shared_pty_mode) break;  // Already connected to shared process

          uint16_t columns = 0;
          uint16_t rows = 0;
          json_object *obj = parse_window_size(pss->buffer, pss->len, &columns, &rows);
          if (server->credential != NULL) {
            struct json_object *o = NULL;
            if (json_object_object_get_ex(obj, "AuthToken", &o)) {
              const char *token = json_object_get_string(o);
              if (token != NULL && !strcmp(token, server->credential))
                pss->authenticated = true;
              else
                lwsl_warn("WS authentication failed with token: %s\n", token);
            }
            if (!pss->authenticated) {
              json_object_put(obj);
              lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION, NULL, 0);
              return -1;
            }
          }
          json_object_put(obj);

      // NEW: Shared PTY mode
      if (server->shared_pty_mode) {
        lwsl_notice("Client %s reported %ux%u; locking session to %ux%u\n",
                    pss->address, columns, rows,
                    server->session_columns, server->session_rows);

        // Create shared process if needed (first client)
        if (server->shared_process == NULL) {
          if (!create_shared_process(server, pss)) {
            lwsl_err("Failed to create shared process\n");
            return 1;
          }
          pss->is_primary_client = true;
          lwsl_notice("Client %s is primary\n", pss->address);
        } else {
          pss->is_primary_client = false;
          lwsl_notice("Client %s connected to existing shared process\n", pss->address);
        }

        // Add this client to the tracking list
        add_client_to_list(server, wsi);

        // Ensure we send the locked geometry on the next writable callback
        pss->pending_session_resize = true;
        pss->resize_sent = false;

        // Trigger initial message sending (don't set initialized yet)
        lws_callback_on_writable(wsi);
      } else {
        // OLD: Per-client PTY mode
        if (!spawn_process(pss, columns, rows)) return 1;
      }
      break;
        default:
          lwsl_warn("ignored unknown message type: %c\n", command);
          break;
      }

      if (pss->buffer != NULL) {
        free(pss->buffer);
        pss->buffer = NULL;
      }
      break;

    case LWS_CALLBACK_CLOSED:
      if (pss->wsi == NULL) break;

      server->client_count--;
      lwsl_notice("WS closed from %s, clients: %d\n", pss->address, server->client_count);

      // NEW: Handle shared mode disconnection
      if (server->shared_pty_mode && pss->client_index >= 0) {
        int remaining = server->active_client_count > 0 ? server->active_client_count - 1 : 0;
        lwsl_notice("Shared mode: removing client (remaining: %d)\n", remaining);
        remove_client_from_list(server, wsi);
      }

      // Clean up client resources
      if (pss->buffer != NULL) free(pss->buffer);
      if (server->shared_pty_mode) {
        bool had_pending_queue = pss->pending_pty_head != NULL;
        if (had_pending_queue) {
          shared_client_buffers_clear(pss);
        } else if (pss->pty_buf != NULL) {
          // Defensive: release any stray pointer not tracked in the queue
          pty_buf_release(pss->pty_buf);
          pss->pty_buf = NULL;
          pss->pending_pty_bytes = 0;
        }

        // In shared mode, PTY is continuously resumed in shared_process_read_cb
        // No need to resume here
      } else if (pss->pty_buf != NULL) {
        pty_buf_free(pss->pty_buf);
        pss->pty_buf = NULL;
      }
      for (int i = 0; i < pss->argc; i++) {
        free(pss->args[i]);
      }

      // OLD: Per-client mode - kill the dedicated process
      if (!server->shared_pty_mode && pss->process != NULL) {
        ((pty_ctx_t *)pss->process->ctx)->ws_closed = true;
        if (process_running(pss->process)) {
          pty_pause(pss->process);
          lwsl_notice("killing process, pid: %d\n", pss->process->pid);
          pty_kill(pss->process, server->sig_code);
        }
      }

      // NOTE: In shared mode, process exit is handled in remove_client_from_list()
      // or shared_process_exit_cb()

      if ((server->once || server->exit_no_conn) && server->client_count == 0 && !server->shared_pty_mode) {
        lwsl_notice("exiting due to the --once/--exit-no-conn option.\n");
        force_exit = true;
        lws_cancel_service(context);
        exit(0);
      }
      break;

    default:
      break;
  }

  return 0;
}

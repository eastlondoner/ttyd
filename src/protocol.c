#include <errno.h>
#include <json.h>
#include <libwebsockets.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pty.h"
#include "server.h"
#include "utils.h"

// Buffer overflow protection - max buffer size per client
#define MAX_CLIENT_BUFFER_SIZE (1024 * 1024)  // 1MB per client

// initial message list
static char initial_cmds[] = {SET_WINDOW_TITLE, SET_PREFERENCES};

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
static char **build_args_from_server(struct server *server);
static char **build_env_from_server(struct server *server);

// Create shared PTY process (called for first client only)
static bool create_shared_process(struct server *server, struct pss_tty *first_pss,
                                   uint16_t columns, uint16_t rows) {
  if (server->shared_process != NULL) {
    lwsl_warn("Shared process already exists\n");
    return true;  // Already exists
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

  // Spawn the process with shared callbacks
  if (pty_spawn(process, shared_process_read_cb, shared_process_exit_cb) != 0) {
    lwsl_err("pty_spawn failed: %d (%s)\n", errno, strerror(errno));
    process_free(process);
    free(ctx);
    return false;
  }

  server->shared_process = process;
  server->primary_columns = columns;
  server->primary_rows = rows;

  lwsl_notice("Shared PTY process created (PID: %d, size: %dx%d)\n",
              process->pid, columns, rows);

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

  // Check for buffer overflow protection
  if (buf_len > MAX_CLIENT_BUFFER_SIZE) {
    lwsl_warn("PTY output buffer overflow (%zu bytes), dropping data\n", buf_len);
    pty_buf_free(buf);
    return;
  }

  // Broadcast to ALL connected clients using reference counting
  for (int i = 0; i < server->client_wsi_capacity; i++) {
    if (server->client_wsi_list[i] != NULL) {
      struct pss_tty *pss = get_pss_from_wsi(server->client_wsi_list[i]);

      if (pss->initialized) {
        // Check if this client already has a pending buffer that's too large
        if (pss->pty_buf != NULL && pss->pty_buf->len > MAX_CLIENT_BUFFER_SIZE / 2) {
          lwsl_warn("Client %d buffer overflow, disconnecting\n", pss->client_index);
          lws_close_reason(server->client_wsi_list[i], LWS_CLOSE_STATUS_POLICY_VIOLATION,
                           (unsigned char *)"Buffer overflow", 15);
          continue;  // Skip this client
        }

        // Retain buffer for this client (increments ref_count)
        pss->pty_buf = pty_buf_retain(buf);
        lws_callback_on_writable(server->client_wsi_list[i]);
        delivered++;
      }
    }
  }

  // Release the original reference (buffer will be freed when all clients finish)
  pty_buf_release(buf);
  lwsl_debug("Broadcast %zu bytes to %d clients\n", buf_len, delivered);

  if (server->active_client_count > 0) {
    pty_resume(process);
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
      pss->requested_columns = 0;
      pss->requested_rows = 0;

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
        if (pss->initial_cmd_index == sizeof(initial_cmds)) {
          pss->initialized = true;
          // Only resume in non-shared mode (pss->process is NULL in shared mode)
          if (!server->shared_pty_mode && pss->process != NULL) {
            pty_resume(pss->process);
          }
          break;
        }
        if (send_initial_message(wsi, pss->initial_cmd_index) < 0) {
          lwsl_err("failed to send initial message, index: %d\n", pss->initial_cmd_index);
          lws_close_reason(wsi, LWS_CLOSE_STATUS_UNEXPECTED_CONDITION, NULL, 0);
          return -1;
        }
        pss->initial_cmd_index++;
        lws_callback_on_writable(wsi);
        break;
      }

      if (pss->lws_close_status > LWS_CLOSE_STATUS_NOSTATUS) {
        lws_close_reason(wsi, pss->lws_close_status, NULL, 0);
        return 1;
      }

      if (pss->pty_buf != NULL) {
        wsi_output(wsi, pss->pty_buf);

        // Use reference counting in shared mode, direct free in non-shared mode
        if (server->shared_pty_mode) {
          pty_buf_release(pss->pty_buf);
        } else {
          pty_buf_free(pss->pty_buf);
        }

        pss->pty_buf = NULL;

        // Resume PTY to continue reading
        if (!server->shared_pty_mode && pss->process != NULL) {
          pty_resume(pss->process);
        } else if (server->shared_pty_mode && server->shared_process != NULL) {
          // In shared mode, resume the shared PTY after sending data
          pty_resume(server->shared_process);
        }
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

          // NEW: Shared mode - max-dimension strategy
          if (server->shared_pty_mode && server->shared_process != NULL) {
            uint16_t req_cols = 0, req_rows = 0;
            json_object_put(parse_window_size(pss->buffer + 1, pss->len - 1, &req_cols, &req_rows));

            // Store this client's requested dimensions
            pss->requested_columns = req_cols;
            pss->requested_rows = req_rows;

            // Calculate max dimensions across all clients
            uint16_t max_cols = 0, max_rows = 0;
            for (int i = 0; i < server->client_wsi_capacity; i++) {
              if (server->client_wsi_list[i] != NULL) {
                struct pss_tty *p = get_pss_from_wsi(server->client_wsi_list[i]);
                if (p->requested_columns > max_cols) max_cols = p->requested_columns;
                if (p->requested_rows > max_rows) max_rows = p->requested_rows;
              }
            }

            // Apply maximum dimensions
            if (max_cols > 0 && max_rows > 0) {
              pty_resize_set(server->shared_process, max_cols, max_rows);
              server->primary_columns = max_cols;
              server->primary_rows = max_rows;
              lwsl_notice("Resized shared PTY to max dimensions: %dx%d\n", max_cols, max_rows);
            }
          } else {
            // OLD: Per-client mode
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
            // Store requested dimensions for max-dimension strategy
            pss->requested_columns = columns;
            pss->requested_rows = rows;

            // Create shared process if needed (first client)
            if (server->shared_process == NULL) {
              if (!create_shared_process(server, pss, columns, rows)) {
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
      if (pss->pty_buf != NULL) {
        if (server->shared_pty_mode) {
          pty_buf_release(pss->pty_buf);
        } else {
          pty_buf_free(pss->pty_buf);
        }
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

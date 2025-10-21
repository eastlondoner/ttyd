#include <libwebsockets.h>
#include <stdbool.h>
#include <uv.h>

#include "pty.h"

// libtsm - Terminal State Machine for snapshots
#include <libtsm.h>

// client message
#define INPUT '0'
#define RESIZE_TERMINAL '1'
#define PAUSE '2'
#define RESUME '3'
#define SNAPSHOT_ACK '4'
#define JSON_DATA '{'

// server message
#define OUTPUT '0'
#define SET_WINDOW_TITLE '1'
#define SET_PREFERENCES '2'
#define SNAPSHOT '3'
#define SESSION_RESIZE '4'

// url paths
struct endpoints {
  char *ws;
  char *index;
  char *token;
  char *parent;
};

extern volatile bool force_exit;
extern struct lws_context *context;
extern struct server *server;
extern struct endpoints endpoints;

struct pss_http {
  char path[128];
  char *buffer;
  char *ptr;
  size_t len;
};

struct pending_shared_buffer;

struct pss_tty {
  bool initialized;
  int initial_cmd_index;
  bool authenticated;
  char user[30];
  char address[50];
  char path[128];
  char **args;
  int argc;

  struct lws *wsi;
  char *buffer;
  size_t len;

  pty_process *process;        // Used when shared_pty_mode = false
  pty_buf_t *pty_buf;

  int lws_close_status;

  // NEW: Client tracking for shared mode
  struct pending_shared_buffer *pending_pty_head;  // Queue of pending PTY buffers (shared mode)
  struct pending_shared_buffer *pending_pty_tail;
  size_t pending_pty_bytes;
  bool is_primary_client;      // Is this the first/controlling client?
  int client_index;            // Index in server->client_wsi_list (-1 if not in list)
  bool pending_session_resize; // Whether we owe the client a session resize frame
  bool resize_sent;                // Track if initial resize was sent during handshake
  bool snapshot_pending;           // Snapshot sent but not yet acknowledged
};

typedef struct {
  struct pss_tty *pss;     // Used in non-shared mode
  struct server *server;   // Used in shared mode (points to server for broadcast)
  bool ws_closed;
  bool shared_mode;        // Indicates which pointer to use
} pty_ctx_t;

struct server {
  int client_count;        // client count
  char *prefs_json;        // client preferences
  char *credential;        // encoded basic auth credential
  char *auth_header;       // header name used for auth proxy
  char *index;             // custom index.html
  char *command;           // full command line
  char **argv;             // command with arguments
  int argc;                // command + arguments count
  char *cwd;               // working directory
  int sig_code;            // close signal
  char sig_name[20];       // human readable signal string
  bool url_arg;            // allow client to send cli arguments in URL
  bool writable;           // whether clients to write to the TTY
  bool check_origin;       // whether allow websocket connection from different origin
  int max_clients;         // maximum clients to support
  bool once;               // whether accept only one client and exit on disconnection
  bool exit_no_conn;       // whether exit on all clients disconnection
  char socket_path[255];   // UNIX domain socket path
  char terminal_type[30];  // terminal type to report

  uv_loop_t *loop;         // the libuv event loop

  // NEW: Shared PTY support
  bool shared_pty_mode;           // Enable shared PTY mode
  pty_process *shared_process;    // The one shared PTY process
  struct lws **client_wsi_list;   // Dynamic array of active WebSocket connections
  int client_wsi_capacity;        // Capacity of the array
  int active_client_count;        // Number of active clients in shared mode
  uint16_t session_columns;       // Session-wide terminal width (fixed)
  uint16_t session_rows;
  char *first_client_user;        // Username of first authenticated client (for TTYD_USER)

  // NEW: libtsm snapshot support (required in shared_pty_mode)
  struct tsm_screen *tsm_screen;  // Terminal screen state machine
  struct tsm_vte *tsm_vte;        // VT100 emulator
  int scrollback_size;            // Scrollback buffer size (default: 2000)
};

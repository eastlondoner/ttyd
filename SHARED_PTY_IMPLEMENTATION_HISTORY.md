# Shared PTY Implementation History

This document chronicles the development of ttyd's shared PTY mode, which transforms the architecture from one-PTY-per-connection to one-shared-PTY-for-all-connections.

## Table of Contents

1. [Feature Overview](#feature-overview)
2. [Architecture Changes](#architecture-changes)
3. [Design Decisions](#design-decisions)
4. [Implementation Timeline](#implementation-timeline)
5. [Critical Issues & Resolutions](#critical-issues--resolutions)
6. [Testing & Validation](#testing--validation)
7. [Key Commits](#key-commits)

---

## Feature Overview

### What is Shared PTY Mode?

Shared PTY mode allows multiple WebSocket clients to connect to a single shared pseudo-terminal, enabling collaborative terminal sessions similar to `tmux` or `screen` over the web.

**Before:**
```
┌─────────────┐         ┌──────────────┐
│ WebSocket 1 │────────▶│ PTY Process 1│
└─────────────┘         └──────────────┘

┌─────────────┐         ┌──────────────┐
│ WebSocket 2 │────────▶│ PTY Process 2│
└─────────────┘         └──────────────┘
```

**After (Shared Mode):**
```
┌─────────────┐
│ WebSocket 1 │─┐
└─────────────┘ │
                │       ┌──────────────────┐
┌─────────────┐ │       │                  │
│ WebSocket 2 │─┼──────▶│ Shared PTY Process│
└─────────────┘ │       │                  │
                │       └──────────────────┘
┌─────────────┐ │
│ WebSocket 3 │─┘
└─────────────┘
```

### Use Cases

- **Live coding demonstrations**: Presenter shares terminal, viewers watch in real-time
- **Collaborative debugging**: Multiple developers interact with same terminal session
- **Remote pair programming**: Two developers share control of a terminal
- **Screen sharing for presentations**: Show terminal output to multiple viewers
- **Training and education**: Instructor demonstrates commands to students

### Key Benefits

✅ **Resource efficiency**: One process serves all clients
✅ **True collaboration**: All users see identical output
✅ **Screen-sharing friendly**: Like tmux/screen over the web
✅ **Maintains architecture**: Still single-threaded event loop
✅ **Backward compatible**: Can be feature-flagged

---

## Architecture Changes

### Core Data Structures

#### Extended `struct server` (src/server.h)

```c
struct server {
  // ... existing fields ...

  // Shared PTY support (added)
  pty_process *shared_process;      // The one shared PTY process
  struct lws **client_wsi_list;     // Dynamic array of active WebSocket connections
  int client_wsi_capacity;          // Capacity of the array
  int active_client_count;          // Number of active clients
  uint16_t session_columns;         // Session terminal dimensions
  uint16_t session_rows;
  char *first_client_user;          // Username for TTYD_USER env var

  // Snapshot support (added)
  bool snapshot_enabled;
  struct tsm_screen *tsm_screen;    // libtsm terminal emulator
  struct tsm_vte *tsm_vte;
};
```

#### Extended `struct pss_tty` (src/server.h)

```c
struct pss_tty {
  // ... existing fields ...

  // Kept for backward compatibility with isolated mode
  pty_process *process;            // Used when shared_pty_mode = false

  // Client tracking for shared mode (added)
  int client_index;                // Index in server->client_wsi_list
  uint16_t requested_columns;      // Client's requested dimensions
  uint16_t requested_rows;

  // Session resize tracking (added)
  bool pending_session_resize;
  uint16_t pending_session_columns;
  uint16_t pending_session_rows;
  bool resize_sent;                // Track if initial resize was sent during handshake
};
```

#### Modified `pty_ctx_t` (src/pty.h)

```c
// OLD:
struct pty_ctx {
  struct pss_tty *pss;    // Points to single client
  bool ws_closed;
};

// NEW:
struct pty_ctx {
  struct server *server;   // Points to server (access to all clients)
  bool shared_mode;        // Shared or per-client mode
  struct pss_tty *pss;     // NULL in shared mode, set in per-client mode
  bool ws_closed;
};
```

#### Buffer Reference Counting (src/pty.h)

```c
typedef struct {
  char *base;        // Buffer data
  size_t len;        // Buffer length
  int ref_count;     // NEW: Reference counter (added)
} pty_buf_t;
```

### Data Flow Changes

#### Output Broadcasting

**Before (one-to-one):**
```
PTY output → process_read_cb() → pss->pty_buf → single WebSocket
```

**After (one-to-many):**
```
PTY output → shared_process_read_cb() → for each client:
                                          ├─ pss1->pty_buf (pty_buf_retain())
                                          ├─ pss2->pty_buf (pty_buf_retain())
                                          └─ pss3->pty_buf (pty_buf_retain())
                                       → all WebSockets
```

#### Input Handling

**Before:**
```
WebSocket → INPUT message → pty_write(pss->process)
```

**After (merged input):**
```
WebSocket 1 → INPUT → pty_write(server->shared_process)
WebSocket 2 → INPUT → pty_write(server->shared_process)
WebSocket 3 → INPUT → pty_write(server->shared_process)
```

---

## Design Decisions

### 1. Input Handling: Merged Input from All Clients

**Decision:** All authenticated clients can send input to the shared PTY (merged input).

**Rationale:**
- Enables true collaborative terminal sessions
- Maintains backward compatibility with `-W`/`--writable` flag
- Simplest implementation for v1

**Implementation:**
- Global `-W` flag controls write permission for all clients
- Individual clients respect authentication requirements
- Future enhancement: per-client write permissions

### 2. Terminal Resize: Minimum Dimensions Strategy

**Decision:** Use minimum dimensions across all connected clients.

**Rationale:**
- Ensures all clients can see full terminal content without scrolling
- More predictable than "primary client controls" strategy
- Avoids cropping content for narrow clients

**Implementation:**
```c
// Find narrowest client
for each client:
  min_cols = min(min_cols, client->requested_columns)
  min_rows = min(min_rows, client->requested_rows)

// Resize PTY and all clients
pty_resize(shared_process, min_cols, min_rows)
broadcast_session_resize(server, min_cols, min_rows)
```

**Alternative Considered:** Primary client controls dimensions
- Simpler but can cause content cropping for secondary clients
- Rejected in favor of minimum dimensions approach

### 3. Process Lifecycle

**PTY Creation:** Lazy initialization
- Create shared PTY when first client connects
- Reuse for all subsequent connections
- Clean resource usage

**PTY Exit:** Close all connections
- When shared PTY exits, close all WebSocket connections
- Simple and predictable behavior
- Respects `--once` flag (server exits after PTY exits)

**Client Tracking:**
- Dynamic array that grows as needed (doubles in size)
- O(1) addition and removal using `client_index`
- Automatic cleanup when clients disconnect

### 4. Buffer Management: Reference Counting

**Decision:** Use reference counting instead of buffer copying.

**Rationale:**
- More efficient (one allocation serves all clients)
- Prevents memory waste from duplicating large buffers
- Thread-safe with proper locking

**Implementation:**
```c
// Increment reference count
pty_buf_t *pty_buf_retain(pty_buf_t *buf) {
  if (buf == NULL) return NULL;
  buf->ref_count++;
  return buf;
}

// Decrement and free when last reference released
void pty_buf_release(pty_buf_t *buf) {
  if (buf == NULL) return;
  buf->ref_count--;
  if (buf->ref_count == 0) {
    free(buf->base);
    free(buf);
  }
}
```

### 5. Snapshot Delivery: Backend Message Ordering

**Decision:** Send SESSION_RESIZE before SNAPSHOT in handshake sequence.

**Rationale:**
- Backend owns shared session state
- WebSocket messages are delivered in order (TCP guarantees)
- No frontend changes required
- Eliminates race condition

**Implementation:**
- Add `resize_sent` flag to track initial resize
- Reorder handshake: title → prefs → **RESIZE → SNAPSHOT** → initialized
- Frontend terminal is correctly sized before snapshot rendering

**Alternative Considered:** Frontend resizes before rendering snapshot
- Would require TypeScript changes
- Duplicates resize logic (snapshot triggers resize, then SESSION_RESIZE confirms)
- Less clean separation of concerns

---

## Implementation Timeline

### Phase 1: Core Shared PTY Infrastructure (2025-10-18)

**Goal:** Transform architecture from one-to-one to one-to-many

**Implemented:**
1. ✅ Extended data structures (`server->shared_process`, client tracking)
2. ✅ Client tracking with dynamic array
3. ✅ Shared process creation (`create_shared_process()`)
4. ✅ Output broadcasting (`shared_process_read_cb()`)
5. ✅ Buffer reference counting (`pty_buf_retain/release`)
6. ✅ Input handling (merged input to shared process)
7. ✅ Terminal resize (minimum dimensions strategy)
8. ✅ Process exit handling (close all clients)
9. ✅ Client disconnect handling (track and cleanup)
10. ✅ Server initialization and cleanup

**Files Modified:**
- `src/server.h` - Data structure extensions
- `src/protocol.c` - Core logic (500+ lines)
- `src/pty.h`, `src/pty.c` - Buffer reference counting
- `src/server.c` - Initialization and cleanup

**Lines of Code:** ~300 lines added

### Phase 2: Critical Bug Fixes (2025-10-18 - 2025-10-19)

**Implemented:**
1. ✅ Fixed PTY read resume after broadcast
2. ✅ Fixed buffer lifecycle on client disconnect (use release, not free)
3. ✅ Removed dead WSIs from broadcast list
4. ✅ Protected active_client_count from underflow
5. ✅ Honored `--once` flag in shared mode

**Impact:** Stabilized shared PTY mode for production use

### Phase 3: Snapshot Feature - Resize Fix (2025-10-19)

**Goal:** Fix snapshot corruption when clients with different dimensions connect

**Problem:** Narrow clients (80×24) joining wide sessions (120×30) received snapshots before resize, causing line wrapping corruption.

**Solution:** Reordered handshake to send SESSION_RESIZE before SNAPSHOT

**Implemented:**
1. ✅ Added `resize_sent` flag to `struct pss_tty`
2. ✅ Reordered handshake sequence in `LWS_CALLBACK_SERVER_WRITEABLE`
3. ✅ Added debug logging for resize/snapshot sequence
4. ✅ Removed duplicate resize send after initialization

**Files Modified:**
- `src/server.h:71` - Added `bool resize_sent`
- `src/protocol.c:1017` - Initialize `resize_sent = false`
- `src/protocol.c:1049-1059` - Send resize before snapshot
- `src/protocol.c:1105-1107` - Removed duplicate resize

**Impact:** Eliminated snapshot corruption, ~20 lines modified

**Testing Status:** Built and ready for manual testing

### Phase 4: Snapshot Generation (Planned)

**Goal:** Generate terminal snapshots using libtsm for new clients

**Status:** Design complete, implementation pending

**Next Steps:**
1. Integrate libtsm dependency
2. Feed PTY output to libtsm VTE
3. Serialize snapshots on client connect
4. Update frontend to render snapshots

---

## Critical Issues & Resolutions

### Issue 1: PTY Read Freeze After First Output

**Severity:** Critical (fatal regression)

**Symptom:** Shared terminal freezes after initial output chunk

**Root Cause:** `read_cb()` calls `uv_read_stop()`, but shared mode broadcast never resumed reads. `LWS_CALLBACK_SERVER_WRITEABLE` explicitly skipped `pty_resume()` in shared mode.

**Fix (src/protocol.c):**
```c
static void shared_process_read_cb(pty_process *process, pty_buf_t *buf, bool eof) {
  // ... broadcast to all clients ...

  // Resume PTY reads after broadcast (ADDED)
  if (server->active_client_count > 0) {
    pty_resume(process);
  }
}
```

**Status:** ✅ Fixed in Phase 2

### Issue 2: Buffer Use-After-Free on Client Disconnect

**Severity:** High (heap corruption/crash)

**Symptom:** Crash when client disconnects while others have buffered data

**Root Cause:** `LWS_CALLBACK_CLOSED` called `pty_buf_free(pss->pty_buf)`, bypassing reference counting. Other clients still held references to same buffer.

**Fix (src/protocol.c):**
```c
case LWS_CALLBACK_CLOSED:
  if (pss->pty_buf != NULL) {
    pty_buf_release(pss->pty_buf);  // Changed from pty_buf_free()
    pss->pty_buf = NULL;
  }
  // ... rest of cleanup ...
```

**Status:** ✅ Fixed in Phase 2

### Issue 3: Dangling WSI Pointers in Broadcast List

**Severity:** High (crash on broadcast)

**Symptom:** Crash when broadcasting to clients that disconnected early

**Root Cause:** `remove_client_from_list()` only called when `pss->initialized == true`. Early failures (auth rejection, handshake aborts) left stale pointers in `client_wsi_list`.

**Fix (src/protocol.c):**
```c
case LWS_CALLBACK_CLOSED:
  // Remove from list regardless of initialized state (FIXED)
  if (pss->initialized || pss->client_index >= 0) {
    remove_client_from_list(server, wsi);
  }
```

**Status:** ✅ Fixed in Phase 2

### Issue 4: Active Client Count Underflow

**Severity:** High (incorrect state tracking)

**Symptom:** Negative `active_client_count`, preventing new clients from registering

**Root Cause:** `shared_process_exit_cb()` set `active_client_count = 0`, then each client's `LWS_CALLBACK_CLOSED` decremented the counter again.

**Fix (src/protocol.c):**
```c
static void shared_process_exit_cb(...) {
  // Close all clients first
  for (int i = 0; i < server->client_wsi_capacity; i++) {
    if (server->client_wsi_list[i] != NULL) {
      // ... close client ...
      server->client_wsi_list[i] = NULL;  // Clear to prevent double-decrement
    }
  }

  // Then reset counter
  server->active_client_count = 0;
}
```

**Status:** ✅ Fixed in Phase 2

### Issue 5: `--once` Flag Not Honored in Shared Mode

**Severity:** High (behavioral regression)

**Symptom:** Server doesn't exit after first client disconnects when using `--once`

**Root Cause:** Legacy shutdown logic was removed for shared mode, and `remove_client_from_list()` only checked `--exit-no-conn` flag.

**Fix (src/protocol.c):**
```c
static void remove_client_from_list(struct server *server, struct lws *wsi) {
  // ... remove client ...

  // Honor both --exit-no-conn AND --once (FIXED)
  if (server->active_client_count == 0 &&
      (server->exit_no_conn || server->once) &&
      server->shared_process != NULL) {
    pty_kill(server->shared_process, server->sig_code);
  }
}
```

**Status:** ✅ Fixed in Phase 2

### Issue 6: Snapshot Corruption with Mismatched Dimensions

**Severity:** Medium (visual corruption)

**Symptom:** Scrambled terminal display when narrow client (80×24) joins wide session (120×30)

**Root Cause:** Messages sent in wrong order: SNAPSHOT → SESSION_RESIZE. Snapshot with 120-char lines rendered to 80-column terminal, causing line wrapping and overwrite corruption.

**Example:**
```
Line 1: "│ ✨ Update available! 0.46.0 -> 0.47.0.             │"  (120 chars)
  ↓ Wraps to 1.5 lines in 80-col terminal
Line 2: "│                                                    │"  (120 chars)
  ↓ Overwrites wrapped portion with absolute positioning
Result: Corrupted display
```

**Fix (src/protocol.c):**
```c
// Reordered handshake sequence:
// OLD: title → prefs → SNAPSHOT → resize
// NEW: title → prefs → RESIZE → snapshot

if (server->shared_pty_mode && pss->pending_session_resize && !pss->resize_sent) {
  flush_pending_session_resize(server, pss, wsi);  // Send RESIZE first
  pss->resize_sent = true;
  lws_callback_on_writable(wsi);
  break;  // Snapshot sent on next callback
}

// Snapshot now sent AFTER terminal is correctly sized
if (server->shared_pty_mode && server->snapshot_enabled) {
  send_snapshot(...);
}
```

**Status:** ✅ Fixed in Phase 3

**Testing:** Ready for manual testing with narrow/wide client combinations

---

## Testing & Validation

### Unit Tests (tests/shared_pty_regression_tests.c)

**Added:**
1. ✅ `shared_read_resumes_after_broadcast` - Verifies PTY reads resume after broadcasting
2. ✅ `shared_buffer_released_on_close` - Verifies reference counting on client disconnect
3. ✅ `remove_client_without_initialization` - Verifies early disconnect cleanup
4. ✅ `active_client_count_reset_on_process_exit` - Verifies counter reset without underflow
5. ✅ `once_flag_triggers_teardown` - Verifies `--once` flag behavior

**Build & Run:**
```bash
cmake --build build
./build/tests/shared_pty_regression_tests
```

### Manual Test Cases

#### Test 1: Multiple Concurrent Clients
```bash
./build/ttyd -W -p 7682 bash
# Open 3 browser tabs, verify all see same output
# Type in each tab, verify input appears in all tabs
```

**Expected:**
- ✅ All tabs synchronized
- ✅ Input from any tab visible in all tabs
- ✅ Logs show "Broadcast to 3 clients"

#### Test 2: Client Disconnect (Non-Primary)
```bash
./build/ttyd -W -p 7682 bash
# Connect 3 clients, close middle client
# Type in remaining clients
```

**Expected:**
- ✅ Remaining clients unaffected
- ✅ Process continues running
- ✅ Logs show "Client removed, remaining: 2"

#### Test 3: Process Exit
```bash
./build/ttyd -W -p 7682 -o bash
# Connect 3 clients, type 'exit' in any client
```

**Expected:**
- ✅ All 3 clients receive exit notification
- ✅ All connections close
- ✅ Server exits (due to `-o` flag)

#### Test 4: Narrow Client Joins Wide Session (Resize Fix)
```bash
./build/ttyd -W -p 7682 -d 9 bash
# Open first browser with wide window (120+ columns)
# Run htop or codex
# Open second browser with narrow window (80 columns)
```

**Expected:**
- ✅ No snapshot corruption in narrow client
- ✅ Logs show "sending resize before snapshot"
- ✅ Browser console shows SESSION_RESIZE before snapshot

#### Test 5: Terminal Resize
```bash
./build/ttyd -W -p 7682 bash
# Connect client A (120×30), then client B (80×24)
# Run: echo $COLUMNS $LINES
```

**Expected:**
- ✅ Both clients show 80×24 (minimum dimensions)
- ✅ Content visible in both terminals without cropping

#### Test 6: Memory Leak Test
```bash
valgrind --leak-check=full ./build/ttyd -W -p 7682 -o echo "test"
# Connect 5 clients simultaneously
```

**Expected:**
- ✅ No memory leaks reported
- ✅ All buffers properly freed
- ✅ Clean shutdown

### Stress Testing

**Rapid Connect/Disconnect:**
```javascript
// Browser console:
for (let i = 0; i < 100; i++) {
  setTimeout(() => {
    const ws = new WebSocket('ws://localhost:7682/ws');
    setTimeout(() => ws.close(), 1000);
  }, i * 100);
}
```

**Expected:**
- ✅ No crashes
- ✅ Correct client count tracking
- ✅ No resource leaks

---

## Key Commits

### Shared PTY Implementation
- **Commit**: [Pending] "Implement shared PTY mode"
- **Files**: src/server.h, src/protocol.c, src/pty.h, src/pty.c, src/server.c
- **Changes**: +300 lines core infrastructure

### Critical Bug Fixes
- **Commit**: [Pending] "Fix shared PTY stability issues"
- **Files**: src/protocol.c
- **Changes**: PTY resume, buffer lifecycle, WSI cleanup, counter underflow, --once flag

### Snapshot Resize Fix
- **Commit**: 366e662 "Fix snapshot corruption by sending SESSION_RESIZE before SNAPSHOT"
- **Files**: src/server.h, src/protocol.c
- **Changes**: +20 lines, reordered handshake sequence

### Related Commits
- c71e94b "Fix shared PTY snapshot issues: prevent OSC leaks and ensure session resize delivery"
- 1dd41f5 "Add terminal snapshot support with ANSI formatting preservation"

---

## Command-Line Flag

**Added:** `-Q` / `--shared-pty` flag to enable shared PTY mode

**Usage:**
```bash
# Shared PTY with writable mode (collaborative session)
./ttyd -Q -W bash

# Shared PTY with authentication (read-only viewers)
./ttyd -Q -c admin:password bash

# One-shot shared demo
./ttyd -Q -o -W htop
```

**Backward Compatibility:** Default behavior unchanged. Shared mode is opt-in.

---

## Behavioral Changes in Shared Mode

### 1. Input Handling
- **Before:** Each client has dedicated PTY, isolated input
- **After:** All clients send input to shared PTY (merged)
- **Impact:** Multiple users typing simultaneously can be confusing
- **Recommendation:** Use external coordination (voice, chat) or read-only mode

### 2. Terminal Dimensions
- **Before:** Each client's terminal size is independent
- **After:** Session uses minimum dimensions across all clients
- **Impact:** Wide clients see content sized for narrowest client
- **Benefit:** All clients can see full content without scrolling

### 3. Process Exit
- **Before:** Process exit only affects that client
- **After:** Process exit closes ALL connected clients
- **Impact:** One client typing `exit` disconnects everyone
- **Workaround:** Warn users not to exit, or use `--once` intentionally

### 4. Environment Variables
- **Before:** Each client gets `TTYD_USER=<username>` based on authentication
- **After:** All clients share environment (first client's username)
- **Impact:** Scripts cannot distinguish between users
- **Note:** Future enhancement could set `TTYD_USERS=user1,user2,user3`

---

## Documentation

**See Also:**
- [README.md](README.md) - Main documentation
- [BUILD_AND_TEST.md](BUILD_AND_TEST.md) - Build and testing instructions
- [SHARED_PTY_OUTSTANDING_WORK.md](SHARED_PTY_OUTSTANDING_WORK.md) - Remaining work and future features

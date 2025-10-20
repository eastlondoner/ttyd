# Shared PTY Outstanding Work

This document tracks remaining tasks, known issues, and future enhancements for ttyd's shared PTY mode.

## Table of Contents

1. [Remaining Bugs](#remaining-bugs)
2. [Testing Needs](#testing-needs)
3. [Pending Features](#pending-features)
4. [Future Enhancements](#future-enhancements)
5. [Documentation Updates](#documentation-updates)

---

## Remaining Bugs

### Bug 1: Memory Leak - Duplicated Arg/Env Resources

**Severity:** Medium
**Impact:** Memory leaks in long-running daemons with frequent shared PTY creation

**Problem:**
- `build_args_from_server()` duplicates every `argv` entry with `strdup()`
- `process_free()` only frees the outer pointer (`src/pty.c:132-136`)
- Strings leak on every shared PTY creation
- `server->first_client_user` is repeatedly `strdup`'d and only freed during server teardown

**Location:** `src/protocol.c` (build_args_from_server), `src/pty.c` (process_free)

**Solution:**
1. Update `process_free()` to free each element of `process->argv`:
   ```c
   void process_free(pty_process *process) {
     // ... existing code ...

     // Free argv strings (ADDED)
     if (process->argv != NULL) {
       for (int i = 0; process->argv[i] != NULL; i++) {
         free(process->argv[i]);
       }
       free(process->argv);
     }

     // ... rest of cleanup ...
   }
   ```

2. Free `first_client_user` before reassigning in `create_shared_process()`:
   ```c
   if (server->first_client_user != NULL) {
     free(server->first_client_user);
   }
   server->first_client_user = strdup(username);
   ```

3. Ensure env arrays are properly freed in `process_free()`

**Testing:**
- Run with valgrind: `valgrind --leak-check=full ./ttyd -Q -W bash`
- Create and destroy shared PTYs repeatedly
- Verify no "definitely lost" allocations

**Priority:** Medium (affects long-running servers)

---

### Bug 2: User-Specified `disableStdin` Override Ignored

**Severity:** Low
**Impact:** User overrides silently ignored

**Problem:**
- Code calls `json_object_object_add(client_prefs, "disableStdin", ...)` after parsing `-t key=value` options (`src/server.c:546-548`)
- `json_object_object_add()` overwrites existing keys
- User overrides from CLI are lost

**Location:** `src/server.c:546-548`

**Solution:**
Only set `disableStdin` if the key is absent:
```c
// Check if user already set disableStdin
json_object *existing = NULL;
if (!json_object_object_get_ex(client_prefs, "disableStdin", &existing)) {
  // Only set if not already present
  json_object_object_add(client_prefs, "disableStdin",
                         json_object_new_boolean(!server->writable));
}
```

**Testing:**
- Run: `./ttyd -Q -t disableStdin=false bash`
- Verify stdin is enabled despite default read-only mode
- Check that preference is not overwritten

**Priority:** Low (workaround: just use `-W` flag)

---

## Testing Needs

### Manual Test Cases (Priority: High)

The resize fix (SESSION_RESIZE before SNAPSHOT) needs manual validation:

#### Test 1: Narrow Client Joins Wide Session
```bash
./build/ttyd -Q -W -p 7682 -d 9 bash
```

**Steps:**
1. Open first browser with wide window (120+ columns)
2. Run: `htop` or `codex` (full-screen TUI)
3. Verify first client sees full display
4. **Open second browser with narrow window (80 columns)**
5. **Expected:** Second client sees clean snapshot, no corruption
6. **Verify logs:** "Client X: requested=80x24, session=120x30, sending resize before snapshot"
7. **Verify browser console:** "Received SESSION_RESIZE" before "received snapshot"

**Status:** ⬜ Not tested yet

#### Test 2: Wide Client Joins Narrow Session
```bash
./build/ttyd -Q -W -p 7682 bash
```

**Steps:**
1. Open first browser with narrow window (80 columns)
2. Run a TUI app
3. **Open second browser with wide window (120 columns)**
4. **Expected:** Both clients resize to 80×24, snapshot renders correctly
5. **Verify:** No corruption, layout intact

**Status:** ⬜ Not tested yet

#### Test 3: Multiple Rapid Connections
```bash
./build/ttyd -Q -W -p 7682 bash
```

**Steps:**
1. Open first browser, run `codex`
2. **Rapidly open 5 more browser windows with varying widths**
3. **Expected:** All clients see correct snapshot, no corruption
4. **Verify:** Check each client's browser console for message ordering

**Status:** ⬜ Not tested yet

#### Test 4: First Client Edge Case
```bash
./build/ttyd -Q -W -p 7682 -d 9 bash
```

**Steps:**
1. Open first browser with 100×30 terminal
2. **Expected:** No SESSION_RESIZE sent (first client establishes session)
3. **Verify logs:** No "sending resize before snapshot" for first client
4. Open second browser with 80×24
5. **Expected:** Both clients receive resize to 80×24, then snapshot
6. **Verify logs:** "sending resize before snapshot" with session=80x24

**Status:** ⬜ Not tested yet

#### Test 5: Client Matches Session Dimensions
```bash
./build/ttyd -Q -W -p 7682 bash
```

**Steps:**
1. Start with first client at 100×30
2. Open second client also at 100×30 (exactly matching)
3. **Expected:** Second client receives SESSION_RESIZE (informational), then snapshot
4. **Verify:** Check that snapshot renders correctly

**Status:** ⬜ Not tested yet

#### Test 6: Verify Browser Console Message Ordering
**Steps:**
1. Open browser console (F12 → Console)
2. Connect to shared PTY session
3. **Expected:** Console shows:
   - "Received SESSION_RESIZE" before "received snapshot"
   - Terminal dimensions logged correctly
4. **Verify:** No errors or warnings

**Status:** ⬜ Not tested yet

---

### Regression Tests (Priority: Medium)

#### Test 7: Non-Shared Mode (Regular ttyd)
```bash
./build/ttyd -W -p 7682 bash
```

**Steps:**
1. Open multiple clients
2. Verify each has isolated PTY
3. Type in one client, verify others don't see input
4. **Expected:** No impact on per-client PTY mode

**Status:** ⬜ Not tested yet

#### Test 8: Shared Mode with Snapshot Disabled
```bash
./build/ttyd -Q -W --shared-pty-snapshot=false -p 7682 bash
```
*(Note: This flag may not exist yet, test if implemented)*

**Steps:**
1. Connect multiple clients
2. **Expected:** No snapshot sent, resize messages still work
3. **Verify:** No crashes when snapshot is skipped

**Status:** ⬜ Not tested yet

#### Test 9: Memory Leak Detection
```bash
valgrind --leak-check=full --show-leak-kinds=all \
  ./build/ttyd -Q -W -p 7682 -o echo "test"
```

**Steps:**
1. Connect 5 clients simultaneously
2. Wait for process to exit
3. **Expected:** No memory leaks reported
4. **Verify:** All buffers properly freed

**Status:** ⬜ Not tested yet

---

### Integration Tests (Priority: Low)

**Automated Test Script:**
```bash
#!/bin/bash
# test_shared_pty.sh

echo "=== Test 1: Single Client ==="
./ttyd -Q -p 7682 -o echo "test" &
PID=$!
sleep 1
curl http://localhost:7682 > /dev/null
wait $PID
echo "✅ Test 1 passed"

echo ""
echo "=== Test 2: Process Exit (Multiple Clients) ==="
./ttyd -Q -p 7682 -o ls &
PID=$!
sleep 1
# Open 3 connections
curl http://localhost:7682 > /dev/null &
curl http://localhost:7682 > /dev/null &
curl http://localhost:7682 > /dev/null &
wait $PID
echo "✅ Test 2 passed"
```

**Status:** ⬜ Not implemented yet

---

## Pending Features

### Feature 1: libtsm Snapshot Generation

**Goal:** Generate terminal snapshots for new clients using libtsm

**Status:** Design complete, implementation pending

**Remaining Steps:**

1. **Dependency Integration** (High Priority)
   - [ ] Vendor libtsm into `third_party/libtsm/`
   - [ ] Update CMakeLists.txt to build and link libtsm
   - [ ] Verify cross-platform compatibility (macOS, Linux, Windows)
   - [ ] Document libtsm licensing and requirements

2. **Server-Side VTE Integration** (High Priority)
   - [ ] Add `struct tsm_screen *tsm_screen` and `struct tsm_vte *tsm_vte` to `struct server`
   - [ ] Initialize libtsm objects when shared PTY is created
   - [ ] Feed PTY output to libtsm in `shared_process_read_cb()`
   - [ ] Ensure UTF-8 boundary handling (don't split multi-byte sequences)

3. **Snapshot Serialization** (High Priority)
   - [ ] Implement `serialize_snapshot()` using `tsm_screen_draw()`
   - [ ] Generate JSON with:
     - Array of lines (text + attributes)
     - Cursor position (row, col)
     - Terminal modes (insert mode, alternate screen, etc.)
   - [ ] Add bounds checking (limit scrollback depth)
   - [ ] Trim trailing blanks to reduce payload size

4. **Client Handshake Changes** (Medium Priority)
   - [ ] During JSON_DATA handshake:
     - Generate snapshot matching client's terminal size
     - Send SNAPSHOT message after SESSION_RESIZE
     - Resume normal output stream
   - [ ] Handle edge cases:
     - No snapshot available yet (PTY just created)
     - Snapshot generation fails
     - Client disconnects during snapshot send

5. **Frontend Integration** (Medium Priority)
   - [ ] Update frontend to handle SNAPSHOT message type
   - [ ] Implement `applySnapshot()` in xterm.js:
     - Clear terminal
     - Write each line
     - Set cursor position
     - Restore terminal modes
   - [ ] Inject scrollback lines (if supported by xterm.js)
   - [ ] Ensure backward compatibility (older frontends ignore snapshot)

6. **Configuration Options** (Low Priority)
   - [ ] Add `--shared-pty-snapshot=<true|false>` CLI flag
   - [ ] Add `--shared-pty-scrollback=<lines>` (default: 2000)
   - [ ] Add debug logging:
     - Snapshot size (bytes)
     - Generation time (ms)
     - Number of lines sent

7. **Testing** (High Priority)
   - [ ] Unit tests: Feed recorded PTY transcripts to libtsm, assert snapshot output
   - [ ] Integration tests: Connect clients, verify snapshot delivery
   - [ ] Stress tests: Monitor memory with frequent connects/disconnects
   - [ ] Fixtures: Store expected snapshots for regression testing

**Implementation Notes:**

**libtsm Integration Example:**
```c
// Initialize libtsm when creating shared PTY
server->tsm_screen = tsm_screen_new();
server->tsm_vte = tsm_vte_new();
tsm_screen_resize(server->tsm_screen, columns, rows);

// Feed PTY output to libtsm
static void shared_process_read_cb(pty_process *process, pty_buf_t *buf, bool eof) {
  // ... existing broadcast logic ...

  // Feed to libtsm for snapshot generation
  tsm_vte_input(server->tsm_vte, buf->base, buf->len);

  // ... continue with broadcast ...
}
```

**Snapshot Serialization Example:**
```c
char *serialize_snapshot(struct server *server, uint16_t cols, uint16_t rows) {
  json_object *snapshot = json_object_new_object();
  json_object *lines_array = json_object_new_array();

  // Walk screen via tsm_screen_draw
  for (int row = 0; row < rows; row++) {
    // Extract line text and attributes
    char *line_text = extract_line(server->tsm_screen, row);
    json_object_array_add(lines_array, json_object_new_string(line_text));
    free(line_text);
  }

  json_object_object_add(snapshot, "lines", lines_array);
  json_object_object_add(snapshot, "cursor_row", json_object_new_int(cursor_row));
  json_object_object_add(snapshot, "cursor_col", json_object_new_int(cursor_col));

  const char *json_str = json_object_to_json_string(snapshot);
  char *result = strdup(json_str);
  json_object_put(snapshot);

  return result;
}
```

**Open Questions:**
- Should libtsm be vendored or added as system dependency?
  - **Recommendation:** Vendor (easier cross-platform builds)
- What scrollback limit is appropriate?
  - **Recommendation:** 2000 lines (configurable)
- How to handle very large terminals (300×100)?
  - **Recommendation:** Set maximum snapshot size, truncate if needed
- Should snapshot be compressed?
  - **Recommendation:** Not initially, add if payload size is problematic

---

## Future Enhancements

### Enhancement 1: Per-Client Write Permissions

**Goal:** Allow fine-grained control over which clients can send input

**Use Case:** Presenter mode (one writer, multiple read-only viewers)

**Implementation:**
```c
// Add to struct pss_tty
bool can_write;  // Per-client write permission

// During authentication
if (strcmp(pss->user, "admin") == 0) {
  pss->can_write = true;  // Admin can write
} else {
  pss->can_write = false;  // Others are read-only
}

// In INPUT handler
if (!pss->can_write) {
  lwsl_debug("Client %s attempted to write (read-only)\n", pss->address);
  break;
}
```

**Configuration Options:**
- `--write-roles=admin,presenter` - List of usernames with write permission
- `--read-only-by-default` - All clients read-only unless explicitly granted

**Priority:** Medium

---

### Enhancement 2: Maximum Dimensions Resize Strategy

**Goal:** Use maximum dimensions instead of minimum to avoid content cropping

**Current Behavior:**
- Session dimensions = min(client1, client2, client3)
- Ensures all clients see full content
- Wide clients see "narrow" session

**Alternative Behavior:**
- Session dimensions = max(client1, client2, client3)
- Ensures no content is cropped
- Narrow clients must scroll to see full content

**Implementation:**
```c
// In update_shared_session_geometry()
uint16_t max_cols = 0, max_rows = 0;
for (int i = 0; i < server->client_wsi_capacity; i++) {
  if (server->client_wsi_list[i] != NULL) {
    struct pss_tty *pss = get_pss_from_wsi(server->client_wsi_list[i]);
    if (pss->requested_columns > max_cols) max_cols = pss->requested_columns;
    if (pss->requested_rows > max_rows) max_rows = pss->requested_rows;
  }
}

// Apply maximum dimensions
pty_resize(server->shared_process, max_cols, max_rows);
```

**Configuration:**
- `--shared-pty-resize=min` (default, current behavior)
- `--shared-pty-resize=max` (new option)

**Priority:** Low (minimum dimensions works well for most cases)

---

### Enhancement 3: Process Auto-Respawn

**Goal:** Automatically restart shared PTY on crash/exit

**Use Case:** Keep server available for new clients after process exits

**Implementation:**
```c
static void shared_process_exit_cb(...) {
  // ... close all clients ...

  // Auto-respawn if configured
  if (server->auto_respawn) {
    lwsl_notice("Auto-respawning shared PTY process\n");
    sleep(1);  // Brief delay
    create_shared_process(server, default_cols, default_rows);
  }
}
```

**Configuration:**
- `--shared-pty-respawn` - Enable auto-respawn
- `--shared-pty-respawn-delay=<seconds>` - Delay before respawn

**Complexity:** Medium (need to handle respawn loops, max retries)

**Priority:** Low (defer to future enhancement)

---

### Enhancement 4: Snapshot Compression

**Goal:** Reduce snapshot payload size for large terminals

**Use Case:** Very large terminals (300×100) or high-latency connections

**Implementation:**
```c
// Compress snapshot JSON before sending
char *compressed = zlib_compress(snapshot_json, &compressed_size);

// Send with compression flag
unsigned char *message = xmalloc(LWS_PRE + 1 + compressed_size);
message[LWS_PRE] = SNAPSHOT_COMPRESSED;  // New message type
memcpy(&message[LWS_PRE + 1], compressed, compressed_size);
```

**Frontend:**
```typescript
case Command.SNAPSHOT_COMPRESSED:
  const decompressed = pako.inflate(data);  // Use pako.js for decompression
  this.applySnapshot(decompressed);
  break;
```

**Priority:** Low (only needed if snapshot sizes are problematic)

---

### Enhancement 5: Broadcast Resize Notifications to Clients

**Goal:** Inform non-controlling clients when session geometry changes

**Use Case:** Narrow client wants to know why content is sized differently

**Implementation:**
```c
// Send notification to all clients when PTY resized
for (int i = 0; i < server->client_wsi_capacity; i++) {
  if (server->client_wsi_list[i] != NULL) {
    char msg[128];
    snprintf(msg, sizeof(msg),
             "{\"type\":\"session_resized\",\"cols\":%d,\"rows\":%d,\"reason\":\"client_joined\"}",
             columns, rows);
    send_json_message(server->client_wsi_list[i], msg);
  }
}
```

**Frontend:** Display notification in terminal or status bar

**Priority:** Low (nice-to-have, not critical)

---

## Documentation Updates

### README.md Updates (Priority: High)

**Add Section: Shared Terminal Mode**

Location: After "Features" section

```markdown
## Shared Terminal Mode

Enable shared terminal mode to allow multiple clients to connect to the same terminal session:

    ttyd --shared-pty bash

All connected clients will:
- See the same output in real-time
- Share input (all can type, configurable with `-W`)
- Share terminal dimensions (sized for narrowest client)
- Disconnect when the process exits

**Use cases:**
- Live coding demonstrations
- Collaborative debugging sessions
- Remote pair programming
- Screen sharing for presentations

**Limitations:**
- Multiple simultaneous typers can create input chaos
- Session dimensions sized for narrowest client (others may see extra space)
- All clients disconnect when PTY process exits

**Best practices:**
- Coordinate who types using external communication (voice, chat)
- Use read-only mode (default, no `-W` flag) for presentations
- Enable writable mode (`-W`) only for trusted collaborators
```

**Status:** ⬜ Not updated yet

---

### Man Page Updates (Priority: High)

**Add Flag Documentation:**

```
-Q, --shared-pty
    Enable shared PTY mode. All WebSocket clients connect to a single shared
    pseudo-terminal instead of getting dedicated PTY processes.

    In shared mode:
    • All clients see identical output in real-time
    • Terminal dimensions sized for narrowest client
    • Process exit disconnects all clients
    • Use with -W to enable collaborative input

    Example: ttyd --shared-pty -W bash
```

**Status:** ⬜ Not updated yet

---

### BUILD_AND_TEST.md Updates (Priority: Medium)

**Add Section: Testing Shared PTY Mode**

```markdown
## Testing Shared PTY Mode

### Basic Shared PTY Test
```bash
./build/ttyd -Q -W -p 7682 bash
# Open multiple browser tabs to http://localhost:7682
# Type in any tab, verify output appears in all tabs
```

### Regression Test Suite
```bash
# Run shared PTY unit tests
./build/tests/shared_pty_regression_tests

# Run all tests
ctest -R shared_pty
```

### Memory Leak Detection
```bash
valgrind --leak-check=full ./build/ttyd -Q -W -p 7682 -o echo "test"
```
```

**Status:** ⬜ Not updated yet

---

### CLAUDE.md Updates (Priority: Low)

**Add Section: Shared PTY Architecture**

```markdown
## Shared PTY Mode

Shared PTY mode (`--shared-pty` flag) allows multiple clients to connect to one terminal:

**Key files:**
- `src/protocol.c:create_shared_process()` - Shared PTY initialization
- `src/protocol.c:shared_process_read_cb()` - Broadcast output to all clients
- `src/protocol.c:update_shared_session_geometry()` - Compute minimum dimensions
- `tests/shared_pty_regression_tests.c` - Regression test suite

**Data structures:**
- `server->shared_process` - Single PTY for all clients
- `server->client_wsi_list[]` - Dynamic array of connected clients
- `pty_buf_t->ref_count` - Reference counting for shared buffers

**Testing:**
Run: `./build/tests/shared_pty_regression_tests`
```

**Status:** ⬜ Not updated yet

---

## Summary

### Critical Path

1. ✅ **Complete manual testing** of resize fix (Test Cases 1-6)
2. ⬜ **Fix memory leaks** (Bug 1 - arg/env resources)
3. ⬜ **Implement libtsm snapshot generation** (Feature 1, Steps 1-3)
4. ⬜ **Update documentation** (README, man page)

### Long-Term Roadmap

**Phase 1: Stabilization** (Current)
- ✅ Core shared PTY infrastructure
- ✅ Critical bug fixes
- ✅ Snapshot resize fix
- ⬜ Manual testing
- ⬜ Memory leak fixes

**Phase 2: Snapshot Feature** (Next)
- libtsm integration
- Snapshot serialization
- Frontend rendering
- Integration testing

**Phase 3: Enhancements** (Future)
- Per-client write permissions
- Advanced resize strategies
- Process auto-respawn
- Snapshot compression

**Phase 4: Polish** (Future)
- Performance optimization
- Comprehensive documentation
- Example configurations
- Tutorial videos

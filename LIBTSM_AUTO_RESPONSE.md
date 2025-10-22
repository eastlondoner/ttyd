# libtsm Auto-Response Feature

## Problem

Some TUI applications (like cursor, btop, etc.) send terminal queries during initialization:
- **CSI 6n** - Cursor Position Request (ESC[6n)
- **DA** - Device Attributes (ESC[c or ESC[>c)
- **DSR** - Device Status Report
- **OSC queries** - Operating System Commands (colors, etc.)

These apps expect an immediate response from the terminal emulator. In ttyd's shared PTY mode, when the process starts **before any web client connects**, there's no xterm.js instance to respond to these queries. This causes some TUI apps to timeout and exit with errors like:

```
The cursor position could not be read within a normal duration
```

## Solution

We leverage libtsm (which is already used for snapshot generation) to act as a minimal server-side terminal responder **only when no clients are connected**.

### Implementation

In `src/protocol.c`, the `tsm_write_cb` callback now conditionally responds to terminal queries:

```c
static void tsm_write_cb(struct tsm_vte *vte, const char *u8, size_t len, void *data) {
  struct server *server = (struct server *)data;
  
  // Only respond when NO clients are attached
  if (server->active_client_count == 0 && server->shared_process != NULL) {
    pty_buf_t *response = pty_buf_init((char *)u8, len);
    pty_write(server->shared_process, response);
  }
}
```

### How It Works

1. **libtsm VTE processes all PTY output** (already happening for snapshots)
2. When VTE encounters a query (CSI 6n, DA, etc.), it generates the appropriate response
3. **If `active_client_count == 0`**: Response is sent back to the PTY
4. **If clients are connected**: Response is discarded (xterm.js handles it)

### Benefits

✅ **Correct responses** - libtsm generates accurate, context-aware replies (not hardcoded)
- Cursor position reflects actual screen state
- Device attributes match terminal capabilities  
- Color queries return correct values

✅ **No pattern matching** - libtsm handles all escape sequence parsing

✅ **Zero overhead** - libtsm VTE already processes PTY output for snapshots

✅ **Automatic handoff** - When first client connects, xterm.js takes over

✅ **Prevents timeouts** - TUI apps no longer hang waiting for responses

### Limitations

- Only works in **shared PTY mode** (requires libtsm)
- Small window between first client WebSocket connect and xterm.js ready
  - During this window, both libtsm and xterm.js might respond
  - Not a problem in practice - duplicate responses are harmless

## Testing

### Manual Test

```bash
# Start ttyd with debug output
./build/ttyd --shared-session -d 9 cursor

# Look for this log message before any client connects:
# "libtsm auto-responding to terminal query (6 bytes) - no clients attached"
```

### Affected Applications

This fixes issues with:
- **cursor** - Claude Code TUI (sends CSI 6n on startup)
- **btop** - System monitor (sends device attribute queries)
- **tmux** - Terminal multiplexer (when launched inside ttyd)
- Any TUI that queries terminal capabilities during init

## Related Issues

- [openai/codex#2805](https://github.com/openai/codex/issues/2805) - Cursor position timeout in tmux
- Similar issues reported with other TUI apps in headless/automated environments

## Alternative Approaches Considered

1. ❌ **Pattern matching in PTY output** - Fragile, incomplete
2. ❌ **Delay PTY spawn** - Doesn't help with tmux pre-attach scenarios  
3. ❌ **Hardcoded responses** - Incorrect cursor position, missing queries
4. ✅ **libtsm conditional response** - Leverages existing infrastructure perfectly

## Future Improvements

Consider implementing [Alternative #2](LIBTSM_AUTO_RESPONSE.md#alternative-2) from design discussion:
- Delay `pty_resume()` until first client acknowledges snapshot
- Eliminates the small race window entirely
- Would be complementary to this solution (defense in depth)


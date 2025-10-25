# Shared PTY Protocol Guide for Custom Clients

This document describes the WebSocket protocol changes required to connect custom xterm.js clients to ttyd's shared PTY mode (`-Q` flag).

**Target Audience:** Developers building custom web clients that use xterm.js and WebSockets to connect to ttyd, but are **NOT** using the ttyd frontend.

## Overview

When ttyd runs in shared PTY mode (`ttyd -Q`), multiple clients connect to a single shared terminal session. This requires protocol changes to:

1. Synchronize terminal dimensions across all clients
2. Deliver initial terminal state (snapshot) to late-joining clients
3. Prevent individual clients from resizing the shared session independently

## Protocol Changes

### New Server-to-Client Commands

The following commands are sent from ttyd server to connected clients:

| Command | Byte | Description |
|---------|------|-------------|
| `SNAPSHOT` | `'3'` | Terminal state snapshot (JSON) sent to new clients joining an existing session |
| `SESSION_RESIZE` | `'4'` | Session-wide terminal resize (JSON) - all clients must resize to match |

### New Client-to-Server Commands

| Command | Byte | Description |
|---------|------|-------------|
| `SNAPSHOT_ACK` | `'4'` | Client acknowledges snapshot receipt - unblocks PTY output |

### Existing Commands (unchanged)

**Client → Server:**
- `INPUT` (`'0'`) - Terminal input data
- `RESIZE_TERMINAL` (`'1'`) - **IGNORED in shared mode** - terminal size is controlled by server
- `PAUSE` (`'2'`) - Pause output
- `RESUME` (`'3'`) - Resume output

**Server → Client:**
- `OUTPUT` (`'0'`) - Terminal output data
- `SET_WINDOW_TITLE` (`'1'`) - Window title
- `SET_PREFERENCES` (`'2'`) - Terminal preferences (JSON)

## Implementation Requirements

### 1. Disable Client-Side Terminal Resizing

**CRITICAL:** In shared mode, clients must NOT resize the terminal based on browser window size or user preferences.

**What you must change:**

```typescript
// ❌ BAD - Do NOT use FitAddon in shared mode
import { FitAddon } from '@xterm/addon-fit';
const fitAddon = new FitAddon();
terminal.loadAddon(fitAddon);
window.addEventListener('resize', () => fitAddon.fit());

// ✅ GOOD - Let container scroll instead
terminal.open(parentElement);
parentElement.style.overflow = 'auto';  // Enable scrolling
```

**Why:** The terminal dimensions are set by the server to accommodate all connected clients. Individual clients resizing would desync the session.

### 2. Handle SESSION_RESIZE Command

The server sends `SESSION_RESIZE` to set the terminal dimensions. All clients must resize to match.

**Message Format:**
```
Byte 0: '4' (SESSION_RESIZE command)
Bytes 1+: JSON object
```

**JSON Schema:**
```json
{
  "columns": 80,
  "rows": 24
}
```

**Implementation:**

```typescript
function handleServerMessage(data: Uint8Array) {
  const decoder = new TextDecoder();
  const cmd = String.fromCharCode(data[0]);

  if (cmd === '4') {  // SESSION_RESIZE
    const json = decoder.decode(data.slice(1));
    const { columns, rows } = JSON.parse(json);

    // Resize terminal without sending RESIZE_TERMINAL back to server
    suppressResizeEvent = true;
    try {
      terminal.resize(columns, rows);
    } finally {
      suppressResizeEvent = false;
    }

    console.log(`Terminal resized to ${columns}x${rows} by server`);
  }
}
```

**Important:** When resizing in response to `SESSION_RESIZE`, you must NOT send a `RESIZE_TERMINAL` message back to the server, as this would create a loop.

### 3. Handle SNAPSHOT Command

When a client joins an existing shared session, the server sends a snapshot of the current terminal state. This allows late-joining clients to see what happened before they connected.

**Message Format:**
```
Byte 0: '3' (SNAPSHOT command)
Bytes 1+: JSON object
```

**JSON Schema:**
```json
{
  "lines": [
    "line 0 content with \u001b[31mANSI\u001b[0m codes",
    "line 1 content",
    "line 2 content",
    ...
  ],
  "cursor_x": 10,
  "cursor_y": 5
}
```

**Fields:**
- `lines`: Array of strings, one per terminal row. Each string may contain ANSI escape sequences for colors/formatting.
- `cursor_x`: Cursor column position (0-indexed)
- `cursor_y`: Cursor row position (0-indexed)

**Implementation:**

```typescript
function handleServerMessage(data: Uint8Array) {
  const decoder = new TextDecoder();
  const cmd = String.fromCharCode(data[0]);

  if (cmd === '3') {  // SNAPSHOT
    const json = decoder.decode(data.slice(1));
    const snapshot = JSON.parse(json);

    console.log(`Received snapshot: ${snapshot.lines.length} lines, ` +
                `cursor at (${snapshot.cursor_x}, ${snapshot.cursor_y})`);

    // Clear screen and reset cursor
    terminal.write('\x1b[2J\x1b[H');

    // Write each line using ANSI positioning
    for (let i = 0; i < snapshot.lines.length; i++) {
      if (snapshot.lines[i].length > 0) {
        // Position cursor at row (1-indexed)
        terminal.write(`\x1b[${i + 1};1H${snapshot.lines[i]}`);
      }
    }

    // Position cursor at saved location (1-indexed)
    const row = snapshot.cursor_y + 1;
    const col = snapshot.cursor_x + 1;
    terminal.write(`\x1b[${row};${col}H`);

    // Send acknowledgment to server
    const ack = new Uint8Array([0x34]);  // '4' = SNAPSHOT_ACK
    websocket.send(ack);

    console.log('Snapshot applied successfully');
  }
}
```

**Critical:** You MUST send `SNAPSHOT_ACK` after applying the snapshot. The server blocks PTY output until it receives this acknowledgment to prevent race conditions.

### 4. Suppress Client-Initiated Resizes

In shared mode, clients should not send `RESIZE_TERMINAL` messages to the server.

**Implementation:**

```typescript
// Track session dimensions
let sessionColumns: number | undefined;
let sessionRows: number | undefined;
let suppressResize = false;

terminal.onResize(({ cols, rows }) => {
  if (suppressResize) {
    return;  // Ignore resize events we triggered ourselves
  }

  // In shared mode, prevent any resize that doesn't match session size
  if (sessionColumns !== undefined && sessionRows !== undefined) {
    if (cols !== sessionColumns || rows !== sessionRows) {
      // Revert to session size
      suppressResize = true;
      try {
        terminal.resize(sessionColumns, sessionRows);
      } finally {
        suppressResize = false;
      }
    }
  }
});

// When receiving SESSION_RESIZE, update tracked dimensions
function handleSessionResize(columns: number, rows: number) {
  sessionColumns = columns;
  sessionRows = rows;

  suppressResize = true;
  try {
    terminal.resize(columns, rows);
  } finally {
    suppressResize = false;
  }
}
```

## Connection Lifecycle

### First Client Connecting

1. Client connects via WebSocket
2. Server sends `SET_PREFERENCES` with terminal configuration
3. Server sends `SESSION_RESIZE` with initial terminal dimensions
4. Client resizes terminal to match
5. Server creates shared PTY process
6. Server starts sending `OUTPUT` messages
7. Client begins normal operation

### Additional Clients Joining

1. Client connects via WebSocket
2. Server sends `SET_PREFERENCES` with terminal configuration
3. Server sends `SESSION_RESIZE` with current terminal dimensions
4. Client resizes terminal to match
5. Server sends `SNAPSHOT` with current terminal state
6. Client applies snapshot and sends `SNAPSHOT_ACK`
7. Server resumes sending `OUTPUT` messages to this client
8. Client begins normal operation

### Terminal Resize by Any Client

In shared mode, terminal resizing is **disabled**. The terminal size is fixed when the first client connects.

**Why:** Supporting dynamic resizing in shared mode would require:
- Negotiating dimensions between all connected clients
- Handling conflicting resize requests
- Resizing the PTY (which can disrupt running programs)

For simplicity, the current implementation uses a fixed terminal size. All clients must match this size.

### Client Disconnection

When a client disconnects:
1. Server removes client from active client list
2. If the disconnecting client was the "primary" client, another client is promoted
3. If no clients remain and `--once` or `--exit-no-conn` is set, server terminates the PTY process

## Complete Example Implementation

```typescript
import { Terminal } from '@xterm/xterm';

// Configuration
let sessionColumns: number | undefined;
let sessionRows: number | undefined;
let suppressClientResize = false;

// Create terminal
const terminal = new Terminal({
  // Your terminal options
});

terminal.open(document.getElementById('terminal')!);

// Enable scrolling (since we can't resize to fit)
document.getElementById('terminal')!.style.overflow = 'auto';

// Connect to ttyd WebSocket
const ws = new WebSocket('ws://localhost:7681/ws');
ws.binaryType = 'arraybuffer';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// Handle incoming messages
ws.onmessage = (event) => {
  const data = new Uint8Array(event.data);
  const cmd = String.fromCharCode(data[0]);

  switch (cmd) {
    case '0':  // OUTPUT
      terminal.write(data.slice(1));
      break;

    case '1':  // SET_WINDOW_TITLE
      document.title = textDecoder.decode(data.slice(1));
      break;

    case '2':  // SET_PREFERENCES
      const prefs = JSON.parse(textDecoder.decode(data.slice(1)));
      // Apply preferences to terminal
      Object.assign(terminal.options, prefs);
      break;

    case '3':  // SNAPSHOT
      handleSnapshot(data.slice(1));
      break;

    case '4':  // SESSION_RESIZE
      handleSessionResize(data.slice(1));
      break;

    default:
      console.warn(`Unknown command: ${cmd}`);
  }
};

function handleSessionResize(jsonData: Uint8Array) {
  const { columns, rows } = JSON.parse(textDecoder.decode(jsonData));

  console.log(`Server set terminal size: ${columns}x${rows}`);

  sessionColumns = columns;
  sessionRows = rows;

  suppressClientResize = true;
  try {
    terminal.resize(columns, rows);
  } finally {
    suppressClientResize = false;
  }
}

function handleSnapshot(jsonData: Uint8Array) {
  const snapshot = JSON.parse(textDecoder.decode(jsonData));

  console.log(`Applying snapshot: ${snapshot.lines.length} lines`);

  // Clear and home
  terminal.write('\x1b[2J\x1b[H');

  // Render each line
  for (let i = 0; i < snapshot.lines.length; i++) {
    if (snapshot.lines[i].length > 0) {
      terminal.write(`\x1b[${i + 1};1H${snapshot.lines[i]}`);
    }
  }

  // Position cursor
  const row = snapshot.cursor_y + 1;
  const col = snapshot.cursor_x + 1;
  terminal.write(`\x1b[${row};${col}H`);

  // Send ACK
  ws.send(textEncoder.encode('4'));

  console.log('Snapshot applied');
}

// Send input to server
terminal.onData((data) => {
  ws.send(textEncoder.encode('0' + data));
});

// Prevent client-initiated resizing in shared mode
terminal.onResize(({ cols, rows }) => {
  if (suppressClientResize) {
    return;
  }

  // If session size is set, enforce it
  if (sessionColumns !== undefined && sessionRows !== undefined) {
    if (cols !== sessionColumns || rows !== sessionRows) {
      suppressClientResize = true;
      try {
        terminal.resize(sessionColumns, sessionRows);
      } finally {
        suppressClientResize = false;
      }
    }
  }
});
```

## Testing Your Implementation

### Test 1: Single Client
```bash
ttyd -Q -W bash
```

Open your client. You should:
1. Receive `SET_PREFERENCES`
2. Receive `SESSION_RESIZE`
3. See a working terminal

### Test 2: Multiple Clients
```bash
ttyd -Q -W bash
```

Open first client, type some commands. Open second client. The second client should:
1. Receive `SET_PREFERENCES`
2. Receive `SESSION_RESIZE`
3. Receive `SNAPSHOT` with current terminal state
4. Show the same output as the first client
5. See real-time updates when the first client types

### Test 3: Snapshot Rendering

1. Start ttyd: `ttyd -Q -W bash`
2. In first client, run: `ls -la && echo "TEST" && cal`
3. Wait for output to complete
4. Open second client
5. Verify the second client shows all previous output

### Test 4: Terminal Dimensions

1. Start ttyd: `ttyd -Q -W bash`
2. In first client, run: `echo $COLUMNS x $LINES`
3. Open second client (with different browser window size)
4. Verify both clients show the same terminal dimensions
5. Resize browser windows - terminal should not change size

## Common Issues

### Issue: Terminal doesn't resize to fit browser window

**Expected behavior** in shared mode. The terminal size is fixed. Use CSS `overflow: auto` to enable scrolling.

### Issue: Second client shows empty terminal

You forgot to handle the `SNAPSHOT` command or didn't send `SNAPSHOT_ACK`.

### Issue: Terminal output stops after snapshot

You forgot to send `SNAPSHOT_ACK`. The server blocks PTY output until acknowledgment.

### Issue: Terminal keeps resizing repeatedly

You're sending `RESIZE_TERMINAL` messages in response to `SESSION_RESIZE`. Don't do that - use a flag to suppress client-initiated resizes.

### Issue: ANSI escape sequences appear as text

Your snapshot rendering is wrong. The `lines` array contains ANSI sequences that should be processed by xterm.js, not displayed as literal text. Use `terminal.write()`, not `terminal.writeln()` or DOM manipulation.

## Differences from Non-Shared Mode

| Feature | Non-Shared Mode | Shared PTY Mode |
|---------|----------------|-----------------|
| Terminal resizing | Client controls size | Server controls size |
| FitAddon | Works normally | **Must disable** |
| Window resize events | Trigger terminal resize | Ignored |
| Multiple clients | Each gets own PTY | All share one PTY |
| Late joining | Starts fresh | Receives snapshot |
| `RESIZE_TERMINAL` command | Accepted | Ignored |
| Initial state | Clean terminal | Snapshot of current state |

## Compatibility Notes

- Shared PTY mode requires ttyd to be compiled with **libtsm** support (for snapshot generation)
- The backend must be built from the `shared-tty` branch (or after the shared PTY feature is merged to main)
- Older ttyd versions (without shared PTY support) will not send `SNAPSHOT` or `SESSION_RESIZE` commands
- A client built for shared mode will still work with non-shared ttyd, but the snapshot/resize handling code will simply not be triggered

## Additional Resources

- ttyd source code: `src/protocol.c` (server protocol implementation)
- ttyd frontend reference: `html/src/components/terminal/xterm/index.ts`
- libtsm documentation: https://www.freedesktop.org/wiki/Software/libtsm/
- xterm.js documentation: https://xtermjs.org/docs/

## Questions?

If you encounter issues implementing this protocol, please:
1. Check server logs with debug level 9: `ttyd -d 9 -Q -W bash`
2. Check browser console for WebSocket messages
3. Verify you're sending `SNAPSHOT_ACK` after applying snapshots
4. Ensure you're not sending `RESIZE_TERMINAL` in shared mode

File issues at: https://github.com/tsl0922/ttyd/issues

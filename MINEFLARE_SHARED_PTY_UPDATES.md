# Mineflare Shared PTY Client Updates

The ttyd shared-PTY protocol now sends richer reconnect snapshots so secondary viewers inherit the live terminal state (alternate screen, keypad modes, cursor visibility, colors, etc.). To keep Codex behaving identically after a reconnect, the Mineflare web client in `/Users/andy/repos/mineflare/src/terminal` should adopt the following changes.

## 1. Snapshot Acknowledgment (if not already applied)
File: `/Users/andy/repos/mineflare/src/terminal/terminal.ts`

Guarantee that the `SNAPSHOT_ACK` (`0x34`) is sent even if JSON parsing or rendering errors occur. Wrap the snapshot handler in `try/finally` so the PTY never stays blocked waiting for an ACK.

```ts
function handleSnapshot(...) {
  const ack = new Uint8Array([0x34]);
  let ackSent = false;
  try {
    const snapshot = JSON.parse(...);
    ...
    instance.ws?.send(ack);
    ackSent = true;
  } catch (err) {
    console.error(...);
  } finally {
    if (!ackSent && instance.ws?.readyState === WebSocket.OPEN) {
      instance.ws.send(ack);
    }
  }
}
```

## 2. Restore Terminal Modes from Snapshot Flags
Snapshots now include two optional fields:

```json
{
  "screen_flags": <uint32>,
  "vte_flags": <uint32>
}
```

These encode libtsm’s screen/VTE state (alternate screen, cursor visibility, DEC application cursor keys, keypad application mode, wrap, origin, insert mode, etc.). Before replaying the snapshot text, emit the matching ANSI control sequences so xterm.js mirrors the shared PTY mode.

### Suggested Implementation Snippet

```ts
const ScreenFlag = {
  INSERT_MODE: 0x01,
  AUTO_WRAP: 0x02,
  REL_ORIGIN: 0x04,
  INVERSE: 0x08,
  HIDE_CURSOR: 0x10,
  ALTERNATE: 0x40,
} as const;

const VteFlag = {
  CURSOR_KEY_MODE: 0x0001,
  KEYPAD_APPLICATION_MODE: 0x0002,
  TEXT_CURSOR_MODE: 0x0200,
  INVERSE_SCREEN_MODE: 0x0400,
  ORIGIN_MODE: 0x0800,
  AUTO_WRAP_MODE: 0x1000,
} as const;

function applySnapshotModes(term: Terminal, snapshot: SnapshotPayload) {
  let seq = '';

  const setDecPrivate = (code: number, enable?: boolean) => {
    if (enable === undefined) return;
    seq += `\x1b[?${code}${enable ? 'h' : 'l'}`;
  };
  const setMode = (code: number, enable?: boolean) => {
    if (enable === undefined) return;
    seq += `\x1b[${code}${enable ? 'h' : 'l'}`;
  };

  const screen = snapshot.screen_flags ?? 0;
  const vte = snapshot.vte_flags ?? 0;

  const altScreen = (screen & ScreenFlag.ALTERNATE) !== 0;
  const showCursor = snapshot.screen_flags !== undefined
    ? (screen & ScreenFlag.HIDE_CURSOR) === 0
    : (vte & VteFlag.TEXT_CURSOR_MODE) !== 0;
  const inverse = ((screen & ScreenFlag.INVERSE) !== 0) || ((screen === 0) && ((vte & VteFlag.INVERSE_SCREEN_MODE) !== 0));
  const insertMode = (screen & ScreenFlag.INSERT_MODE) !== 0;
  const originMode = (vte & VteFlag.ORIGIN_MODE) !== 0;
  const autoWrap = ((screen & ScreenFlag.AUTO_WRAP) !== 0) || ((vte & VteFlag.AUTO_WRAP_MODE) !== 0);
  const cursorKeys = (vte & VteFlag.CURSOR_KEY_MODE) !== 0;
  const keypadApp = (vte & VteFlag.KEYPAD_APPLICATION_MODE) !== 0;

  setDecPrivate(1049, altScreen);
  setDecPrivate(25, showCursor);
  setDecPrivate(5, inverse);
  setMode(4, insertMode);
  setDecPrivate(6, originMode);
  setDecPrivate(7, autoWrap);
  setDecPrivate(1, cursorKeys);
  seq += keypadApp ? '\x1b=' : '\x1b>';

  if (seq) {
    term.write(seq);
  }
}
```

Call this helper right after parsing the snapshot JSON and **before** clearing / rewriting the screen. This ensures the Ratatui UI keeps its alternate screen, spinning logo animation, and keypad behaviour when additional viewers attach mid-session.

## 3. Deploy

1. Implement the changes in `terminal.ts`.
2. Rebuild and redeploy the Mineflare frontend so browsers load the updated client bundle.
3. Test a reconnect scenario to confirm Codex’s spinner and menu navigation continue without manual refresh.

Keeping these pieces in sync with upstream ttyd prevents regressions for late joiners while shared-PTY mode is active. !*** End Patch

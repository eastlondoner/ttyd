import { bind } from 'decko';
import type { IDisposable, ITerminalOptions } from '@xterm/xterm';
import { Terminal } from '@xterm/xterm';
import { CanvasAddon } from '@xterm/addon-canvas';
import { ClipboardAddon } from '@xterm/addon-clipboard';
import { WebglAddon } from '@xterm/addon-webgl';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { ImageAddon } from '@xterm/addon-image';
import { Unicode11Addon } from '@xterm/addon-unicode11';
import { OverlayAddon } from './addons/overlay';
import { ZmodemAddon } from './addons/zmodem';

import '@xterm/xterm/css/xterm.css';

declare global {
    interface Window {
        term: Terminal;
    }
}

interface SnapshotPayload {
    lines: string[];
    cursor_x: number;
    cursor_y: number;
    width: number;
    height: number;
    screen_flags?: number;
    vte_flags?: number;
}

enum ScreenFlag {
    INSERT_MODE = 0x01,
    AUTO_WRAP = 0x02,
    REL_ORIGIN = 0x04,
    INVERSE = 0x08,
    HIDE_CURSOR = 0x10,
    FIXED_POS = 0x20,
    ALTERNATE = 0x40,
}

enum VteFlag {
    CURSOR_KEY_MODE = 0x0001,
    KEYPAD_APPLICATION_MODE = 0x0002,
    INVERSE_SCREEN_MODE = 0x0400,
    TEXT_CURSOR_MODE = 0x0200,
    ORIGIN_MODE = 0x0800,
    AUTO_WRAP_MODE = 0x1000,
}

enum Command {
    // server side
    OUTPUT = '0',
    SET_WINDOW_TITLE = '1',
    SET_PREFERENCES = '2',
    SNAPSHOT = '3',
    SESSION_RESIZE = '4',

    // client side
    INPUT = '0',
    RESIZE_TERMINAL = '1',
    PAUSE = '2',
    RESUME = '3',
    SNAPSHOT_ACK = '4',
}
type Preferences = ITerminalOptions & ClientOptions;

export type RendererType = 'dom' | 'canvas' | 'webgl';

export interface ClientOptions {
    rendererType: RendererType;
    disableLeaveAlert: boolean;
    disableResizeOverlay: boolean;
    enableZmodem: boolean;
    enableTrzsz: boolean;
    enableSixel: boolean;
    titleFixed?: string;
    isWindows: boolean;
    trzszDragInitTimeout: number;
    unicodeVersion: string;
    closeOnDisconnect: boolean;
}

export interface FlowControl {
    limit: number;
    highWater: number;
    lowWater: number;
}

export interface XtermOptions {
    wsUrl: string;
    tokenUrl: string;
    flowControl: FlowControl;
    clientOptions: ClientOptions;
    termOptions: ITerminalOptions;
}

function toDisposable(f: () => void): IDisposable {
    return { dispose: f };
}

function addEventListener(target: EventTarget, type: string, listener: EventListener): IDisposable {
    target.addEventListener(type, listener);
    return toDisposable(() => target.removeEventListener(type, listener));
}

export class Xterm {
    private disposables: IDisposable[] = [];
    private textEncoder = new TextEncoder();
    private textDecoder = new TextDecoder();
    private written = 0;
    private pending = 0;

    private terminal: Terminal;
    private overlayAddon = new OverlayAddon();
    private clipboardAddon = new ClipboardAddon();
    private webLinksAddon = new WebLinksAddon();
    private webglAddon?: WebglAddon;
    private canvasAddon?: CanvasAddon;
    private zmodemAddon?: ZmodemAddon;

    private socket?: WebSocket;
    private token: string;
    private opened = false;
    private title?: string;
    private titleFixed?: string;
    private resizeOverlay = true;
    private reconnect = true;
    private doReconnect = true;
    private closeOnDisconnect = false;
    private sessionCols?: number;
    private sessionRows?: number;
    private suppressClientResize = false;

    private writeFunc = (data: ArrayBuffer) => this.writeData(new Uint8Array(data));

    constructor(
        private options: XtermOptions,
        private sendCb: () => void
    ) {}

    dispose() {
        for (const d of this.disposables) {
            d.dispose();
        }
        this.disposables.length = 0;
    }

    @bind
    private register<T extends IDisposable>(d: T): T {
        this.disposables.push(d);
        return d;
    }

    @bind
    public sendFile(files: FileList) {
        this.zmodemAddon?.sendFile(files);
    }

    @bind
    public async refreshToken() {
        try {
            const resp = await fetch(this.options.tokenUrl);
            if (resp.ok) {
                const json = await resp.json();
                this.token = json.token;
            }
        } catch (e) {
            console.error(`[ttyd] fetch ${this.options.tokenUrl}: `, e);
        }
    }

    @bind
    private onWindowUnload(event: BeforeUnloadEvent) {
        event.preventDefault();
        if (this.socket?.readyState === WebSocket.OPEN) {
            const message = 'Close terminal? this will also terminate the command.';
            event.returnValue = message;
            return message;
        }
        return undefined;
    }

    @bind
    public open(parent: HTMLElement) {
        this.terminal = new Terminal(this.options.termOptions);
        const { terminal, overlayAddon, clipboardAddon, webLinksAddon } = this;
        window.term = terminal;

        terminal.loadAddon(overlayAddon);
        terminal.loadAddon(clipboardAddon);
        terminal.loadAddon(webLinksAddon);

        terminal.open(parent);
        parent.style.overflow = 'auto';
    }

    @bind
    private initListeners() {
        const { terminal, register, sendData } = this;
        register(
            terminal.onTitleChange(data => {
                if (data && data !== '' && !this.titleFixed) {
                    document.title = data + ' | ' + this.title;
                }
            })
        );
        register(terminal.onData(data => sendData(data)));
        register(terminal.onBinary(data => sendData(Uint8Array.from(data, v => v.charCodeAt(0)))));
        register(
            terminal.onResize(({ cols, rows }) => {
                if (this.suppressClientResize) {
                    return;
                }

                if (this.sessionCols !== undefined && this.sessionRows !== undefined) {
                    if (cols !== this.sessionCols || rows !== this.sessionRows) {
                        this.forceSessionGeometry(this.sessionCols, this.sessionRows);
                    }
                }
            })
        );
        register(
            terminal.onSelectionChange(() => {
                if (this.terminal.getSelection() === '') return;
                try {
                    document.execCommand('copy');
                } catch (e) {
                    return;
                }
                this.overlayAddon?.showOverlay('\u2702', 200);
            })
        );
        register(addEventListener(window, 'beforeunload', this.onWindowUnload));
    }

    @bind
    public writeData(data: string | Uint8Array) {
        const { terminal, textEncoder } = this;
        const { limit, highWater, lowWater } = this.options.flowControl;

        this.written += data.length;
        if (this.written > limit) {
            terminal.write(data, () => {
                this.pending = Math.max(this.pending - 1, 0);
                if (this.pending < lowWater) {
                    this.socket?.send(textEncoder.encode(Command.RESUME));
                }
            });
            this.pending++;
            this.written = 0;
            if (this.pending > highWater) {
                this.socket?.send(textEncoder.encode(Command.PAUSE));
            }
        } else {
            terminal.write(data);
        }
    }

    @bind
    public sendData(data: string | Uint8Array) {
        const { socket, textEncoder } = this;
        if (socket?.readyState !== WebSocket.OPEN) return;

        if (typeof data === 'string') {
            const payload = new Uint8Array(data.length * 3 + 1);
            payload[0] = Command.INPUT.charCodeAt(0);
            const stats = textEncoder.encodeInto(data, payload.subarray(1));
            socket.send(payload.subarray(0, (stats.written as number) + 1));
        } else {
            const payload = new Uint8Array(data.length + 1);
            payload[0] = Command.INPUT.charCodeAt(0);
            payload.set(data, 1);
            socket.send(payload);
        }
    }

    @bind
    public connect() {
        this.socket = new WebSocket(this.options.wsUrl, ['tty']);
        const { socket, register } = this;

        socket.binaryType = 'arraybuffer';
        register(addEventListener(socket, 'open', this.onSocketOpen));
        register(addEventListener(socket, 'message', this.onSocketData as EventListener));
        register(addEventListener(socket, 'close', this.onSocketClose as EventListener));
        register(addEventListener(socket, 'error', () => (this.doReconnect = false)));
    }

    @bind
    private onSocketOpen() {
        console.log('[ttyd] websocket connection opened');

        const { textEncoder, terminal, overlayAddon } = this;
        const msg = JSON.stringify({ AuthToken: this.token, columns: terminal.cols, rows: terminal.rows });
        this.socket?.send(textEncoder.encode(msg));

        if (this.opened) {
            terminal.reset();
            terminal.options.disableStdin = false;
            overlayAddon.showOverlay('Reconnected', 300);
        } else {
            this.opened = true;
        }

        this.doReconnect = this.reconnect;
        this.initListeners();
        terminal.focus();
    }

    @bind
    private onSocketClose(event: CloseEvent) {
        console.log(`[ttyd] websocket connection closed with code: ${event.code}`);

        const { refreshToken, connect, doReconnect, overlayAddon } = this;
        overlayAddon.showOverlay('Connection Closed');
        this.dispose();

        // 1000: CLOSE_NORMAL
        if (event.code !== 1000 && doReconnect) {
            overlayAddon.showOverlay('Reconnecting...');
            refreshToken().then(connect);
        } else if (this.closeOnDisconnect) {
            window.close();
        } else {
            const { terminal } = this;
            const keyDispose = terminal.onKey(e => {
                const event = e.domEvent;
                if (event.key === 'Enter') {
                    keyDispose.dispose();
                    overlayAddon.showOverlay('Reconnecting...');
                    refreshToken().then(connect);
                }
            });
            overlayAddon.showOverlay('Press ⏎ to Reconnect');
        }
    }

    @bind
    private parseOptsFromUrlQuery(query: string): Preferences {
        const { terminal } = this;
        const { clientOptions } = this.options;
        const prefs = {} as Preferences;
        const queryObj = Array.from(new URLSearchParams(query) as unknown as Iterable<[string, string]>);

        for (const [k, queryVal] of queryObj) {
            let v = clientOptions[k];
            if (v === undefined) v = terminal.options[k];
            switch (typeof v) {
                case 'boolean':
                    prefs[k] = queryVal === 'true' || queryVal === '1';
                    break;
                case 'number':
                case 'bigint':
                    prefs[k] = Number.parseInt(queryVal, 10);
                    break;
                case 'string':
                    prefs[k] = queryVal;
                    break;
                case 'object':
                    prefs[k] = JSON.parse(queryVal);
                    break;
                default:
                    console.warn(`[ttyd] maybe unknown option: ${k}=${queryVal}, treating as string`);
                    prefs[k] = queryVal;
                    break;
            }
        }

        return prefs;
    }

    @bind
    private onSocketData(event: MessageEvent) {
        const { textDecoder } = this;
        const rawData = event.data as ArrayBuffer;
        const cmd = String.fromCharCode(new Uint8Array(rawData)[0]);
        const data = rawData.slice(1);

        switch (cmd) {
            case Command.OUTPUT:
                this.writeFunc(data);
                break;
            case Command.SET_WINDOW_TITLE:
                this.title = textDecoder.decode(data);
                document.title = this.title;
                break;
            case Command.SET_PREFERENCES:
                this.applyPreferences({
                    ...this.options.clientOptions,
                    ...JSON.parse(textDecoder.decode(data)),
                    ...this.parseOptsFromUrlQuery(window.location.search),
                } as Preferences);
                break;
            case Command.SNAPSHOT:
                this.applySnapshot(textDecoder.decode(data));
                break;
            case Command.SESSION_RESIZE:
                this.applySessionResize(textDecoder.decode(data));
                break;
            default:
                console.warn(`[ttyd] unknown command: ${cmd}`);
                break;
        }
    }

    @bind
    private applyPreferences(prefs: Preferences) {
        const { terminal, register } = this;
        if (prefs.enableZmodem || prefs.enableTrzsz) {
            this.zmodemAddon = new ZmodemAddon({
                zmodem: prefs.enableZmodem,
                trzsz: prefs.enableTrzsz,
                windows: prefs.isWindows,
                trzszDragInitTimeout: prefs.trzszDragInitTimeout,
                onSend: this.sendCb,
                sender: this.sendData,
                writer: this.writeData,
            });
            this.writeFunc = data => this.zmodemAddon?.consume(data);
            terminal.loadAddon(register(this.zmodemAddon));
        }

        for (const [key, value] of Object.entries(prefs)) {
            switch (key) {
                case 'rendererType':
                    this.setRendererType(value);
                    break;
                case 'disableLeaveAlert':
                    if (value) {
                        window.removeEventListener('beforeunload', this.onWindowUnload);
                        console.log('[ttyd] Leave site alert disabled');
                    }
                    break;
                case 'disableResizeOverlay':
                    if (value) {
                        console.log('[ttyd] Resize overlay disabled');
                        this.resizeOverlay = false;
                    }
                    break;
                case 'disableReconnect':
                    if (value) {
                        console.log('[ttyd] Reconnect disabled');
                        this.reconnect = false;
                        this.doReconnect = false;
                    }
                    break;
                case 'enableZmodem':
                    if (value) console.log('[ttyd] Zmodem enabled');
                    break;
                case 'enableTrzsz':
                    if (value) console.log('[ttyd] trzsz enabled');
                    break;
                case 'trzszDragInitTimeout':
                    if (value) console.log(`[ttyd] trzsz drag init timeout: ${value}`);
                    break;
                case 'enableSixel':
                    if (value) {
                        terminal.loadAddon(register(new ImageAddon()));
                        console.log('[ttyd] Sixel enabled');
                    }
                    break;
                case 'closeOnDisconnect':
                    if (value) {
                        console.log('[ttyd] close on disconnect enabled (Reconnect disabled)');
                        this.closeOnDisconnect = true;
                        this.reconnect = false;
                        this.doReconnect = false;
                    }
                    break;
                case 'titleFixed':
                    if (!value || value === '') return;
                    console.log(`[ttyd] setting fixed title: ${value}`);
                    this.titleFixed = value;
                    document.title = value;
                    break;
                case 'isWindows':
                    if (value) console.log('[ttyd] is windows');
                    break;
                case 'unicodeVersion':
                    switch (value) {
                        case 6:
                        case '6':
                            console.log('[ttyd] setting Unicode version: 6');
                            break;
                        case 11:
                        case '11':
                        default:
                            console.log('[ttyd] setting Unicode version: 11');
                            terminal.loadAddon(new Unicode11Addon());
                            terminal.unicode.activeVersion = '11';
                            break;
                    }
                    break;
                default:
                    console.log(`[ttyd] option: ${key}=${JSON.stringify(value)}`);
                    if (terminal.options[key] instanceof Object) {
                        terminal.options[key] = Object.assign({}, terminal.options[key], value);
                    } else {
                        terminal.options[key] = value;
                    }
                    if (key.indexOf('font') === 0) {
                        const targetCols = this.sessionCols ?? terminal.cols;
                        const targetRows = this.sessionRows ?? terminal.rows;
                        this.forceSessionGeometry(targetCols, targetRows);
                    }
                    break;
            }
        }
    }

    @bind
    private forceSessionGeometry(cols: number, rows: number) {
        if (!this.terminal) {
            return;
        }

        if (!Number.isFinite(cols) || !Number.isFinite(rows)) {
            return;
        }

        const targetCols = Math.max(1, Math.floor(cols));
        const targetRows = Math.max(1, Math.floor(rows));

        if (this.terminal.cols === targetCols && this.terminal.rows === targetRows) {
            return;
        }

        this.suppressClientResize = true;
        try {
            this.terminal.resize(targetCols, targetRows);
        } finally {
            this.suppressClientResize = false;
        }

        if (this.resizeOverlay) {
            this.overlayAddon.showOverlay(`${targetCols}x${targetRows}`, 300);
        }
    }

    @bind
    private applySessionResize(jsonData: string) {
        let payload: { columns?: number; rows?: number };
        try {
            payload = JSON.parse(jsonData);
        } catch (e) {
            console.warn('[ttyd] failed to parse session resize payload', e);
            return;
        }

        const { columns, rows } = payload;
        if (!Number.isFinite(columns) || !Number.isFinite(rows)) {
            console.warn('[ttyd] invalid session resize payload', payload);
            return;
        }

        const width = Math.max(1, Math.floor(columns!));
        const height = Math.max(1, Math.floor(rows!));

        if (this.sessionCols === width && this.sessionRows === height) {
            if (this.terminal && this.terminal.cols === width && this.terminal.rows === height) {
                return;
            }
        }

        this.sessionCols = width;
        this.sessionRows = height;
        this.forceSessionGeometry(width, height);
    }

    @bind
    private applySnapshot(jsonData: string) {
        const { terminal, socket, textEncoder } = this;
        let ackSent = false;

        try {
            const snapshot = JSON.parse(jsonData) as SnapshotPayload;
            this.applySnapshotModes(snapshot);
            console.log(
                `[ttyd] received snapshot: ${snapshot.lines.length} lines, cursor at (${snapshot.cursor_x},${snapshot.cursor_y})`
            );

            // Use proper ANSI sequences to render the snapshot
            // This ensures the terminal stays in a proper state for control sequences

            // Clear screen and move cursor to home: ESC[2J ESC[H
            terminal.write('\x1b[2J\x1b[H');

            // Write each line with proper ANSI positioning
            for (let i = 0; i < snapshot.lines.length; i++) {
                if (snapshot.lines[i].length > 0) {
                    // Position cursor at start of line (row is 1-indexed): ESC[row;1H
                    terminal.write(`\x1b[${i + 1};1H${snapshot.lines[i]}`);
                }
            }

            // Position cursor at the saved position (1-indexed): ESC[row;colH
            const row = snapshot.cursor_y + 1;
            const col = snapshot.cursor_x + 1;
            terminal.write(`\x1b[${row};${col}H`);

            console.log('[ttyd] snapshot applied successfully');

            // Send acknowledgment to server to unblock PTY output
            if (socket?.readyState === WebSocket.OPEN) {
                socket.send(textEncoder.encode(Command.SNAPSHOT_ACK));
                console.log('[ttyd] sent snapshot acknowledgment');
                ackSent = true;
            }
        } catch (e) {
            console.error('[ttyd] failed to apply snapshot:', e);
        } finally {
            if (!ackSent && socket?.readyState === WebSocket.OPEN) {
                socket.send(textEncoder.encode(Command.SNAPSHOT_ACK));
                console.log('[ttyd] sent snapshot acknowledgment after recoverable error');
            }
        }
    }

    @bind
    private applySnapshotModes(snapshot: SnapshotPayload) {
        const { terminal } = this;
        const state = {
            altScreen: undefined as boolean | undefined,
            showCursor: undefined as boolean | undefined,
            inverse: undefined as boolean | undefined,
            insertMode: undefined as boolean | undefined,
            originMode: undefined as boolean | undefined,
            autoWrap: undefined as boolean | undefined,
            cursorKeyMode: undefined as boolean | undefined,
            keypadApplication: undefined as boolean | undefined,
        };

        if (typeof snapshot.screen_flags === 'number') {
            const flags = snapshot.screen_flags;
            state.altScreen = (flags & ScreenFlag.ALTERNATE) !== 0;
            state.showCursor = (flags & ScreenFlag.HIDE_CURSOR) === 0;
            state.inverse = (flags & ScreenFlag.INVERSE) !== 0;
            state.insertMode = (flags & ScreenFlag.INSERT_MODE) !== 0;
        }

        if (typeof snapshot.vte_flags === 'number') {
            const flags = snapshot.vte_flags;
            state.cursorKeyMode = (flags & VteFlag.CURSOR_KEY_MODE) !== 0;
            state.keypadApplication = (flags & VteFlag.KEYPAD_APPLICATION_MODE) !== 0;
            state.originMode = (flags & VteFlag.ORIGIN_MODE) !== 0;
            state.autoWrap = (flags & VteFlag.AUTO_WRAP_MODE) !== 0;
            if (state.inverse === undefined) {
                state.inverse = (flags & VteFlag.INVERSE_SCREEN_MODE) !== 0;
            }
            if (state.showCursor === undefined) {
                state.showCursor = (flags & VteFlag.TEXT_CURSOR_MODE) !== 0;
            }
        }

        let controlSeq = '';
        const setDecPrivateMode = (code: number, enable: boolean | undefined) => {
            if (enable === undefined) return;
            controlSeq += `\x1b[?${code}${enable ? 'h' : 'l'}`;
        };
        const setMode = (code: number, enable: boolean | undefined) => {
            if (enable === undefined) return;
            controlSeq += `\x1b[${code}${enable ? 'h' : 'l'}`;
        };

        setDecPrivateMode(1049, state.altScreen);
        setDecPrivateMode(25, state.showCursor);
        setDecPrivateMode(5, state.inverse);
        setMode(4, state.insertMode);
        setDecPrivateMode(6, state.originMode);
        setDecPrivateMode(7, state.autoWrap);
        setDecPrivateMode(1, state.cursorKeyMode);

        if (state.keypadApplication !== undefined) {
            controlSeq += state.keypadApplication ? '\x1b=' : '\x1b>';
        }

        if (controlSeq !== '') {
            terminal.write(controlSeq);
        }
    }

    @bind
    private setRendererType(value: RendererType) {
        const { terminal } = this;
        const disposeCanvasRenderer = () => {
            try {
                this.canvasAddon?.dispose();
            } catch {
                // ignore
            }
            this.canvasAddon = undefined;
        };
        const disposeWebglRenderer = () => {
            try {
                this.webglAddon?.dispose();
            } catch {
                // ignore
            }
            this.webglAddon = undefined;
        };
        const enableCanvasRenderer = () => {
            if (this.canvasAddon) return;
            this.canvasAddon = new CanvasAddon();
            disposeWebglRenderer();
            try {
                this.terminal.loadAddon(this.canvasAddon);
                console.log('[ttyd] canvas renderer loaded');
            } catch (e) {
                console.log('[ttyd] canvas renderer could not be loaded, falling back to dom renderer', e);
                disposeCanvasRenderer();
            }
        };
        const enableWebglRenderer = () => {
            if (this.webglAddon) return;
            this.webglAddon = new WebglAddon();
            disposeCanvasRenderer();
            try {
                this.webglAddon.onContextLoss(() => {
                    this.webglAddon?.dispose();
                });
                terminal.loadAddon(this.webglAddon);
                console.log('[ttyd] WebGL renderer loaded');
            } catch (e) {
                console.log('[ttyd] WebGL renderer could not be loaded, falling back to canvas renderer', e);
                disposeWebglRenderer();
                enableCanvasRenderer();
            }
        };

        switch (value) {
            case 'canvas':
                enableCanvasRenderer();
                break;
            case 'webgl':
                enableWebglRenderer();
                break;
            case 'dom':
                disposeWebglRenderer();
                disposeCanvasRenderer();
                console.log('[ttyd] dom renderer loaded');
                break;
            default:
                break;
        }
    }
}

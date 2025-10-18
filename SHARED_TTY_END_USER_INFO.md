# Shared PTY Mode - End User Guide

## Overview

The new **Shared PTY Mode** feature allows multiple web browser clients to connect to a single shared terminal session, enabling real-time collaborative terminal sharing similar to tmux/screen but accessible through a web browser.

## Quick Start

### Basic Usage (Read-Only)

Share a terminal that multiple people can view:

```bash
ttyd --shared-pty bash
```

Then share the URL `http://localhost:7681` with others. All connected users will see the same terminal output in real-time.

### Collaborative Mode (Read-Write)

Allow multiple users to type in the shared terminal:

```bash
ttyd --shared-pty --writable bash
# or using short flags:
ttyd -Q -W bash
```

⚠️ **Warning**: In writable mode, all authenticated clients can send input. Coordinate who types to avoid confusion!

## Use Cases

### 1. Live Demonstrations & Presentations
```bash
# Read-only mode is perfect for demos
ttyd -Q -B bash
```
- Present code or terminal commands to an audience
- Viewers can't interfere with your commands
- `-B` flag automatically opens the browser

### 2. Pair Programming
```bash
# Writable mode for collaboration
ttyd -Q -W -c user1:pass1 bash
```
- Both programmers see the same terminal
- Both can type (coordinate via voice/chat)
- Basic authentication protects the session

### 3. Remote Teaching
```bash
# Teacher demonstrates, students watch
ttyd -Q -p 8080 bash
```
- Teacher runs commands
- Students follow along in their browsers
- No tmux/screen knowledge required

### 4. Debugging Sessions
```bash
# Multiple team members debug together
ttyd -Q -W -c team:secret bash
```
- Share debugging output in real-time
- Any team member can run diagnostic commands
- Everyone sees results immediately

### 5. One-Shot Demonstrations
```bash
# Show output of a single command to multiple viewers
ttyd -Q -o python demo_script.py
```
- Exits automatically after the script completes
- All viewers see the same output

## Installation & Download

### Pre-built Test Binaries

Download the test build from the GitHub Actions artifacts:

1. **Visit the GitHub Actions page:**
   ```
   https://github.com/eastlondoner/ttyd/actions/runs/18620671896
   ```

2. **Download your platform's binary** from the Artifacts section:
   - `ttyd.macos-arm64` - macOS Apple Silicon (M1/M2/M3)
   - `ttyd.macos-x86_64` - macOS Intel
   - `ttyd.x86_64` - Linux x86_64
   - `ttyd.aarch64` - Linux ARM64
   - `ttyd.armhf` - Linux ARM 32-bit
   - `ttyd.i686` - Linux 32-bit
   - `ttyd.win32` - Windows 32-bit
   - Plus MIPS and s390x variants

3. **Make it executable** (macOS/Linux):
   ```bash
   chmod +x ttyd
   ```

4. **Run it:**
   ```bash
   ./ttyd --shared-pty bash
   ```

### Build from Source

```bash
git clone https://github.com/eastlondoner/ttyd.git
cd ttyd
git checkout v1.7.8-shared-pty-test

# Install dependencies (macOS)
brew install cmake json-c libwebsockets libuv

# Build
mkdir build && cd build
cmake ..
make

# Test
./ttyd --shared-pty bash
```

See [BUILD_AND_TEST.md](BUILD_AND_TEST.md) for detailed build instructions.

## Command-Line Options

### Core Shared PTY Options

- `-Q, --shared-pty` - Enable shared PTY mode (required)
- `-W, --writable` - Allow clients to write to the terminal (default: read-only)
- `-m, --max-clients <n>` - Limit maximum number of clients (default: unlimited)
- `-q, --exit-no-conn` - Exit when all clients disconnect
- `-o, --once` - Exit after the process completes

### Useful Combinations

```bash
# Read-only demo with auto-open browser
ttyd -Q -B bash

# Collaborative session with authentication
ttyd -Q -W -c admin:password bash

# Limited to 5 clients
ttyd -Q -m 5 bash

# Exit when last client disconnects
ttyd -Q -q bash

# One-shot command for multiple viewers
ttyd -Q -o ls -la

# Custom port with SSL
ttyd -Q -p 8443 -S -C cert.pem -K key.pem bash

# Debug mode (verbose logging)
ttyd -Q -W -d 9 bash
```

## How It Works

### Architecture

**Standard Mode** (default):
```
Client 1 → PTY 1
Client 2 → PTY 2
Client 3 → PTY 3
```

**Shared PTY Mode** (`--shared-pty`):
```
Client 1 ↘
Client 2 → Shared PTY
Client 3 ↗
```

### Key Features

1. **Real-time Output Broadcasting**
   - PTY output is broadcast to all connected clients simultaneously
   - Efficient reference-counted buffers (no unnecessary copies)

2. **Merged Input** (when `-W` is used)
   - Input from any client is sent to the shared PTY
   - All clients see the input and output

3. **Smart Terminal Sizing**
   - Terminal dimensions use the maximum size across all clients
   - Ensures content isn't cropped for any viewer

4. **Graceful Disconnects**
   - Individual clients can disconnect without affecting others
   - When PTY process exits, all clients are notified and disconnected

5. **Buffer Overflow Protection**
   - Maximum 1MB per buffer broadcast
   - Maximum 512KB pending per client
   - Slow clients are disconnected to protect server resources

## Behavior & Limitations

### What Works

✅ Multiple clients viewing same output in real-time
✅ All clients can send input (when `-W` is enabled)
✅ Terminal resizing handles all client window sizes
✅ Clean client disconnect without affecting others
✅ Process exit closes all clients gracefully
✅ Authentication (`-c` flag) works normally
✅ SSL/TLS encryption (`-S` flag) works normally

### Limitations & Behavioral Changes

⚠️ **URL Arguments Not Supported**
- The `-a` flag (URL arguments) is not compatible with shared mode
- Only server-side command configuration is used

⚠️ **Shared Environment**
- All clients share the same environment variables
- `TTYD_USER` is set to the first authenticated client's username

⚠️ **Input Coordination Required**
- Multiple simultaneous writers can create confusing/garbled input
- Use external coordination (voice chat, screen sharing, etc.)

⚠️ **Terminal Sizing**
- Uses maximum dimensions from all clients
- Clients with small terminals may see scrolling for large content

⚠️ **Process Exit Affects All**
- When PTY process exits, ALL clients are disconnected
- One client typing `exit` closes the session for everyone

## Best Practices

### For Demonstrations (Read-Only)

```bash
# Recommended setup
ttyd -Q -B bash
```

**Do:**
- Use read-only mode (don't use `-W`)
- Start with browser auto-open (`-B`)
- Use authentication if sharing publicly (`-c user:pass`)

**Don't:**
- Don't enable writable mode for demos
- Don't share URLs publicly without authentication

### For Collaboration (Writable)

```bash
# Recommended setup
ttyd -Q -W -c team:secret bash
```

**Do:**
- Use authentication (`-c`) to restrict access
- Coordinate via voice/video chat
- Establish "typing rules" (take turns, announce before typing)
- Consider using with tmux for better multi-user control

**Don't:**
- Don't enable public writable access without authentication
- Don't type simultaneously without coordination

### For Production Use

```bash
# Recommended setup
ttyd -Q -W \
  -c admin:$(openssl rand -base64 12) \
  -S -C /path/to/cert.pem -K /path/to/key.pem \
  -m 10 \
  -q \
  bash
```

**Do:**
- Use strong authentication
- Enable SSL/TLS encryption
- Set max client limit (`-m`)
- Use `--exit-no-conn` for cleanup
- Monitor server logs (`-d 7` or higher)

**Don't:**
- Don't expose unencrypted sessions over public networks
- Don't use weak/default passwords
- Don't allow unlimited clients without monitoring

## Troubleshooting

### Issue: Garbled Input

**Symptom:** Multiple people typing creates gibberish

**Solution:**
- Establish typing coordination (take turns)
- Use voice/video chat to coordinate
- Consider tmux with proper access control instead

### Issue: Terminal Size Wrong

**Symptom:** Content is cropped or has too much whitespace

**Solution:**
- Ensure all clients use similar terminal window sizes
- First client to connect sets initial size
- Resize your browser window to trigger recalculation

### Issue: Client Disconnected Unexpectedly

**Symptom:** "Connection closed" or "Buffer overflow"

**Possible Causes:**
- Network connectivity issues
- Client fell too far behind in output consumption (buffer overflow)
- Server stopped or crashed

**Solution:**
- Check network connection
- Refresh browser to reconnect
- Check server logs with `-d 9` for details

### Issue: Permission Denied

**Symptom:** Can't type in terminal even with `-W` flag

**Possible Causes:**
- Not authenticated (when `-c` flag is used)
- Server not started with `-W` flag

**Solution:**
- Ensure you provided correct username/password
- Verify server started with `-W` or `--writable` flag

### Issue: Can't Connect

**Symptom:** Browser shows connection error

**Possible Causes:**
- Port already in use
- Firewall blocking connections
- Server not running

**Solution:**
```bash
# Check if server is running
ps aux | grep ttyd

# Check port availability
lsof -i :7681

# Try different port
ttyd -Q -p 8080 bash

# Check firewall settings
```

## Testing Shared PTY Mode

### Basic Test (Single Machine)

1. **Start ttyd:**
   ```bash
   ./ttyd -Q -W bash
   ```

2. **Open multiple browser tabs:**
   - Tab 1: http://localhost:7681
   - Tab 2: http://localhost:7681
   - Tab 3: http://localhost:7681

3. **Type in any tab:**
   ```bash
   echo "Hello from shared PTY!"
   ls -la
   ```

4. **Verify:** All tabs show the same output

### Network Test (Multiple Machines)

1. **Start ttyd on server:**
   ```bash
   ./ttyd -Q -W -c test:password bash
   ```

2. **Find server IP:**
   ```bash
   ifconfig | grep inet
   ```

3. **Connect from other machines:**
   ```
   http://<server-ip>:7681
   ```

4. **Authenticate** with username `test` and password `password`

5. **Test collaboration** by typing from different machines

## Advanced Usage

### With tmux for Better Control

```bash
# Start shared session with tmux
ttyd -Q -W tmux new -A -s shared

# Clients connect via browser
# Also connect directly via terminal:
tmux attach -t shared
```

Benefits:
- Better session persistence
- Individual pane control
- Tmux's built-in multi-user features

### With Custom Scripts

```bash
# Run a monitoring script for multiple viewers
ttyd -Q -o watch -n 1 "docker ps --format 'table {{.Names}}\t{{.Status}}'"
```

### With Docker

```bash
# Share a docker container session
ttyd -Q -W docker run -it ubuntu bash
```

### Behind Nginx Reverse Proxy

```nginx
location /terminal {
    proxy_pass http://localhost:7681;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 3600s;
}
```

Then start ttyd with:
```bash
ttyd -Q -W -b /terminal bash
```

## Security Considerations

### Authentication

**Always use authentication for shared writable sessions:**

```bash
# Generate random password
PASSWORD=$(openssl rand -base64 16)
echo "Password: $PASSWORD"
ttyd -Q -W -c admin:$PASSWORD bash
```

### Encryption

**Use SSL/TLS for network communication:**

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Start with SSL
ttyd -Q -W -S -C cert.pem -K key.pem bash
```

### Access Control

**Limit client connections:**

```bash
# Maximum 5 simultaneous clients
ttyd -Q -W -m 5 bash
```

**Exit when empty:**

```bash
# Kill process when last client disconnects
ttyd -Q -W -q bash
```

### Network Isolation

**Bind to specific interface:**

```bash
# Only listen on localhost
ttyd -Q -W -i lo bash

# Or specific IP
ttyd -Q -W -i 192.168.1.100 bash
```

## Version Information

- **Feature**: Shared PTY Mode
- **Flag**: `-Q, --shared-pty`
- **Version**: 1.7.8-shared-pty-test (commit 7ce4794)
- **Status**: Test build / Pre-release
- **Tag**: v1.7.8-shared-pty-test

## Getting Help

### Resources

- **GitHub Repository**: https://github.com/eastlondoner/ttyd
- **Test Build Actions**: https://github.com/eastlondoner/ttyd/actions/runs/18620671896
- **Implementation Plan**: See `SINGLE_TTY_PROCESS_PLAN.md` in repository
- **Build Instructions**: See `BUILD_AND_TEST.md` in repository

### Reporting Issues

If you encounter problems with shared PTY mode:

1. **Enable debug logging:**
   ```bash
   ttyd -Q -W -d 9 bash
   ```

2. **Reproduce the issue** and save the output

3. **Report on GitHub** with:
   - Command used to start ttyd
   - Number of clients connected
   - Expected vs actual behavior
   - Debug log output
   - Platform (macOS/Linux/Windows)

### Feature Status

This is a **test build** of the shared PTY feature. The functionality is:

- ✅ **Feature Complete**: All planned functionality implemented
- ✅ **Compiles Successfully**: Builds on all platforms
- ⏳ **Testing Phase**: Needs real-world usage testing
- ⏳ **Documentation**: Complete but may need refinement based on feedback

Feedback and bug reports are welcome!

## Credits

**Implementation**: Based on detailed design in `SINGLE_TTY_PROCESS_PLAN.md`

**Original ttyd Author**: Shuanglei Tao (tsl0922)

**Shared PTY Feature**: Implemented October 2025

---

*For more information about ttyd, visit the [main README](README.md)*

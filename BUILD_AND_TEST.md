# Build and Test Instructions

This document provides step-by-step instructions for building and testing ttyd from source on macOS.

## Prerequisites

### Required Dependencies

Before building ttyd, ensure you have the following dependencies installed:

1. **Xcode Command Line Tools**
   ```bash
   xcode-select --install
   ```

2. **Homebrew** (if not already installed)
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

3. **Build Dependencies**
   ```bash
   brew install cmake json-c libwebsockets libuv
   ```

### Verify Dependencies

Check that all required tools and libraries are installed:

```bash
which cmake          # Should output: /opt/homebrew/bin/cmake (or similar)
brew list | grep -E "(json-c|libwebsockets|libuv)"
```

## Building ttyd

### Step 1: Clone the Repository (if not already done)

```bash
git clone https://github.com/tsl0922/ttyd.git
cd ttyd
```

### Step 2: Create Build Directory

```bash
mkdir -p build
cd build
```

### Step 3: Run CMake Configuration

```bash
cmake ..
```

Expected output should include:
- Found LIBUV
- Found JSON-C
- Found ZLIB
- Found OpenSSL
- LWS_WITH_LIBUV - found
- Configuring done
- Generating done

### Step 4: Compile the Project

```bash
make
```

You should see compilation progress:
```
[ 16%] Building C object CMakeFiles/ttyd.dir/src/utils.c.o
[ 33%] Building C object CMakeFiles/ttyd.dir/src/pty.c.o
[ 50%] Building C object CMakeFiles/ttyd.dir/src/protocol.c.o
[ 66%] Building C object CMakeFiles/ttyd.dir/src/http.c.o
[ 83%] Building C object CMakeFiles/ttyd.dir/src/server.c.o
[100%] Linking C executable ttyd
[100%] Built target ttyd
```

### Step 5: Install (Optional)

To install ttyd system-wide:

```bash
sudo make install
```

This will install:
- Binary to `/usr/local/bin/ttyd`
- Man page to `/usr/local/share/man/man1/ttyd.1`

## Testing the Build

### Basic Verification Tests

1. **Check Version**
   ```bash
   ./ttyd --version
   ```
   Expected output: `ttyd version 1.7.7-eccebc6` (or similar)

2. **View Help**
   ```bash
   ./ttyd --help
   ```
   Should display all available command-line options.

3. **Verify Binary Type**
   ```bash
   file ./ttyd
   ```
   Expected: `Mach-O 64-bit executable arm64` (on Apple Silicon)

### Functional Tests

1. **Test with Simple Command**
   ```bash
   ./ttyd -p 7682 -o echo "Hello from ttyd"
   ```

   In another terminal, test the connection:
   ```bash
   curl http://localhost:7682/
   ```

   You should see HTML content from the ttyd web interface.

2. **Test with Interactive Shell**
   ```bash
   ./ttyd -p 7682 bash
   ```

   Open your browser and navigate to:
   ```
   http://localhost:7682
   ```

   You should see an interactive terminal in your browser.

3. **Test with Auto-open Browser**
   ```bash
   ./ttyd -B bash
   ```

   This should automatically open your default browser with the terminal interface.

### Common Test Scenarios

#### Test Read-only Mode (default)
```bash
./ttyd -p 7682 bash
```
Terminal will be read-only by default.

#### Test Writable Mode
```bash
./ttyd -W -p 7682 bash
```
Terminal will accept input from the web interface.

#### Test with Authentication
```bash
./ttyd -c username:password -p 7682 bash
```
Browser will prompt for credentials.

#### Test One-shot Mode
```bash
./ttyd -o -p 7682 ls -la
```
Server will exit after the first client disconnects.

## Troubleshooting

### CMake Cannot Find Dependencies

If CMake reports missing dependencies:

```bash
# Verify Homebrew installation paths
brew --prefix libwebsockets
brew --prefix json-c
brew --prefix libuv

# If needed, set CMAKE_PREFIX_PATH
CMAKE_PREFIX_PATH=/opt/homebrew cmake ..
```

### libwebsockets Not Built with libuv Support

If you see: `libwebsockets was not build with libuv support`

Reinstall libwebsockets with proper flags:
```bash
brew uninstall libwebsockets
brew install libwebsockets
```

### Port Already in Use

If port 7681 (default) or your chosen port is busy:

```bash
# Use a different port
./ttyd -p 8080 bash

# Or use random port (0)
./ttyd -p 0 bash
```

## Cleaning Up

To clean the build directory:

```bash
cd build
make clean
```

To remove all build artifacts:

```bash
cd ..
rm -rf build
```

## GitHub Actions Multi-Architecture Builds

The ttyd project uses GitHub Actions to automatically build binaries for multiple platforms and architectures. This is the **recommended approach** for creating distributable binaries.

### Supported Architectures

The GitHub Actions workflow builds binaries for:

**Linux (cross-compiled):**
- `ttyd.x86_64` - 64-bit Intel/AMD
- `ttyd.i686` - 32-bit Intel/AMD
- `ttyd.aarch64` - 64-bit ARM (e.g., Raspberry Pi 4, AWS Graviton)
- `ttyd.arm` - 32-bit ARM
- `ttyd.armhf` - ARM hard-float
- `ttyd.mips`, `ttyd.mipsel` - MIPS architectures
- `ttyd.mips64`, `ttyd.mips64el` - 64-bit MIPS
- `ttyd.s390x` - IBM System z

**macOS (native builds):**
- `ttyd.macos-arm64` - Apple Silicon (M1/M2/M3)
- `ttyd.macos-x86_64` - Intel Mac

**Windows:**
- `ttyd.win32.exe` - 32-bit Windows

**Additional files:**
- `SHA256SUMS` - Checksums for all binaries

### How the Build System Works

The build system consists of three GitHub Actions workflows:

1. **`.github/workflows/backend.yml`** - Builds all platform binaries
   - Linux builds use cross-compilation on Ubuntu runners
   - macOS builds use native compilation on macOS runners (macos-14 for ARM, macos-13 for Intel)
   - Windows builds use cross-compilation with MinGW

2. **`.github/workflows/release.yml`** - Creates releases
   - Triggered when you push a git tag
   - Calls the backend workflow to build all binaries
   - Validates that the tag matches the version in `CMakeLists.txt`
   - Creates a draft GitHub release with all binaries
   - Generates SHA256 checksums

3. **`.github/workflows/frontend.yml`** - Builds web interface (runs separately)

### Creating a Test Release

To create a test release without publishing:

```bash
# The tag name should NOT match the version pattern [0-9]*.[0-9]*.[0-9]*
# This will build everything but fail the version check (preventing publication)
git tag 1.7.7-test
git push origin 1.7.7-test

# Monitor the build progress
gh run list --limit 5

# Or watch a specific run
gh run watch <run-id>

# Download test binaries from artifacts (without creating a release)
gh run download <run-id>
```

### Creating a Production Release

To create an official release:

**Step 1: Update the version**

Edit `CMakeLists.txt` and update the version number:

```cmake
project(ttyd VERSION 1.7.8 LANGUAGES C)
```

**Step 2: Commit the version change**

```bash
git add CMakeLists.txt
git commit -m "Bump version to 1.7.8"
git push origin main
```

**Step 3: Create and push a matching tag**

```bash
# The tag MUST match the version in CMakeLists.txt exactly
git tag 1.7.8
git push origin 1.7.8
```

**Step 4: Monitor the build**

```bash
# View workflow runs
gh run list --limit 5

# Watch the release workflow
gh run watch --repo <your-repo>
```

The workflow takes approximately 3-5 minutes to complete all builds.

**Step 5: Review and publish the release**

Once the workflow completes:

```bash
# View the draft release
gh release view 1.7.8

# Or open in browser
gh release view 1.7.8 --web

# Publish the release when ready
gh release edit 1.7.8 --draft=false
```

### Downloading Release Binaries

**Download all binaries from a release:**

```bash
gh release download 1.7.7 --repo tsl0922/ttyd
```

**Download a specific binary:**

```bash
# For macOS ARM64
gh release download 1.7.7 --pattern 'ttyd.macos-arm64'

# For Linux x86_64
gh release download 1.7.7 --pattern 'ttyd.x86_64'

# For Windows
gh release download 1.7.7 --pattern 'ttyd.win32.exe'
```

**Verify checksums:**

```bash
# Download checksums
gh release download 1.7.7 --pattern 'SHA256SUMS'

# Verify a binary
sha256sum -c SHA256SUMS --ignore-missing
```

### Testing Downloaded Binaries

**On macOS:**

```bash
# Download
gh release download 1.7.7 --pattern 'ttyd.macos-arm64'

# Make executable
chmod +x ttyd.macos-arm64

# Verify it's a native binary
file ttyd.macos-arm64
# Should show: Mach-O 64-bit executable arm64

# Test
./ttyd.macos-arm64 --version
./ttyd.macos-arm64 -p 7682 bash
```

**On Linux:**

```bash
# Download appropriate architecture
gh release download 1.7.7 --pattern 'ttyd.x86_64'

# Make executable
chmod +x ttyd.x86_64

# Verify it's a Linux binary
file ttyd.x86_64
# Should show: ELF 64-bit LSB executable, x86-64

# Test
./ttyd.x86_64 --version
./ttyd.x86_64 -p 7681 bash
```

### Troubleshooting GitHub Actions Builds

**Build fails with version mismatch:**

```
Error: Version in CMakeLists.txt and git tag does not match!
Git Tag: 1.7.8, Version: 1.7.7
```

**Solution:** Make sure the tag name exactly matches the version in `CMakeLists.txt`:
- Edit `CMakeLists.txt` to update the version
- Commit and push the change
- Delete and recreate the tag:
  ```bash
  git tag -d 1.7.8
  git push origin :refs/tags/1.7.8
  git tag 1.7.8
  git push origin 1.7.8
  ```

**Build fails on macOS runner:**

Check that Homebrew dependencies are correctly specified in `.github/workflows/backend.yml`:
```yaml
brew install cmake json-c libwebsockets libuv
```

**Artifacts not appearing in release:**

The release is created as a draft. Artifacts are attached automatically. If missing:
1. Check the workflow run logs
2. Verify all build jobs completed successfully
3. Check the "publish" job completed without errors

**Need to rebuild a release:**

```bash
# Delete the release
gh release delete 1.7.7 --yes

# Delete the tag locally and remotely
git tag -d 1.7.7
git push origin :refs/tags/1.7.7

# Recreate and push the tag
git tag 1.7.7
git push origin 1.7.7
```

### Workflow Customization

The workflows can be customized by editing:

- `.github/workflows/backend.yml` - Add/remove architectures, change build flags
- `.github/workflows/release.yml` - Modify release creation behavior
- `scripts/cross-build.sh` - Customize cross-compilation settings

Always test workflow changes with a test tag before creating an official release.

## Building on Other Platforms

### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake git libjson-c-dev libwebsockets-dev
git clone https://github.com/tsl0922/ttyd.git
cd ttyd && mkdir build && cd build
cmake ..
make && sudo make install
```

### Windows

See the project wiki: [Compile on Windows](https://github.com/tsl0922/ttyd/wiki/Compile-on-Windows)

## Additional Resources

- Project README: [README.md](README.md)
- Example Usage: [Wiki - Example Usage](https://github.com/tsl0922/ttyd/wiki/Example-Usage)
- Report Issues: [GitHub Issues](https://github.com/tsl0922/ttyd/issues)

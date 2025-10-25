# Git Submodule Setup for libtsm

This document explains how to complete the conversion of libtsm from a nested git repository to a proper git submodule.

## What Was Done

1. ✅ Updated `.github/workflows/backend.yml` to checkout submodules
2. ✅ Updated `.github/workflows/release.yml` to checkout submodules
3. ✅ Updated `.github/workflows/frontend.yml` to checkout submodules
4. ✅ Updated `BUILD_AND_TEST.md` with comprehensive submodule documentation

## What You Need To Do

Run these commands to complete the submodule setup:

```bash
cd /Users/andy/repos/ttyd

# Remove libtsm from git index (it's currently tracked as a directory)
git rm --cached third_party/libtsm

# Remove the directory
rm -rf third_party/libtsm

# Add libtsm as a proper git submodule
git submodule add https://github.com/Aetf/libtsm.git third_party/libtsm

# Stage all changes
git add .gitmodules third_party/libtsm .github/workflows/ BUILD_AND_TEST.md

# Commit the changes
git commit -m "Convert libtsm to git submodule and update workflows

- Add libtsm as git submodule at third_party/libtsm
- Update all GitHub Actions workflows to checkout submodules recursively
- Add comprehensive submodule documentation to BUILD_AND_TEST.md
- Ensures CI builds will work properly with vendored dependencies"

# Push to your branch
git push origin shared-tty
```

## Verification Steps

After completing the setup, verify everything works:

### 1. Check Submodule Status

```bash
git submodule status
```

Expected output:
```
<commit-hash> third_party/libtsm (tag-or-branch)
```

### 2. View .gitmodules File

```bash
cat .gitmodules
```

Expected content:
```
[submodule "third_party/libtsm"]
	path = third_party/libtsm
	url = https://github.com/Aetf/libtsm.git
```

### 3. Test Local Build

```bash
# Clean and rebuild
rm -rf build
mkdir -p build && cd build
cmake ..
make

# Should compile successfully including libtsm sources
```

### 4. Test Fresh Clone

In a different directory, test that a fresh clone works:

```bash
cd /tmp
git clone --recurse-submodules https://github.com/YOUR_USERNAME/ttyd.git ttyd-test
cd ttyd-test

# Verify libtsm is populated
ls -la third_party/libtsm/
# Should show libtsm source files, not empty

# Build to verify
mkdir build && cd build
cmake ..
make
```

## Benefits of This Approach

1. **GitHub Actions Compatible**: CI will automatically fetch libtsm using `submodules: recursive`
2. **Standard Practice**: Git submodules are the standard way to vendor dependencies
3. **Easy Updates**: Can update libtsm with `git submodule update --remote`
4. **Clean Repository**: Keeps your repo size smaller since submodules are separate
5. **Version Pinning**: Submodule tracks specific commit, ensuring reproducible builds

## Troubleshooting

If you encounter issues:

### "fatal: already exists in the index"

```bash
git rm --cached -r third_party/libtsm
git rm -rf third_party/libtsm
```

### Submodule directory is empty

```bash
git submodule update --init --recursive
```

### Build fails with missing libtsm files

```bash
git submodule deinit -f .
git submodule update --init --recursive
cd build
cmake ..
make
```

## What Happens Next

Once you push these changes:

1. Future clones must use `git clone --recurse-submodules`
2. GitHub Actions will automatically fetch libtsm during builds
3. Other developers need to run `git submodule update --init --recursive` if they already have the repo cloned

This is documented in the updated BUILD_AND_TEST.md file.

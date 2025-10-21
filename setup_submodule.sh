#!/bin/bash
set -e

echo "Setting up libtsm as a git submodule..."

# Navigate to repo root
cd /Users/andy/repos/ttyd

# Remove from git index if tracked
echo "Removing libtsm from git index..."
git rm --cached -r third_party/libtsm 2>/dev/null || echo "Not in index, continuing..."

# Remove directory
echo "Removing libtsm directory..."
rm -rf third_party/libtsm

# Add as submodule
echo "Adding libtsm as submodule..."
git submodule add https://github.com/Aetf/libtsm.git third_party/libtsm

echo "Submodule setup complete!"
echo ""
echo "Next steps:"
echo "1. git add .gitmodules third_party/libtsm"
echo "2. git commit -m 'Convert libtsm to git submodule'"

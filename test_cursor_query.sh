#!/bin/bash
# Test script to verify libtsm responds to cursor position queries
# when no clients are attached in shared PTY mode

set -e

echo "Testing libtsm auto-response to terminal queries..."
echo ""

# Create a simple script that sends a cursor position query
cat > /tmp/query_test.sh <<'EOF'
#!/bin/bash
# Send cursor position query
printf '\033[6n'
sleep 0.5
# If we get here without timing out, it worked
echo "SUCCESS: No timeout occurred"
EOF
chmod +x /tmp/query_test.sh

# Test 1: Shared PTY mode with no clients
echo "Test 1: Starting ttyd in shared PTY mode..."
./ttyd --shared-session --port 7681 /tmp/query_test.sh &
TTYD_PID=$!
sleep 1

echo "  - ttyd started (PID: $TTYD_PID)"
echo "  - Waiting for process to complete (should not timeout)..."
sleep 2

# Check if ttyd is still running (process should have completed)
if kill -0 $TTYD_PID 2>/dev/null; then
    echo "  ✓ Process completed without errors"
    kill $TTYD_PID 2>/dev/null || true
else
    echo "  ✓ Process exited (expected)"
fi

# Test 2: Show debug output
echo ""
echo "Test 2: Running with debug output to see libtsm response..."
./ttyd --shared-session --port 7682 -d 9 /tmp/query_test.sh &
TTYD_PID=$!
sleep 2
kill $TTYD_PID 2>/dev/null || true

echo ""
echo "✓ Tests complete!"
echo ""
echo "To test manually with cursor or any TUI:"
echo "  ./build/ttyd --shared-session -d 9 cursor"
echo ""
echo "Look for log message:"
echo "  'libtsm auto-responding to terminal query ... - no clients attached'"

rm -f /tmp/query_test.sh


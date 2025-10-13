#!/bin/bash
# Script to check if external-proofs metrics are being recorded

set -e

METRICS_PORT="${METRICS_PORT:-9001}"
METRICS_URL="http://localhost:${METRICS_PORT}/metrics"

echo "Checking metrics at ${METRICS_URL}..."
echo

# Check if metrics endpoint is available
if ! curl -s "${METRICS_URL}" > /dev/null; then
    echo "❌ ERROR: Cannot reach metrics endpoint at ${METRICS_URL}"
    echo "   Make sure the node is running with --metrics flag"
    echo "   Example: op-reth node --metrics localhost:9001"
    exit 1
fi

echo "✅ Metrics endpoint is reachable"
echo

# Fetch all metrics
METRICS=$(curl -s "${METRICS_URL}")

# Check for external_proofs metrics
echo "=== Checking for external_proofs metrics ==="
echo

EXTERNAL_PROOFS_METRICS=$(echo "$METRICS" | grep "^external_proofs" | grep -v "^#" || true)

if [ -z "$EXTERNAL_PROOFS_METRICS" ]; then
    echo "❌ No external_proofs metrics found"
    echo
    echo "This could mean:"
    echo "  1. The ExEx hasn't run yet (no blocks processed)"
    echo "  2. Metrics descriptions haven't been called"
    echo "  3. The storage wrapper isn't being used"
    exit 1
fi

echo "✅ Found external_proofs metrics!"
echo

# Show all external_proofs metrics
echo "=== All external_proofs metrics ==="
echo "$EXTERNAL_PROOFS_METRICS"
echo

# Check for non-zero values
echo "=== Non-zero metrics ==="
NON_ZERO=$(echo "$EXTERNAL_PROOFS_METRICS" | grep -v " 0$" | grep -v "_bucket{" | grep -v "_count " | grep -v "_sum " || true)

if [ -z "$NON_ZERO" ]; then
    echo "⚠️  All metrics are showing zero"
    echo
    echo "Possible reasons:"
    echo "  1. No blocks have been processed yet"
    echo "  2. All operations are happening too fast (< 1 microsecond)"
    echo "  3. Operations haven't been performed yet"
    echo
    echo "Try processing a block and check again"
else
    echo "$NON_ZERO"
    echo
    echo "✅ SUCCESS: Metrics are being recorded with non-zero values!"
fi

echo
echo "=== Summary Statistics ==="

# Count operations
TOTAL_OPS=$(echo "$METRICS" | grep "external_proofs_storage_operation_duration_seconds_count" | awk '{sum += $2} END {print sum}')
echo "Total storage operations: ${TOTAL_OPS:-0}"

# Show operation breakdown by type
echo
echo "Operations by type:"
echo "$METRICS" | grep "external_proofs_storage_operation_duration_seconds_count{" | while read -r line; do
    OPERATION=$(echo "$line" | sed -n 's/.*operation="\([^"]*\)".*/\1/p')
    COUNT=$(echo "$line" | awk '{print $2}')
    if [ "$COUNT" != "0" ]; then
        echo "  - $OPERATION: $COUNT"
    fi
done

# Show block processing stats
BLOCKS_PROCESSED=$(echo "$METRICS" | grep "external_proofs_block_total_duration_seconds_count " | awk '{print $2}')
if [ -n "$BLOCKS_PROCESSED" ] && [ "$BLOCKS_PROCESSED" != "0" ]; then
    echo
    echo "Blocks processed: $BLOCKS_PROCESSED"
fi

echo
echo "=== To monitor in real-time ==="
echo "watch -n 1 'curl -s ${METRICS_URL} | grep external_proofs | grep -v \"^#\"'"


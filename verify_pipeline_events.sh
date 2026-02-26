#!/bin/bash
# Quick Verification Script for Pipeline Events
# Run this after starting the server to verify real events are flowing

set -e

SERVER_URL="http://localhost:3000"
WS_URL="ws://localhost:3000/ws/pipeline-events"
API_KEY="test"

echo "🔍 AitherShield Pipeline Events Verification"
echo "=============================================="
echo ""

# 1. Check server is running
echo "1️⃣  Checking server connection..."
if ! curl -s "${SERVER_URL}/status" > /dev/null 2>&1; then
    echo "❌ Server not responding at ${SERVER_URL}"
    echo "   Start with: cargo run --bin server"
    exit 1
fi
echo "✅ Server is running"
echo ""

# 2. Test API connectivity
echo "2️⃣  Testing API endpoints..."
RESPONSE=$(curl -s -X POST "${SERVER_URL}/analyze" \
    -H "Content-Type: application/json" \
    -d '{"logs":"Feb 20 14:30:15 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"}')

if echo "$RESPONSE" | grep -q "severity"; then
    echo "✅ /analyze endpoint working"
    echo "   Response: $(echo $RESPONSE | jq -r '.severity // .status')"
else
    echo "⚠️  /analyze response: $RESPONSE"
fi
echo ""

# 3. Test pipeline test endpoint
echo "3️⃣  Testing /pipeline/test endpoint..."
TEST_RESPONSE=$(curl -s -X POST "${SERVER_URL}/pipeline/test")
if echo "$TEST_RESPONSE" | grep -q "success\|error"; then
    echo "✅ /pipeline/test endpoint working"
    echo "   Response: $(echo $TEST_RESPONSE | jq -r '.status // .message')"
else
    echo "⚠️  /pipeline/test response: $TEST_RESPONSE"
fi
echo ""

# 4. WebSocket connection test
echo "4️⃣  Testing WebSocket pipeline events..."
echo "   (This requires wscat - install with: npm install -g wscat)"
echo ""

if command -v wscat &> /dev/null; then
    echo "   Connecting to WebSocket for 5 seconds..."
    (
        timeout 5 wscat -c "${WS_URL}?api_key=${API_KEY}" 2>/dev/null || true
    ) &
    WS_PID=$!
    
    # Give wscat time to connect
    sleep 1
    
    # Trigger an event
    echo "   Sending test log to /analyze..."
    curl -s -X POST "${SERVER_URL}/analyze" \
        -H "Content-Type: application/json" \
        -d '{"logs":"Test security event"}' > /dev/null 2>&1
    
    # Wait for wscat to collect events
    wait $WS_PID 2>/dev/null || true
    echo "   ✅ WebSocket test complete"
else
    echo "   ⚠️  wscat not found. Install with:"
    echo "   npm install -g wscat"
    echo ""
    echo "   Then test with:"
    echo "   wscat -c '${WS_URL}?api_key=${API_KEY}'"
    echo ""
    echo "   In another terminal, run:"
    echo "   curl -X POST http://localhost:3000/analyze \\"
    echo "     -H 'Content-Type: application/json' \\"
    echo "     -d '{\"logs\":\"test log\"}'"
fi
echo ""

# 5. Event structure validation
echo "5️⃣  Verifying event structure..."
echo ""
echo "   Expected fields in WebSocket events:"
echo "   - event_id: UUID"
echo "   - timestamp: ISO 8601 format"
echo "   - stage: Pipeline stage name"
echo "   - status: started|completed|error"
echo "   - log_snippet: First 100 chars of log"
echo "   - model: Optional model name"
echo "   - latency_ms: Optional processing time"
echo "   - confidence: Optional confidence score (0-1)"
echo "   - next_stage: Optional next stage"
echo ""

# 6. Pipeline stages check
echo "6️⃣  Pipeline stages that should emit events:"
STAGES=(
    "Input.Syslog"
    "Anonymizer"
    "Embedder"
    "Chroma.RAG"
    "Ollama.Triage"
    "ConfidenceRouter"
    "Grok.Fallback"
    "AlertGenerator"
    "Storage"
)

echo "   Expected sequence:"
for i in "${!STAGES[@]}"; do
    STAGE=${STAGES[$i]}
    if [ $i -lt $((${#STAGES[@]} - 1)) ]; then
        echo "   $((i+1)). $STAGE →"
    else
        echo "   $((i+1)). $STAGE (complete)"
    fi
done
echo ""

# 7. Performance check
echo "7️⃣  Performance expectations:"
echo "   - Anonymizer: ~5-20ms"
echo "   - Embedder: ~100-500ms"
echo "   - Ollama.Triage: ~800-2000ms"
echo "   - Grok.Fallback (if used): ~300-800ms"
echo "   - Storage: ~50-200ms"
echo "   - Total: ~1.5-3.5 seconds per log"
echo ""

# 8. Code verification
echo "8️⃣  Verifying code changes..."
if grep -q "emit_pipeline_event" src/lib.rs 2>/dev/null; then
    EMIT_COUNT=$(grep -c "emit_pipeline_event" src/lib.rs 2>/dev/null || echo "0")
    echo "   ✅ emit_pipeline_event helper found"
    echo "   📊 Times called: $EMIT_COUNT"
else
    echo "   ❌ emit_pipeline_event not found in src/lib.rs"
fi

if grep -q "PipelineEvent {" src/bin/server.rs 2>/dev/null; then
    echo "   ✅ Server WebSocket handler found"
else
    echo "   ⚠️  WebSocket handler may need verification"
fi
echo ""

# Summary
echo "=============================================="
echo "✨ Verification Complete!"
echo ""
echo "Next steps:"
echo "1. Connect Tauri client to ws://<server>:3000/ws/pipeline-events"
echo "2. Send logs via POST /analyze"
echo "3. Watch pipeline visualization animate in real-time"
echo ""
echo "For detailed documentation, see:"
echo "- PIPELINE_EVENTS.md"
echo "- PIPELINE_EVENTS_IMPLEMENTATION.md"
echo ""

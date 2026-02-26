# Quick Reference - Real Pipeline Events Testing

## 🎬 Run This Now (Copy & Paste)

### **Terminal 1: Start Server**
```bash
cd /home/dgraham/repos/aithershield
cargo run --bin server
```

**Watch for**:
```
🚀 AitherShield API server listening on http://0.0.0.0:3000
📡 WebSocket endpoint: ws://0.0.0.0:3000/ws/pipeline-events
🔐 API Key configured (32 characters)
```

---

### **Terminal 2: Connect WebSocket**
```bash
wscat -c "ws://localhost:3000/ws/pipeline-events?api_key=iZqHX9Wvej48W9raV7J33bgBsOgzJ3Ui"
```

**Should show**:
```
Connected (press CTRL+C to quit)
> 
```

---

### **Terminal 3: Test #1 - Real Log**
```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"logs":"Mar 5 12:34:56 host sshd[1234]: Failed password for invalid user hacker from 192.168.1.100"}'
```

---

## 📋 Expected Outputs

### Terminal 1 Output (Server Console)
```
📊 [Input.Syslog] Started
📊 [Anonymizer] Completed - (12ms)
📊 [Embedder] Completed - nomic-embed-text (287ms)
📊 [Chroma.RAG] Completed - (0ms)
📊 [Ollama.Triage] Completed - qwen2.5:14b-instruct (1240ms, confidence: 0.92)
📊 [ConfidenceRouter] Completed - (confidence: 0.92)
📊 [AlertGenerator] Completed - (confidence: 0.92)
📊 [Storage] Completed - (0ms)
```

### Terminal 2 Output (WebSocket - raw JSON)
```json
{"event_id":"550e8400","timestamp":"2025-02-23T10:30:45.001Z","stage":"Input.Syslog","status":"started","log_snippet":"Mar 5 12:34:56 host sshd[1234]: Failed password","model":null,"latency_ms":null,"confidence":null,"next_stage":"Anonymizer"}

{"event_id":"550e8401","timestamp":"2025-02-23T10:30:45.013Z","stage":"Anonymizer","status":"completed","log_snippet":"Mar 5 12:34:56 host sshd[1234]: Failed password for invalid user [USER] from [IP]","model":null,"latency_ms":12,"confidence":null,"next_stage":"Embedder"}

{"event_id":"550e8402","timestamp":"2025-02-23T10:30:45.250Z","stage":"Embedder","status":"completed","log_snippet":"...","model":"nomic-embed-text","latency_ms":287,"confidence":null,"next_stage":"Chroma.RAG"}

... (5 more events) ...

{"event_id":"550e8407","timestamp":"2025-02-23T10:30:46.650Z","stage":"Storage","status":"completed","log_snippet":"...","model":null,"latency_ms":null,"confidence":null,"next_stage":null}
```

### Terminal 3 Output (cURL Response)
```json
{
  "severity": "High",
  "confidence": 0.92,
  "summary": "Possible brute force SSH attack - failed login attempt from external IP"
}
```

---

## 🧪 Test #2 - Pipeline Test Button

```bash
curl -X POST http://localhost:3000/pipeline/test
```

**Response**:
```json
{
  "status": "success",
  "message": "Pipeline test completed",
  "result": {
    "severity": "High",
    "confidence": 0.89,
    "summary": "Failed SSH login - potential brute force attempt"
  }
}
```

**Server console (Terminal 1)** - Same 📊 logs as Test #1

---

## 🎯 Verify Each Part Works

### Part 1: Server Running?
```bash
curl http://localhost:3000/status | jq
```
**Expected**: `{"alerts_count": 0, "analyses_count": 1, ...}`

### Part 2: Endpoint Responding?
```bash
curl -X POST http://localhost:3000/pipeline/test | jq
```
**Expected**: `{"status": "success", ...}`

### Part 3: WebSocket Connected?
In Terminal 2, type anything → should see error or nothing (WebSocket expects JSON)

### Part 4: Real Events?
Check Terminal 1 for 📊 logs after sending log in Terminal 3

---

## 🔍 Inspect Individual Events

### Get All Events (Pretty Printed)
```bash
# In Terminal 2, add this to parse events nicely
wscat -c "ws://localhost:3000/ws/pipeline-events?api_key=" | jq '.'
```

### Parse Specific Fields
```bash
# Only show stage and latency
wscat -c "..." | jq '{stage: .stage, latency_ms: .latency_ms, model: .model}'
```

### Count Events
```bash
# Count events in Terminal 2
# Should be 8 for normal flow, 9 if Grok is used
```

---

## 📊 Event Field Reference

**Each WebSocket event has these fields**:

| Field | Type | Example | Always? |
|-------|------|---------|---------|
| event_id | string | "550e8400-e29b-41d4" | Yes |
| timestamp | string | "2025-02-23T10:30:45Z" | Yes |
| stage | string | "Ollama.Triage" | Yes |
| status | string | "completed" | Yes |
| log_snippet | string | "Failed password..." | Yes |
| model | string? | "qwen2.5:14b" | Only for LLM stages |
| latency_ms | number? | 1240 | Only for timed stages |
| confidence | number? | 0.92 | Only for decision stages |
| next_stage | string? | "ConfidenceRouter" | No (null on final stage) |

---

## 🎯 Stage Sequence

Normal flow (high confidence):
```
Input.Syslog
  ↓
Anonymizer
  ↓
Embedder
  ↓
Chroma.RAG
  ↓
Ollama.Triage (confidence: 0.92)
  ↓
ConfidenceRouter (routes to AlertGenerator)
  ↓
AlertGenerator
  ↓
Storage
```

Low confidence flow (triggers Grok):
```
Input.Syslog
  ↓
Anonymizer
  ↓
Embedder
  ↓
Chroma.RAG
  ↓
Ollama.Triage (confidence: 0.58)
  ↓
ConfidenceRouter (routes to Grok.Fallback)
  ↓
Grok.Fallback (confidence: 0.87)
  ↓
AlertGenerator
  ↓
Storage
```

---

## ⚡ Quick Curl Tests

### Test 1: Simple Log
```bash
curl -X POST http://localhost:3000/analyze -H "Content-Type: application/json" \
  -d '{"logs":"test event"}'
```

### Test 2: SSH Attack
```bash
curl -X POST http://localhost:3000/analyze -H "Content-Type: application/json" \
  -d '{"logs":"Mar 5 12:34:56 host sshd[1234]: Failed password for invalid user admin from 192.168.1.100"}'
```

### Test 3: Firewall Event
```bash
curl -X POST http://localhost:3000/analyze -H "Content-Type: application/json" \
  -d '{"logs":"Mar 5 12:34:56 host BLOCKED inbound connection from 10.0.0.1:PORT on interface eth0"}'
```

### Test 4: Multiple Logs (JSON array)
```bash
curl -X POST http://localhost:3000/analyze -H "Content-Type: application/json" \
  -d '{"logs":"Log 1\nLog 2\nLog 3"}'
```

---

## 🧪 WebSocket Message Format

### Client Receives Events Like:
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-02-23T10:30:46.540Z",
  "stage": "Ollama.Triage",
  "status": "completed",
  "log_snippet": "Mar 5 12:34:56 host sshd[1234]: Failed password for invalid user [USER] from [IP]",
  "model": "qwen2.5:14b-instruct-q5_K_M",
  "latency_ms": 1240,
  "confidence": 0.92,
  "next_stage": "ConfidenceRouter"
}
```

### Parse in JavaScript:
```javascript
const event = JSON.parse(message.data);
console.log(`Stage: ${event.stage}, Latency: ${event.latency_ms}ms, Confidence: ${event.confidence}`);
// Output: Stage: Ollama.Triage, Latency: 1240ms, Confidence: 0.92
```

### Parse in Rust:
```rust
let event: PipelineEvent = serde_json::from_str(&message)?;
println!("Stage: {}, Latency: {:?}ms", event.stage, event.latency_ms);
```

---

## 🎨 What to Show in Your Graph

For each event, your Tauri client should:

1. **Draw a node** for the stage
   - Label: `stage` name
   - Color: based on `status` (green=completed, red=error)

2. **Add edge from previous stage** with latency label
   - Label: `latency_ms` (if present)
   - Example: "1240ms"

3. **Add model badge** (if present)
   - Example: "qwen2.5:14b" next to node

4. **Add confidence indicator** (for decision stages)
   - Example: "0.92" at ConfidenceRouter

5. **Animate** the traversal
   - Each event = stage becoming active
   - Final event = complete

---

## 🚨 Troubleshooting

**No 📊 logs in Terminal 1?**
- Is cURL in Terminal 3 actually running?
- Try: `curl http://localhost:3000/status`

**No JSON in Terminal 2?**
- Reconnect wscat
- Make sure Terminal 1 is showing connected message
- Try a new log in Terminal 3

**"Connection refused"?**
- Is Terminal 1 still running? Check for `listen on http://0.0.0.0:3000`
- Try: `lsof -i :3000` to see what's using port 3000

**Long latency (>3s)?**
- Normal on first run (model loading)
- Check Ollama running: `ollama status`

**Missing stages?**
- Embedding errors? Check Chroma running
- Storage errors? Check Elasticsearch running (optional)

---

## 🎁 Copy-Paste Commands

### All 3 Terminals At Once

**Run all three in separate terminals**:

```bash
# Terminal 1
cd /home/dgraham/repos/aithershield && cargo run --bin server

# Terminal 2  
wscat -c "ws://localhost:3000/ws/pipeline-events?api_key=iZqHX9Wvej48W9raV7J33bgBsOgzJ3Ui"

# Terminal 3 (send one at a time, watch Terminals 1 & 2)
curl -X POST http://localhost:3000/analyze -H "Content-Type: application/json" -d '{"logs":"Mar 5 12:34:56 host sshd[1234]: Failed password for invalid user hacker from 192.168.1.100"}'
```

---

## ✅ Success Criteria

✓ Terminal 1 shows `🚀 AitherShield API server`  
✓ Terminal 2 shows `Connected (press CTRL+C to quit)`  
✓ Terminal 3 cURL returns JSON with severity + confidence  
✓ Terminal 1 shows 📊 logs (8-9 lines)  
✓ Terminal 2 shows JSON events (8-9 events)  
✓ Each 📊 line matches a WebSocket event  

**If all 5 ✓ → REAL EVENTS WORKING!** 🎉

---

## 🎯 Next: Tauri Integration

Once you confirm events are flowing:

1. Copy this event structure into your client:
```typescript
interface PipelineEvent {
  event_id: string;
  timestamp: string;
  stage: string;
  status: "started" | "completed" | "error";
  log_snippet: string;
  model?: string;
  latency_ms?: number;
  confidence?: number;
  next_stage?: string;
}
```

2. Create WebSocket connection:
```typescript
const ws = new WebSocket(`ws://localhost:3000/ws/pipeline-events?api_key=${apiKey}`);
ws.onmessage = (event) => {
  const pipelineEvent: PipelineEvent = JSON.parse(event.data);
  updateGraph(pipelineEvent);
};
```

3. Draw the graph based on events

---

**That's it! You now have real pipeline events!** 🚀

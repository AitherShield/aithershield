# Real-Time Pipeline Events Guide

## Overview

The AitherShield SIEM system now emits detailed real-time pipeline events for every log that traverses the analysis stages. This enables the Tauri client to visualize the actual processing flow with rich metrics.

## Architecture

### Broadcast Channel
All pipeline events flow through a `tokio::sync::broadcast` channel (`pipeline_tx`) in the server's `App` struct. This allows multiple WebSocket clients to subscribe simultaneously.

### Event Emission Helper
The `emit_pipeline_event()` function (in `src/lib.rs`) centralizes all event creation and transmission:

```rust
fn emit_pipeline_event(
    tx: &Option<&broadcast::Sender<PipelineEvent>>,
    stage: &str,
    status: PipelineStatus,
    log_snippet: &str,
    model: Option<String>,
    latency_ms: Option<u64>,
    confidence: Option<f32>,
    next_stage: Option<&str>,
)
```

**Parameters:**
- `tx`: Optional broadcast sender reference  
- `stage`: Stage identifier (e.g., `"Input.Syslog"`, `"Ollama.Triage"`)
- `status`: `Started`, `Completed`, or `Error`
- `log_snippet`: First 100 characters of the processed log
- `model`: Model name (e.g., `"qwen2.5:14b-instruct-q5_K_M"`, `"grok-4-1-fast"`)
- `latency_ms`: Processing time in milliseconds (useful for performance visualization)
- `confidence`: Triage confidence score (0.0-1.0)
- `next_stage`: Expected next stage in pipeline

### Pipeline Stages

Each log goes through these stages, emitting events at start/end:

1. **Input.Syslog** → Raw log ingestion
2. **Anonymizer** → PII masking (emails, IPs, usernames)
3. **Embedder** → Vector embedding generation
4. **Chroma.RAG** → Semantic context retrieval
5. **Ollama.Triage** → Primary LLM analysis
6. **ConfidenceRouter** → Routes based on confidence threshold
7. **Grok.Fallback** → Secondary LLM (if confidence < threshold)
8. **AlertGenerator** → Alert decisions
9. **Storage** → Vector database persistence

## Usage

### Real Log Processing via `/analyze`

Send a log to the analyze endpoint:

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"logs":"Feb 20 14:30:15 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"}'
```

All 9 pipeline stages will emit events to connected WebSocket clients.

### Pipeline Test via `/pipeline/test`

Trigger a full pipeline test with a synthetic log:

```bash
curl -X POST http://localhost:3000/pipeline/test
```

This uses a realistic authentication failure log and emits real processing events through all stages.

### WebSocket Connection

Connect to receive real-time pipeline events:

```bash
# Basic connection
wscat -c ws://localhost:3000/ws/pipeline-events?api_key=YOUR_API_KEY

# Or with Authorization header
wscat -c ws://localhost:3000/ws/pipeline-events
# Then send: Authorization: Bearer YOUR_API_KEY
```

## Event Flow Examples

### Successful High-Confidence Log

```json
{
  "event_id": "a1b2c3d4",
  "timestamp": "2025-02-23T10:30:45Z",
  "stage": "Input.Syslog",
  "status": "started",
  "log_snippet": "Failed password for invalid user admin from 192.168.1.100",
  "model": null,
  "latency_ms": null,
  "confidence": null,
  "next_stage": "Anonymizer"
}
```

→ Anonymizer processes (23ms)...

```json
{
  "event_id": "b2c3d4e5",
  "timestamp": "2025-02-23T10:30:45Z",
  "stage": "Ollama.Triage",
  "status": "completed",
  "log_snippet": "Failed password for invalid user [USER] from [IP]",
  "model": "qwen2.5:14b-instruct",
  "latency_ms": 1240,
  "confidence": 0.92,
  "next_stage": "ConfidenceRouter"
}
```

### Low-Confidence Fallback to Grok

```json
{
  "event_id": "c3d4e5f6",
  "timestamp": "2025-02-23T10:30:46Z",
  "stage": "ConfidenceRouter",
  "status": "completed",
  "log_snippet": "Ambiguous security event...",
  "model": null,
  "latency_ms": null,
  "confidence": 0.58,
  "next_stage": "Grok.Fallback"
}
```

→ Grok analyzes (567ms) and provides higher confidence...

```json
{
  "event_id": "d4e5f6g7",
  "timestamp": "2025-02-23T10:30:47Z",
  "stage": "Grok.Fallback",
  "status": "completed",
  "log_snippet": "Ambiguous security event...",
  "model": "grok-4-1-fast",
  "latency_ms": 567,
  "confidence": 0.85,
  "next_stage": "AlertGenerator"
}
```

## Implementation Details

### Where Events Are Emitted

**File:** `src/lib.rs`

#### Stage 1: Input.Syslog (line ~610)
```rust
emit_pipeline_event(
    &event_tx,
    "Input.Syslog",
    PipelineStatus::Started,
    &log_snippet,
    None, None, None,
    Some("Anonymizer"),
);
```

#### Stage 2: Anonymizer (line ~622)
```rust
let start_time = std::time::Instant::now();
let (sanitized, _masked) = ingestion::anonymize_log(log_entry);
let anonymize_latency = start_time.elapsed().as_millis() as u64;

emit_pipeline_event(
    &event_tx,
    "Anonymizer",
    PipelineStatus::Completed,
    &sanitized_snippet,
    None,
    Some(anonymize_latency),
    None,
    Some("Embedder"),
);
```

#### Stage 3: Embedder (line ~642)
- Latency captured from embedding generation
- Model: `self.embedding_model` (default: `"nomic-embed-text"`)
- May emit Error status if embedding fails

#### Stage 4: Chroma.RAG (line ~675)
- Retrieves context from vector database
- Completes before Triage begins

#### Stage 5: Ollama.Triage (line ~689)
- Primary model analysis starts
- Latency shows full inference time
- Confidence score from model output
- Model: `self.model`

#### Stage 6: ConfidenceRouter (line ~706)
- Decision point: compare against threshold
- Routes to either AlertGenerator or Grok.Fallback

#### Stage 7: Grok.Fallback (line ~714-733)
- Triggered if confidence < threshold
- Second inference with different model
- Model: `grok_model` ('grok-4-1-fast' or custom)
- Shows results comparison

#### Stage 8: AlertGenerator (line ~742)
- Alert decision stage
- Uses final confidence from triage (or Grok if used)

#### Stage 9: Storage (line ~758)
- Vector embedding stored in Chroma
- Final stage with no next_stage

### Error Handling

When a stage errors, it emits:
```rust
emit_pipeline_event(
    &event_tx,
    "Embedder",      // example
    PipelineStatus::Error,
    &snippet,
    Some(model_name),
    Some(elapsed_ms),
    None,            // no confidence on error
    None,            // no next stage on error
);
```

## Client Visualization

The Tauri client subscribes to WebSocket events and visualizes:

1. **Timeline View**: Each stage as a node with latency labels
2. **Model Info**: Shows which model processed each stage
3. **Confidence Progression**: Displays confidence at decision points
4. **Error Highlighting**: Red nodes for failed stages
5. **Latency Graph**: Performance metrics for optimization

### Recommended Client Updates

```rust
// WebSocket message handler
if let Ok(event) = serde_json::from_str::<PipelineEvent>(&msg) {
    match event.stage.as_str() {
        s if s.starts_with("Input.") => {
            // Mark log entering pipeline
            add_pipeline_node(event, NodeType::Input);
        }
        s if s.contains("Triage") || s == "Grok.Fallback" => {
            // Show model processing with latency
            add_pipeline_node(event, NodeType::LLMInference {
                model: event.model,
                latency: event.latency_ms,
                confidence: event.confidence,
            });
        }
        s if s == "ConfidenceRouter" => {
            // Decision point visualization
            add_pipeline_node(event, NodeType::Decision {
                threshold: 0.7,
                actual: event.confidence,
                routed_to: event.next_stage,
            });
        }
        "Storage" => {
            // Pipeline complete
            mark_pipeline_complete(event.timestamp);
        }
        _ => {
            // Regular processing stage
            add_pipeline_node(event, NodeType::Processing {
                latency: event.latency_ms,
            });
        }
    }
}
```

## Testing & Verification Checklist

### ✅ 1. Compile
```bash
cargo check
cargo build
```

### ✅ 2. WebSocket Connection
```bash
cargo run --bin server &
sleep 2
wscat -c "ws://localhost:3000/ws/pipeline-events?api_key=test" 
```

### ✅ 3. Trigger Pipeline Test
```bash
curl -X POST http://localhost:3000/pipeline/test
```
**Expected:** WebSocket receives 9 events in sequence with increasing timestamps

### ✅ 4. Send Real Log via /analyze
```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"logs":"Feb 20 14:30:15 server sshd[25619]: Received disconnect from 192.168.1.50 port 54321 [preauth]"}'
```
**Expected:** All 9 stages emit events with real latency measurements and confidence scores

### ✅ 5. Check Event Fields
Verify all returned events include:
- `event_id`: Unique UUID
- `timestamp`: ISO 8601 format
- `stage`: Correct pipeline stage name
- `status`: Started/Completed/Error
- `log_snippet`: First 100 chars of sanitized log
- `model`: Present for LLM stages
- `latency_ms`: Present for completed stages
- `confidence`: Present for Triage, Router, and Alert stages
- `next_stage`: Points to next stage (None for Storage)

### ✅ 6. Monitor Performance
```bash
# Watch events in real-time with jq
wscat -c "ws://localhost:3000/ws/pipeline-events" | jq '.latency_ms'
```

### ✅ 7. Test Error Path
```bash
# Simulate embedding failure by stopping Ollama/Chroma
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"logs":"test log"}'
```
**Expected:** Event with `status: "error"` for Embedder stage

## Configuration

### Confidence Threshold
```bash
export GROK_CONFIDENCE_THRESHOLD=0.65  # Route to Grok if < 65%
cargo run --bin server
```

Events will show:
- Ollama result (initial confidence)
- ConfidenceRouter routing decision
- Grok processing (if needed)

### Model Selection
```bash
# In src/bin/server.rs line ~106
let mut analyzer = SiemAnalyzer::new(
    Box::new(ollama_backend), 
    "qwen2.5:14b-instruct-q5_K_M".to_string()  // Change model here
);
```

Events will show this model name in Ollama.Triage stage.

## API Response Integration

The `/analyze` endpoint returns full `AnalysisResult` with severity and summary, while WebSocket streaming provides real-time stage updates:

```
POST /analyze (returns immediately with final result)
  ↓
Each log triggers 9 WebSocket events as it processes
  ↓
Client can show progress bar + live stages while awaiting /analyze response
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No events on WebSocket | Check API key in query param or Authorization header |
| Events missing stages | Verify event_tx is being passed to analyze_log_with_events |
| Latency always None | Check that timing measurements are taken before emit_pipeline_event |
| Confidence is None on non-LLM stages | This is expected - only Triage, Router, and Alert emit confidence |
| Events show Error status | Check logs for backend errors (Ollama, Chroma, Grok) |

## Future Enhancements

1. **Batch Processing Events**: Add event emissions to `process_log_file()` for multi-log scenarios
2. **Stage Metrics**: Aggregate latency stats across all logs for performance dashboards
3. **Custom Stages**: Allow plugins to add custom pipeline stages with event emission
4. **Replay** events from Elasticsearch for historical analysis visualization

---

## Summary

Real pipeline events are now fully integrated:
- ✅ Helper function `emit_pipeline_event()` centralizes event creation
- ✅ All 9 stages emit events with latency, model, and confidence
- ✅ `/analyze` endpoint processes logs through real pipeline with events
- ✅ `/pipeline/test` endpoint demonstrates full flow with synthetic log
- ✅ WebSocket endpoint broadcasts events to connected clients
- ✅ Events include rich information for client visualization

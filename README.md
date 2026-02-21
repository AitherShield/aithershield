![Project Name](https://raw.githubusercontent.com/AitherShield/aithershield/main/assets/aithershield.jpg)
# Hybrid AI powered SIEM

AitherShield is an AI-powered Security Information and Event Management (SIEM) system that combines:
- **Real-time log analysis** using Ollama and Grok AI backends
- **Vector-based context retrieval** with Chroma for enhanced analysis
- **Persistent storage** with Elasticsearch for durability
- **Terminal UI** for interactive monitoring
- **REST API** for integration with other systems
- **Intelligent alerting** with configurable severity thresholds

## Quick Start

1. **Install Ollama** and pull a model:
   ```bash
   ollama pull qwen2.5:14b-instruct-q5_K_M
   ```

2. **Run basic analysis**:
   ```bash
   cargo run
   ```

3. **Enable persistence** (optional):
   ```bash
   export ELASTICSEARCH_URL="http://localhost:9200"
   cargo run --bin tui
   ```

## Environment Variables

AitherShield supports various environment variables for configuration:

### AI Backend Configuration
- `XAI_OPENAI_KEY` - API key for Grok/xAI backend (enables confidence-based routing)
- `GROK_CONFIDENCE_THRESHOLD` - Confidence threshold for routing low-confidence analyses to Grok (default: `0.8`)

### Vector Database
- `CHROMA_URL` - URL for Chroma vector database (default: `http://localhost:8000`)

### Alerting Configuration
- `ALERT_MIN_SEVERITY` - Minimum severity level for alerts (`Low`, `Medium`, `High`, `Critical`) (default: `High`)
- `ALERT_CHANNELS` - Comma-separated list of alert channels (`console`, `file`) (default: `console`)
- `ALERT_FILE_PATH` - File path for file-based alerts (default: `./alerts.log`)

### Persistence
- `ELASTICSEARCH_URL` - URL for Elasticsearch instance (default: `http://elasticsearch:9200`, enables persistent storage)

## Usage Examples

### Basic Usage (Ollama only)
```bash
cargo run
```

### With AI Confidence Routing
```bash
export XAI_OPENAI_KEY="your-api-key"
export GROK_CONFIDENCE_THRESHOLD=0.7
cargo run
```

### With Vector Database (RAG)
```bash
export CHROMA_URL="http://localhost:8000"
cargo run
```

### With Elasticsearch Persistence
```bash
export ELASTICSEARCH_URL="http://localhost:9200"
cargo run --bin tui
```

### API Server Mode
```bash
export ELASTICSEARCH_URL="http://localhost:9200"
cargo run --bin api
```

### Full Configuration Example
```bash
export XAI_OPENAI_KEY="your-api-key"
export GROK_CONFIDENCE_THRESHOLD=0.8
export CHROMA_URL="http://localhost:8000"
export ELASTICSEARCH_URL="http://localhost:9200"
export ALERT_MIN_SEVERITY="Medium"
export ALERT_CHANNELS="console,file"
export ALERT_FILE_PATH="/var/log/aithershield/alerts.log"
cargo run --bin tui
```

### Testing
```bash
cargo test --features mock-chroma
```

## API Endpoints

When running the API server (`cargo run --bin api`), the following REST endpoints are available:

### GET `/`
Returns API information and available endpoints.

### GET `/status`
Returns system status including:
- Alert count
- Analysis count
- Uptime in seconds
- Last update timestamp

### GET `/alerts`
Returns a JSON array of all alerts in the system.

### POST `/analyze`
Analyzes log entries. Expects JSON payload:
```json
{
  "logs": "your log entry here"
}
```
Returns analysis result with severity, summary, and confidence score.

### Elasticsearch Features

When Elasticsearch is configured, AitherShield provides:

- **Automatic Index Creation**: Indices `aithershield-alerts` and `aithershield-analyses` are created with proper mappings
- **Persistent Storage**: All alerts and analyses are indexed for durability
- **Startup Loading**: Recent data (last 24 hours) is loaded on application startup
- **Fallback Mode**: If Elasticsearch is unavailable, the system continues with in-memory storage only

#### Query Examples (Programmatic)

```rust
use aithershield::storage::es_store::{EsStore, EsQuery};
use aithershield::LogSeverity;

// Get recent alerts (last 24 hours)
let alerts = store.get_recent_alerts(24).await?;

// Custom query with filters
let query = EsQuery::new()
    .limit(50)
    .min_severity(LogSeverity::High)
    .last_hours(168)  // Last 7 days
    .sort_desc();

let high_severity_alerts = store.query_alerts(query).await?;
```

### Example API Usage
```bash
# Get system status
curl http://localhost:3000/status

# Get all alerts
curl http://localhost:3000/alerts

# Analyze a log entry
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"logs": "Failed password for user admin from 192.168.1.100"}'
```
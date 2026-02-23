use aithershield::{alerting::Alert, LogSeverity, AnalysisResult, storage, SiemAnalyzer, OllamaBackend, GrokApiBackend, LlmBackend, PipelineEvent, PipelineStatus};
use axum::{
    extract::{Query, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;
use tokio::sync::broadcast;
use futures_util::{SinkExt, StreamExt};

#[derive(Deserialize)]
struct AnalyzeRequest {
    logs: String,
}

#[derive(Serialize)]
struct StatusResponse {
    alerts_count: usize,
    analyses_count: usize,
    uptime_seconds: u64,
    last_update_ago: String,
}

struct App {
    alerts: Vec<Alert>,
    analyses: Vec<AnalysisResult>,
    es_store: Option<storage::es_store::EsStore>,
    start_time: std::time::Instant,
    last_update: std::time::Instant,
    pipeline_tx: broadcast::Sender<PipelineEvent>,
    analyzer: Option<Arc<SiemAnalyzer>>,    api_key: Option<String>,}

impl App {
    async fn new() -> Self {
        let now = std::time::Instant::now();
        let (pipeline_tx, _) = broadcast::channel(100);
        let api_key = std::env::var("API_KEY").ok();
        let mut app = Self {
            alerts: Vec::new(),
            analyses: Vec::new(),
            es_store: None,
            start_time: now,
            last_update: now,
            pipeline_tx,
            analyzer: None,
            api_key,
        };

        // Try to connect to Elasticsearch and load recent data
        if let Ok(es_url) = std::env::var("ELASTICSEARCH_URL") {
            match storage::es_store::EsStore::new(Some(&es_url)).await {
                Ok(mut store) => {
                    // Ensure indices exist
                    if let Err(e) = store.ensure_indices().await {
                        eprintln!("Failed to ensure Elasticsearch indices: {}", e);
                        eprintln!("Proceeding without persistent storage");
                    } else {
                        app.es_store = Some(store);
                        println!("Connected to Elasticsearch at {}", es_url);

                        // Load recent alerts and analyses (last 24 hours)
                        if let Ok(alerts) = app.es_store.as_ref().unwrap().get_recent_alerts(24).await {
                            app.alerts = alerts;
                            println!("Loaded {} alerts from Elasticsearch", app.alerts.len());
                        }

                        if let Ok(analyses) = app.es_store.as_ref().unwrap().get_recent_analyses(24).await {
                            app.analyses = analyses;
                            println!("Loaded {} analyses from Elasticsearch", app.analyses.len());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to connect to Elasticsearch: {}", e);
                    eprintln!("Proceeding without persistent storage");
                }
            }
        } else {
            println!("ELASTICSEARCH_URL not set, using in-memory storage only");
        }

        // Initialize analyzer
        let ollama_backend = OllamaBackend::new("http://localhost:11434".to_string());
        let mut analyzer = SiemAnalyzer::new(Box::new(ollama_backend), "qwen2.5:14b-instruct-q5_K_M".to_string());

        // Set confidence threshold
        let confidence_threshold = std::env::var("GROK_CONFIDENCE_THRESHOLD")
            .unwrap_or_else(|_| "0.7".to_string())
            .parse::<f32>()
            .unwrap_or(0.7);
        analyzer = analyzer.with_confidence_threshold(confidence_threshold);

        // Add Grok if available
        if let Ok(api_key) = std::env::var("XAI_OPENAI_KEY") {
            let grok_backend = GrokApiBackend::new(api_key);
            analyzer = analyzer.with_grok_backend(Box::new(grok_backend), "grok-4-1-fast-non-reasoning".to_string());
        }

        // Add Chroma if available
        let chroma_url = std::env::var("CHROMA_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());
        if let Ok(store) = storage::ChromaStore::new(&chroma_url, "aithershield_logs").await {
            analyzer = analyzer.with_chroma_store(store);
        }

        // Configure alerting
        let alert_min_severity = std::env::var("ALERT_MIN_SEVERITY")
            .unwrap_or_else(|_| "High".to_string())
            .parse::<LogSeverity>()
            .unwrap_or(LogSeverity::High);
        let alert_channels_str = std::env::var("ALERT_CHANNELS").unwrap_or_else(|_| "console".to_string());
        let alert_file_path = std::env::var("ALERT_FILE_PATH").unwrap_or_else(|_| "./alerts.log".to_string());
        let mut alert_channels = Vec::new();
        for channel in alert_channels_str.split(',') {
            match channel.trim() {
                "console" => alert_channels.push(aithershield::alerting::AlertChannel::Console),
                "file" => alert_channels.push(aithershield::alerting::AlertChannel::File(alert_file_path.clone())),
                _ => {}
            }
        }
        analyzer = analyzer.with_alerting(alert_min_severity, alert_channels);

        app.analyzer = Some(Arc::new(analyzer));

        app
    }
}

type SharedApp = Arc<Mutex<App>>;

#[derive(Deserialize)]
struct ApiKeyQuery {
    api_key: Option<String>,
}

fn authenticate(headers: &HeaderMap, query: &ApiKeyQuery, app_api_key: &Option<String>) -> bool {
    if let Some(expected_key) = app_api_key {
        // Check Authorization header
        if let Some(auth) = headers.get("authorization") {
            if let Ok(auth_str) = auth.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let provided_key = &auth_str[7..];
                    if provided_key == expected_key {
                        return true;
                    }
                }
            }
        }
        // Check query param
        if let Some(provided_key) = &query.api_key {
            if provided_key == expected_key {
                return true;
            }
        }
        false
    } else {
        // No API key required
        true
    }
}

async fn get_root() -> &'static str {
    "AitherShield SIEM API Server\n\nEndpoints:\n  GET  /status  - System status\n  GET  /alerts  - List alerts\n  POST /analyze - Analyze logs\n  GET  /ws/pipeline-events - WebSocket pipeline events\n  POST /pipeline/test - Test pipeline flow\n"
}

fn create_router(shared_app: SharedApp) -> Router {
    Router::new()
        .route("/", get(get_root))
        .route("/alerts", get(get_alerts))
        .route("/analyze", post(post_analyze))
        .route("/status", get(get_status))
        .route("/ws/pipeline-events", get(ws_pipeline_events))
        .route("/pipeline/test", post(post_pipeline_test))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(shared_app)
}

async fn get_alerts(State(shared_app): State<SharedApp>) -> Json<Vec<Alert>> {
    let app = shared_app.lock().unwrap();
    Json(app.alerts.clone())
}

#[axum::debug_handler]
async fn post_analyze(
    State(shared_app): State<SharedApp>,
    Json(req): Json<AnalyzeRequest>,
) -> Result<Json<AnalysisResult>, StatusCode> {
    let (tx, analyzer, es_store) = {
        let app = shared_app.lock().unwrap();
        (app.pipeline_tx.clone(), app.analyzer.clone(), app.es_store.clone())
    };

    let analyzer = analyzer.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let analysis = analyzer.analyze_log_with_events(&req.logs, Some(&tx)).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    {
        let mut app = shared_app.lock().unwrap();
        app.analyses.push(analysis.clone());
        app.last_update = std::time::Instant::now();
    }

    // Index to Elasticsearch if available
    if let Some(es_store) = es_store {
        if let Err(e) = es_store.index_analysis(&analysis).await {
            eprintln!("Failed to index analysis to Elasticsearch: {}", e);
            // Continue anyway - don't fail the request
        }
    }

    Ok(Json(analysis))
}

async fn get_status(State(shared_app): State<SharedApp>) -> Json<StatusResponse> {
    let app = shared_app.lock().unwrap();
    let uptime = app.start_time.elapsed().as_secs();
    let last_update_ago = format!("{}s ago", app.last_update.elapsed().as_secs());

    Json(StatusResponse {
        alerts_count: app.alerts.len(),
        analyses_count: app.analyses.len(),
        uptime_seconds: uptime,
        last_update_ago,
    })
}

async fn post_pipeline_test(
    State(shared_app): State<SharedApp>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let (tx, analyzer) = {
        let app = shared_app.lock().unwrap();
        (app.pipeline_tx.clone(), app.analyzer.clone())
    };

    let analyzer = analyzer.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fake log for testing
    let fake_log = "Feb 20 14:30:15 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2";

    // Simulate the full pipeline
    match analyzer.analyze_log_with_events(&fake_log, Some(&tx)).await {
        Ok(result) => Ok(Json(serde_json::json!({
            "status": "success",
            "message": "Pipeline test completed",
            "result": {
                "severity": result.severity,
                "confidence": result.confidence,
                "summary": result.summary
            }
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "status": "error",
            "message": format!("Pipeline test failed: {}", e)
        }))),
    }
}

#[axum::debug_handler]
async fn ws_pipeline_events(
    ws: WebSocketUpgrade,
    Query(query): Query<ApiKeyQuery>,
    headers: HeaderMap,
    State(shared_app): State<SharedApp>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let api_key = {
        let app = shared_app.lock().unwrap();
        app.api_key.clone()
    };

    if !authenticate(&headers, &query, &api_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(ws.on_upgrade(move |socket| handle_pipeline_events_socket(socket, shared_app)))
}

async fn handle_pipeline_events_socket(
    socket: axum::extract::ws::WebSocket,
    shared_app: SharedApp,
) {
    let mut rx = {
        let app = shared_app.lock().unwrap();
        app.pipeline_tx.subscribe()
    };

    let (mut sender, mut receiver) = socket.split();

    // Send connected message
    let connected_event = PipelineEvent {
        event_id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        stage: "System".to_string(),
        status: PipelineStatus::Completed,
        log_snippet: "WebSocket connected".to_string(),
        model: None,
        latency_ms: None,
        confidence: None,
        next_stage: None,
    };
    if let Ok(json) = serde_json::to_string(&connected_event) {
        let _ = sender.send(axum::extract::ws::Message::Text(json.into())).await;
    }

    let mut heartbeat_interval = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = heartbeat_interval.tick() => {
                let heartbeat_event = PipelineEvent {
                    event_id: uuid::Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    stage: "System.Heartbeat".to_string(),
                    status: PipelineStatus::Completed,
                    log_snippet: "Heartbeat".to_string(),
                    model: None,
                    latency_ms: None,
                    confidence: None,
                    next_stage: None,
                };
                if let Ok(json) = serde_json::to_string(&heartbeat_event) {
                    if sender.send(axum::extract::ws::Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }
            event = rx.recv() => {
                match event {
                    Ok(event) => {
                        if let Ok(json) = serde_json::to_string(&event) {
                            if sender.send(axum::extract::ws::Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(_) => continue,
                }
            }
            msg = receiver.next() => {
                match msg {
                    Some(Ok(axum::extract::ws::Message::Close(_))) => {
                        // Send disconnect event
                        let disconnect_event = PipelineEvent {
                            event_id: uuid::Uuid::new_v4(),
                            timestamp: chrono::Utc::now(),
                            stage: "System".to_string(),
                            status: PipelineStatus::Completed,
                            log_snippet: "WebSocket disconnected".to_string(),
                            model: None,
                            latency_ms: None,
                            confidence: None,
                            next_stage: None,
                        };
                        if let Ok(json) = serde_json::to_string(&disconnect_event) {
                            let _ = sender.send(axum::extract::ws::Message::Text(json.into())).await;
                        }
                        break;
                    }
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let app = Arc::new(Mutex::new(App::new().await));

    let router = create_router(app);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("API server listening on http://0.0.0.0:3000");
    axum::serve(listener, router).await.unwrap();
}
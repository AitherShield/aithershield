use aithershield::{alerting::Alert, LogSeverity, AnalysisResult, storage};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

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
}

impl App {
    async fn new() -> Self {
        let now = std::time::Instant::now();
        let mut app = Self {
            alerts: Vec::new(),
            analyses: Vec::new(),
            es_store: None,
            start_time: now,
            last_update: now,
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

        app
    }
}

type SharedApp = Arc<Mutex<App>>;

async fn get_root() -> &'static str {
    "AitherShield SIEM API Server\n\nEndpoints:\n  GET  /status  - System status\n  GET  /alerts  - List alerts\n  POST /analyze - Analyze logs\n"
}

fn create_router(shared_app: SharedApp) -> Router {
    Router::new()
        .route("/", get(get_root))
        .route("/alerts", get(get_alerts))
        .route("/analyze", post(post_analyze))
        .route("/status", get(get_status))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(shared_app)
}

async fn get_alerts(State(shared_app): State<SharedApp>) -> Json<Vec<Alert>> {
    let app = shared_app.lock().unwrap();
    Json(app.alerts.clone())
}

async fn post_analyze(
    State(shared_app): State<SharedApp>,
    Json(req): Json<AnalyzeRequest>,
) -> Result<Json<AnalysisResult>, StatusCode> {
    let mut app = shared_app.lock().unwrap();

    // Perform analysis (simplified for now)
    let analysis = AnalysisResult {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        severity: LogSeverity::Medium,
        summary: "Analysis completed".to_string(),
        details: Some(req.logs),
        related_alerts: vec![],
        confidence: 0.8,
    };

    app.analyses.push(analysis.clone());
    app.last_update = std::time::Instant::now();

    // Index to Elasticsearch if available
    if let Some(ref es_store) = app.es_store {
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

#[tokio::main]
async fn main() {
    let app = Arc::new(Mutex::new(App::new().await));

    let router = create_router(app);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("API server listening on http://0.0.0.0:3000");
    axum::serve(listener, router).await.unwrap();
}
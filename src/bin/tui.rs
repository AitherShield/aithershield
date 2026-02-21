use aithershield::{alerting::Alert, LogSeverity, SiemAnalyzer, LlmBackend, OllamaBackend, AnalysisResult, storage};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use color_eyre::Result;
use crossterm::{
    cursor::Show,
    event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio::signal;
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
        timestamp: chrono::Utc::now(),
        severity: LogSeverity::Medium,
        summary: "Analysis completed".to_string(),
        details: Some(req.logs),
        related_alerts: vec![],
        confidence: 0.8,
    };

    app.analyses.push(analysis.clone());
    app.last_update = std::time::Instant::now();

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
use tokio::time;
use futures::StreamExt;

#[derive(Debug)]
enum Tab {
    Alerts,
    Analyses,
    Status,
}

impl Tab {
    fn next(&self) -> Self {
        match self {
            Tab::Alerts => Tab::Analyses,
            Tab::Analyses => Tab::Status,
            Tab::Status => Tab::Alerts,
        }
    }

    fn prev(&self) -> Self {
        match self {
            Tab::Alerts => Tab::Status,
            Tab::Analyses => Tab::Alerts,
            Tab::Status => Tab::Analyses,
        }
    }

    fn title(&self) -> &str {
        match self {
            Tab::Alerts => "Alerts",
            Tab::Analyses => "Analyses",
            Tab::Status => "Status",
        }
    }
}

#[derive(Debug)]
enum AppEvent {
    Key(KeyEvent),
    NewAlert(Alert),
    NewAnalysis(AnalysisResult),
    Quit,
}

struct App {
    alerts: Vec<Alert>,
    analyses: Vec<AnalysisResult>,
    es_store: Option<storage::elasticsearch::EsStore>,
    tab: Tab,
    alert_list_state: ListState,
    analysis_list_state: ListState,
    selected_alert_details: Option<usize>,
    selected_analysis_details: Option<usize>,
    status_info: String,
    last_update: Instant,
    start_time: Instant,
}

impl App {
    async fn new() -> Self {
        let mut app = Self {
            alerts: Vec::new(),
            analyses: Vec::new(),
            es_store: None,
            tab: Tab::Alerts,
            alert_list_state: ListState::default(),
            analysis_list_state: ListState::default(),
            selected_alert_details: None,
            selected_analysis_details: None,
            status_info: "Initializing...".to_string(),
            last_update: Instant::now(),
            start_time: Instant::now(),
        };

        // Try to connect to Elasticsearch and load recent data
        if let Ok(es_url) = std::env::var("ELASTICSEARCH_URL") {
            match storage::elasticsearch::EsStore::new(&es_url).await {
                Ok(store) => {
                    app.es_store = Some(store);
                    app.status_info = format!("Connected to Elasticsearch at {}", es_url);

                    // Load recent alerts and analyses
                    if let Ok(alerts) = app.es_store.as_ref().unwrap().query_recent_alerts(100, None).await {
                        app.alerts = alerts;
                        app.status_info = format!("Loaded {} alerts from ES", app.alerts.len());
                    }

                    if let Ok(analyses) = app.es_store.as_ref().unwrap().query_recent_analyses(100, None).await {
                        app.analyses = analyses;
                        app.status_info = format!("Loaded {} alerts, {} analyses from ES", app.alerts.len(), app.analyses.len());
                    }
                }
                Err(e) => {
                    app.status_info = format!("ES connection failed: {}", e);
                }
            }
        } else {
            app.status_info = "No ES configured, in-memory only".to_string();
        }

        app
    }
}

impl App {


    fn on_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return false,
            KeyCode::Tab => {
                self.tab = self.tab.next();
                self.selected_alert_details = None;
                self.selected_analysis_details = None;
            }
            KeyCode::BackTab => {
                self.tab = self.tab.prev();
                self.selected_alert_details = None;
                self.selected_analysis_details = None;
            }
            KeyCode::Down => match self.tab {
                Tab::Alerts => {
                    let i = match self.alert_list_state.selected() {
                        Some(i) => (i + 1).min(self.alerts.len().saturating_sub(1)),
                        None => 0,
                    };
                    self.alert_list_state.select(Some(i));
                    self.selected_alert_details = Some(i);
                }
                Tab::Analyses => {
                    let i = match self.analysis_list_state.selected() {
                        Some(i) => (i + 1).min(self.analyses.len().saturating_sub(1)),
                        None => 0,
                    };
                    self.analysis_list_state.select(Some(i));
                    self.selected_analysis_details = Some(i);
                }
                _ => {}
            },
            KeyCode::Up => match self.tab {
                Tab::Alerts => {
                    let i = match self.alert_list_state.selected() {
                        Some(i) => i.saturating_sub(1),
                        None => 0,
                    };
                    self.alert_list_state.select(Some(i));
                    self.selected_alert_details = Some(i);
                }
                Tab::Analyses => {
                    let i = match self.analysis_list_state.selected() {
                        Some(i) => i.saturating_sub(1),
                        None => 0,
                    };
                    self.analysis_list_state.select(Some(i));
                    self.selected_analysis_details = Some(i);
                }
                _ => {}
            },
            KeyCode::Enter => match self.tab {
                Tab::Alerts => {
                    if let Some(i) = self.alert_list_state.selected() {
                        self.selected_alert_details = Some(i);
                    }
                }
                Tab::Analyses => {
                    if let Some(i) = self.analysis_list_state.selected() {
                        self.selected_analysis_details = Some(i);
                    }
                }
                _ => {}
            },
            KeyCode::Char('r') => {
                // Refresh - could trigger re-analysis
            }
            _ => {}
        }
        true
    }

    fn on_new_alert(&mut self, alert: Alert) {
        self.alerts.push(alert.clone());
        self.last_update = Instant::now();

        // Index to Elasticsearch if available (spawn async task)
        if let Some(ref es_store) = self.es_store {
            let store = es_store.clone();
            let alert_clone = alert.clone();
            tokio::spawn(async move {
                if let Err(e) = store.index_alert(&alert_clone).await {
                    eprintln!("Failed to index alert to Elasticsearch: {}", e);
                }
            });
        }
    }

    fn on_new_analysis(&mut self, analysis: AnalysisResult) {
        self.analyses.push(analysis.clone());
        self.last_update = Instant::now();

        // Index to Elasticsearch if available (spawn async task)
        if let Some(ref es_store) = self.es_store {
            let store = es_store.clone();
            let analysis_clone = analysis.clone();
            tokio::spawn(async move {
                if let Err(e) = store.index_analysis(&analysis_clone).await {
                    eprintln!("Failed to index analysis to Elasticsearch: {}", e);
                }
            });
        }
    }
}

fn severity_color(severity: &LogSeverity) -> Color {
    match severity {
        LogSeverity::Low => Color::Green,
        LogSeverity::Medium => Color::Yellow,
        LogSeverity::High => Color::Red,
        LogSeverity::Critical => Color::Magenta,
    }
}

fn draw_alerts_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Alert list
    let items: Vec<ListItem> = app
        .alerts
        .iter()
        .enumerate()
        .map(|(i, alert)| {
            let time = alert.timestamp.format("%H:%M:%S");
            let severity = format!("{:?}", alert.severity);
            let content = format!("{} [{}] {}", time, severity, &alert.explanation[..alert.explanation.len().min(50)]);
            ListItem::new(content).style(Style::default().fg(severity_color(&alert.severity)))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Recent Alerts"))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, chunks[0], &mut app.alert_list_state);

    // Details pane
    let details = if let Some(i) = app.selected_alert_details {
        if let Some(alert) = app.alerts.get(i) {
            format!(
                "Time: {}\nSeverity: {:?}\nLog ID: {}\nExplanation: {}\nAction: {}\nConfidence: {:.2}",
                alert.timestamp, alert.severity, alert.log_entry_id, alert.explanation, alert.action, alert.confidence
            )
        } else {
            "No alert selected".to_string()
        }
    } else {
        "Select an alert to view details".to_string()
    };

    let paragraph = Paragraph::new(details)
        .block(Block::default().borders(Borders::ALL).title("Alert Details"))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, chunks[1]);
}

fn draw_analyses_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Analysis list
    let items: Vec<ListItem> = app
        .analyses
        .iter()
        .enumerate()
        .map(|(i, analysis)| {
            let severity = format!("{:?}", analysis.severity);
            let content = format!("[{}] {} (Conf: {:.2})", severity, &analysis.summary[..analysis.summary.len().min(50)], analysis.confidence);
            ListItem::new(content).style(Style::default().fg(severity_color(&analysis.severity)))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Recent Analyses"))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, chunks[0], &mut app.analysis_list_state);

    // Details pane
    let details = if let Some(i) = app.selected_analysis_details {
        if let Some(analysis) = app.analyses.get(i) {
            format!(
                "Severity: {:?}\nSummary: {}\nDetails: {}\nConfidence: {:.2}",
                analysis.severity, analysis.summary, analysis.details.as_ref().unwrap_or(&"None".to_string()), analysis.confidence
            )
        } else {
            "No analysis selected".to_string()
        }
    } else {
        "Select an analysis to view details".to_string()
    };

    let paragraph = Paragraph::new(details)
        .block(Block::default().borders(Borders::ALL).title("Analysis Details"))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, chunks[1]);
}

fn draw_status_tab(f: &mut Frame, app: &App, area: Rect) {
    let text = format!(
        "AitherShield TUI Dashboard\n\n\
        Status: {}\n\n\
        Controls:\n\
        - Tab/Shift+Tab: Switch tabs\n\
        - ↑/↓: Navigate lists\n\
        - Enter: View details\n\
        - r: Refresh\n\
        - q/Esc: Quit\n\n\
        Real-time monitoring active...",
        app.status_info
    );

    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("System Status"))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn draw(f: &mut Frame, app: &mut App) {
    let size = f.size();

    // Tabs
    let titles = vec!["Alerts", "Analyses", "Status"];
    let tabs = Tabs::new(titles)
        .select(match app.tab {
            Tab::Alerts => 0,
            Tab::Analyses => 1,
            Tab::Status => 2,
        })
        .style(Style::default().fg(Color::Cyan))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)])
        .split(size);

    f.render_widget(tabs, chunks[0]);

    // Content
    match app.tab {
        Tab::Alerts => draw_alerts_tab(f, app, chunks[1]),
        Tab::Analyses => draw_analyses_tab(f, app, chunks[1]),
        Tab::Status => draw_status_tab(f, app, chunks[1]),
    }

    // Status bar
    let status = Paragraph::new(app.status_info.as_str())
        .style(Style::default().bg(Color::Blue).fg(Color::White))
        .alignment(Alignment::Center);

    f.render_widget(status, chunks[2]);
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: Arc<Mutex<App>>,
    event_tx: mpsc::Sender<AppEvent>,
    mut alert_rx: mpsc::Receiver<AppEvent>,
    mut analysis_rx: mpsc::Receiver<AppEvent>,
) -> Result<()> {
    loop {
        let mut app_guard = app.lock().unwrap();
        // Process pending events
        while let Ok(event) = alert_rx.try_recv() {
            match event {
                AppEvent::NewAlert(alert) => app_guard.on_new_alert(alert),
                _ => {}
            }
        }
        while let Ok(event) = analysis_rx.try_recv() {
            match event {
                AppEvent::NewAnalysis(analysis) => app_guard.on_new_analysis(analysis),
                _ => {}
            }
        }

        app_guard.status_info = format!(
            "Ollama Mode | Alerts: {} | Analyses: {}",
            app_guard.alerts.len(),
            app_guard.analyses.len()
        );
        terminal.draw(|f| draw(f, &mut app_guard))?;

        if crossterm::event::poll(Duration::from_millis(100))? {
            match crossterm::event::read()? {
                Event::Key(key) => {
                    if !app_guard.on_key(key) {
                        event_tx.send(AppEvent::Quit).await?;
                        break;
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
    Ok(())
}

async fn event_handler(
    mut event_rx: mpsc::Receiver<AppEvent>,
    alert_tx: mpsc::Sender<AppEvent>,
    analysis_tx: mpsc::Sender<AppEvent>,
) -> Result<()> {
    let mut interval = time::interval(Duration::from_millis(100));
    let mut event_stream = EventStream::new();

    loop {
        tokio::select! {
            _ = interval.tick() => {
            }
            Some(Ok(event)) = event_stream.next() => {
                match event {
                    Event::Key(key) => alert_tx.send(AppEvent::Key(key)).await?,
                    _ => {}
                }
            }
            Some(app_event) = event_rx.recv() => {
                match app_event {
                    AppEvent::Quit => break,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize error handling (ignore errors to prevent TUI corruption)
    let _ = color_eyre::install();

    // Reset terminal state in case a previous TUI session crashed
    let _ = disable_raw_mode();
    let mut stdout = std::io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen, Show);

    // Initialize app
    let app = Arc::new(Mutex::new(App::new().await));

    // Spawn API server (silently handle errors to avoid TUI corruption)
    let shared_app = Arc::clone(&app);
    let api_server = tokio::spawn(async move {
        // Try to bind to port 3000, but don't panic if it fails
        if let Ok(listener) = tokio::net::TcpListener::bind("0.0.0.0:3000").await {
            let router = create_router(shared_app);
            let _ = axum::serve(listener, router).await; // Ignore errors
        }
        // If binding fails, just continue without API server
    });

    // Setup terminal (suppress all error output to avoid TUI corruption)
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create channels
    let (event_tx, event_rx) = mpsc::channel(100);
    let (alert_tx, alert_rx) = mpsc::channel(100);
    let (analysis_tx, analysis_rx) = mpsc::channel(100);

    // Spawn event handler
    let event_handler = tokio::spawn(async move {
        event_handler(event_rx, alert_tx, analysis_tx).await
    });

    // Spawn signal handler for clean shutdown
    let signal_event_tx = event_tx.clone();
    let signal_handler = tokio::spawn(async move {
        // Wait for SIGINT (Ctrl+C) - no debug output during normal operation
        let _ = signal::ctrl_c().await;

        // Send quit signal to the event loop
        let _ = signal_event_tx.send(AppEvent::Quit).await;
    });

    // Run app
    let res = run_app(&mut terminal, Arc::clone(&app), event_tx.clone(), alert_rx, analysis_rx).await;

    // Clean shutdown sequence - restore terminal first to show messages
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture).ok();
    terminal.show_cursor().ok();

    println!("Starting clean shutdown...");

    // 1. Send quit signal to event handler (if not already sent by signal handler)
    let _ = event_tx.send(AppEvent::Quit).await;

    // 2. Wait for event handler to finish gracefully with timeout
    let shutdown_timeout = tokio::time::Duration::from_secs(5);
    match tokio::time::timeout(shutdown_timeout, event_handler).await {
        Ok(result) => {
            if let Err(e) = result {
                println!("Event handler finished with error: {:?}", e);
            } else {
                println!("Event handler shut down gracefully");
            }
        }
        Err(_) => {
            println!("Event handler shutdown timed out, forcing abort");
            // The task will be aborted below anyway
        }
    }

    // 3. Abort API server (Axum doesn't have graceful shutdown in this version easily)
    api_server.abort();
    println!("API server aborted");

    // 4. Abort signal handler
    signal_handler.abort();

    // 5. Report any errors from the main app loop
    if let Err(err) = res {
        println!("Application exited with error: {:?}", err);
        return Err(err);
    }

    println!("Clean shutdown completed");
    Ok(())
}
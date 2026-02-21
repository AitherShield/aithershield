use aithershield::{alerting::Alert, LogSeverity, SiemAnalyzer, LlmBackend, OllamaBackend, AnalysisResult};
use chrono::{DateTime, Utc};
use color_eyre::Result;
use crossterm::{
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
use std::{
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
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
    tab: Tab,
    alert_list_state: ListState,
    analysis_list_state: ListState,
    selected_alert_details: Option<usize>,
    selected_analysis_details: Option<usize>,
    status_info: String,
    last_update: Instant,
}

impl Default for App {
    fn default() -> Self {
        Self {
            alerts: Vec::new(),
            analyses: Vec::new(),
            tab: Tab::Alerts,
            alert_list_state: ListState::default(),
            analysis_list_state: ListState::default(),
            selected_alert_details: None,
            selected_analysis_details: None,
            status_info: "Initializing...".to_string(),
            last_update: Instant::now(),
        }
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
        self.alerts.push(alert);
        self.last_update = Instant::now();
    }

    fn on_new_analysis(&mut self, analysis: AnalysisResult) {
        self.analyses.push(analysis);
        self.last_update = Instant::now();
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
            let content = format!("[{}] {} (Conf: {:.2})", severity, &analysis.explanation[..analysis.explanation.len().min(50)], analysis.confidence);
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
                "Severity: {:?}\nExplanation: {}\nAction: {}\nConfidence: {:.2}",
                analysis.severity, analysis.explanation, analysis.recommended_action, analysis.confidence
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
    color_eyre::install()?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create channels
    let (event_tx, event_rx) = mpsc::channel(100);
    let (alert_tx, mut alert_rx) = mpsc::channel(100);
    let (analysis_tx, mut analysis_rx) = mpsc::channel(100);

    // Initialize app
    let app = Arc::new(Mutex::new(App::default()));

    // Spawn event handler
    let event_handler = tokio::spawn(async move {
        event_handler(event_rx, alert_tx, analysis_tx).await
    });

    // Run app
    let res = run_app(&mut terminal, Arc::clone(&app), event_tx.clone(), alert_rx, analysis_rx).await;

    // Cleanup
    event_tx.send(AppEvent::Quit).await?;
    event_handler.abort();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}
use aithershield::{LlmBackend, OllamaBackend, GrokApiBackend, SiemAnalyzer, GenerateOptions, ChatMessage, Role, LogSeverity, ingestion, storage, alerting};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test Ollama
    println!("Testing Ollama Backend:");
    let ollama_backend = OllamaBackend::new("http://localhost:11434".to_string());

    let prompt = "Explain what Rust is in one sentence.";
    let model = "qwen2.5:14b-instruct-q5_K_M";
    let options = Some(GenerateOptions {
        temperature: Some(0.7),
        max_tokens: Some(100),
        top_p: None,
        frequency_penalty: None,
        presence_penalty: None,
    });

    match ollama_backend.generate(prompt, model, options.clone()).await {
        Ok(response) => println!("Ollama Generated: {}", response),
        Err(e) => println!("Ollama Error: {}", e),
    }

    // Test Grok if API key is available
    if let Ok(api_key) = std::env::var("XAI_OPENAI_KEY") {
        println!("\nTesting Grok API Backend:");
        let grok_backend = GrokApiBackend::new(api_key);

        match grok_backend.generate(prompt, "grok-4-1-fast-non-reasoning", options).await {
            Ok(response) => println!("Grok Generated: {}", response),
            Err(e) => println!("Grok Error: {}", e),
        }

        let messages = vec![
            ChatMessage {
                role: Role::User,
                content: "Hello, how are you?".to_string(),
            },
        ];

        match grok_backend.chat(messages, "grok-4-1-fast-non-reasoning", None).await {
            Ok(response) => println!("Grok Chat: {}", response),
            Err(e) => println!("Grok Chat Error: {}", e),
        }
    } else {
        println!("\nXAI_OPENAI_KEY not set, skipping Grok test.");
    }

    // Test ingestion and anonymization
    println!("\nTesting Log Ingestion and Anonymization:");
    let sample_log = "Feb 20 14:30:15 server sshd[1234]: Failed password for user=admin from 192.168.1.100 with key abc123def456";
    let (sanitized, masked) = ingestion::anonymize_log(sample_log);
    println!("Original: {}", sample_log);
    println!("Sanitized: {}", sanitized);
    println!("Masked fields: {:?}", masked);

    // Test SIEM Analyzer with Ollama and Chroma
    println!("\nTesting SIEM Analyzer with Ollama:");
    let mut analyzer = SiemAnalyzer::new(Box::new(ollama_backend), model.to_string());

    // Set confidence threshold from env var
    let confidence_threshold = std::env::var("GROK_CONFIDENCE_THRESHOLD")
        .unwrap_or_else(|_| "0.7".to_string())
        .parse::<f32>()
        .unwrap_or(0.7);
    analyzer = analyzer.with_confidence_threshold(confidence_threshold);
    println!("Confidence threshold: {}", confidence_threshold);

    // Add Grok backend if API key is available
    if let Ok(api_key) = std::env::var("XAI_OPENAI_KEY") {
        let grok_backend = GrokApiBackend::new(api_key);
        analyzer = analyzer.with_grok_backend(Box::new(grok_backend), "grok-4-1-fast-non-reasoning".to_string());
        println!("Grok backend enabled for low-confidence routing.");
    } else {
        println!("Grok backend not configured (set XAI_OPENAI_KEY for confidence-based routing).");
    }

    // Try to connect to Chroma
    let chroma_url = std::env::var("CHROMA_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());
    match storage::ChromaStore::new(&chroma_url, "aithershield_logs").await {
        Ok(store) => {
            analyzer = analyzer.with_chroma_store(store);
            println!("Chroma connected, RAG enabled.");
        }
        Err(e) => println!("Chroma not available ({}), proceeding without RAG.", e),
    }

    // Configure alerting
    let alert_min_severity = std::env::var("ALERT_MIN_SEVERITY")
        .unwrap_or_else(|_| "High".to_string())
        .parse::<aithershield::LogSeverity>()
        .unwrap_or(aithershield::LogSeverity::High);
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
    analyzer = analyzer.with_alerting(alert_min_severity.clone(), alert_channels);

    let mut alert_manager = alerting::AlertManager::default();

    let sample_logs = vec![
        "Feb 20 14:30:15 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2".to_string(),
        "Feb 20 14:31:00 server kernel: [ 1234.567890] CPU0: Core temperature above threshold, running at 95 C".to_string(),
        "Feb 20 14:32:10 server sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash".to_string(),
        "Feb 20 14:33:00 server auth: Multiple failed login attempts from 192.168.1.100, possible brute force attack".to_string(), // High severity
    ];

    for log in sample_logs {
        println!("\nAnalyzing log: {}", log);
        match analyzer.analyze_log(&log).await {
            Ok(result) => {
                println!("Severity: {:?} (Confidence: {:.2})", result.severity, result.confidence);
                println!("Summary: {}", result.summary);
                println!("Details: {}", result.details.as_deref().unwrap_or("None"));
                println!("Related Alerts: {:?}", result.related_alerts);

                // Check for alerting
                if result.severity >= alert_min_severity || (result.severity == LogSeverity::Medium && result.confidence < 0.5) {
                    let alert = alerting::Alert::new(
                        log.clone(),
                        result.severity.clone(),
                        result.summary.clone(),
                        "Review and investigate".to_string(),
                        result.confidence,
                    );
                    if let Err(e) = alerting::trigger_alert(&alert, &analyzer.alert_channels, &mut alert_manager).await {
                        eprintln!("Alert error: {}", e);
                    }
                }
            }
            Err(e) => println!("Analysis Error: {}", e),
        }
    }

    Ok(())
}

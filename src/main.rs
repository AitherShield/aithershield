use aithershield::{LlmBackend, OllamaBackend, GrokApiBackend, SiemAnalyzer, GenerateOptions, ChatMessage, Role, ingestion, storage};

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

    let sample_logs = vec![
        "Feb 20 14:30:15 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2".to_string(),
        "Feb 20 14:31:00 server kernel: [ 1234.567890] CPU0: Core temperature above threshold, running at 95 C".to_string(),
        "Feb 20 14:32:10 server sudo: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash".to_string(),
    ];

    for log in sample_logs {
        println!("\nAnalyzing log: {}", log);
        match analyzer.analyze_log(&log).await {
            Ok(result) => {
                println!("Severity: {:?} (Confidence: {:.2})", result.severity, result.confidence);
                println!("Explanation: {}", result.explanation);
                println!("Recommended Action: {}", result.recommended_action);
            }
            Err(e) => println!("Analysis Error: {}", e),
        }
    }

    Ok(())
}

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use tokio::sync::broadcast;

pub mod alerting;
pub mod ingestion;
pub mod storage;

#[derive(Clone, Serialize, Debug)]
pub struct PipelineEvent {
    pub event_id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub stage: String,
    pub status: PipelineStatus,
    pub log_snippet: String,
    pub model: Option<String>,
    pub latency_ms: Option<u64>,
    pub confidence: Option<f32>,
    pub next_stage: Option<String>,
}

#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum PipelineStatus {
    Started,
    Completed,
    Error,
}

#[derive(Error, Debug)]
pub enum LlmError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("JSON parsing failed: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("API error: {0}")]
    Api(String),
    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Role {
    System,
    User,
    Assistant,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::System => write!(f, "system"),
            Role::User => write!(f, "user"),
            Role::Assistant => write!(f, "assistant"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: Role,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateOptions {
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub top_p: Option<f32>,
    pub frequency_penalty: Option<f32>,
    pub presence_penalty: Option<f32>,
}

// Extensible trait for LLM backends. Implement this for new APIs like OpenAI, Anthropic, etc.
#[async_trait]
pub trait LlmBackend: Send + Sync {
    async fn generate(
        &self,
        prompt: &str,
        model: &str,
        options: Option<GenerateOptions>,
    ) -> Result<String, LlmError>;

    async fn chat(
        &self,
        messages: Vec<ChatMessage>,
        model: &str,
        options: Option<GenerateOptions>,
    ) -> Result<String, LlmError>;

    async fn embed(&self, text: &str, model: &str) -> Result<Vec<f32>, LlmError> {
        // Default implementation returns empty vec, can be overridden
        Err(LlmError::Other(anyhow::anyhow!("Embedding not implemented")))
    }
}

pub struct OllamaBackend {
    client: Client,
    base_url: String,
}

impl OllamaBackend {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }
}

#[async_trait]
impl LlmBackend for OllamaBackend {
    async fn generate(
        &self,
        prompt: &str,
        model: &str,
        options: Option<GenerateOptions>,
    ) -> Result<String, LlmError> {
        let url = format!("{}/api/generate", self.base_url);

        #[derive(Serialize)]
        struct Request {
            model: String,
            prompt: String,
            stream: bool,
            options: Option<OllamaOptions>,
        }

        #[derive(Serialize)]
        struct OllamaOptions {
            temperature: Option<f32>,
            num_predict: Option<u32>,
            top_p: Option<f32>,
            frequency_penalty: Option<f32>,
            presence_penalty: Option<f32>,
        }

        let ollama_options = options.map(|opts| OllamaOptions {
            temperature: opts.temperature,
            num_predict: opts.max_tokens,
            top_p: opts.top_p,
            frequency_penalty: opts.frequency_penalty,
            presence_penalty: opts.presence_penalty,
        });

        let request = Request {
            model: model.to_string(),
            prompt: prompt.to_string(),
            stream: false,
            options: ollama_options,
        };

        let response = self.client.post(&url).json(&request).send().await?;
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(LlmError::Api(format!("HTTP {}: {}", status, error_text)));
        }
        let response_text = response.text().await?;

        #[derive(Deserialize)]
        struct Response {
            response: String,
            done: bool,
        }

        let parsed: Response = serde_json::from_str(&response_text)?;
        if parsed.done {
            Ok(parsed.response)
        } else {
            Err(LlmError::Api("Generation not done".to_string()))
        }
    }

    async fn chat(
        &self,
        messages: Vec<ChatMessage>,
        model: &str,
        options: Option<GenerateOptions>,
    ) -> Result<String, LlmError> {
        let url = format!("{}/api/chat", self.base_url);

        #[derive(Serialize)]
        struct Request {
            model: String,
            messages: Vec<OllamaMessage>,
            stream: bool,
            options: Option<OllamaOptions>,
        }

        #[derive(Serialize, Deserialize)]
        struct OllamaMessage {
            role: String,
            content: String,
        }

        #[derive(Serialize)]
        struct OllamaOptions {
            temperature: Option<f32>,
            num_predict: Option<u32>,
            top_p: Option<f32>,
            frequency_penalty: Option<f32>,
            presence_penalty: Option<f32>,
        }

        let ollama_messages: Vec<OllamaMessage> = messages
            .into_iter()
            .map(|msg| OllamaMessage {
                role: msg.role.to_string(),
                content: msg.content,
            })
            .collect();

        let ollama_options = options.map(|opts| OllamaOptions {
            temperature: opts.temperature,
            num_predict: opts.max_tokens,
            top_p: opts.top_p,
            frequency_penalty: opts.frequency_penalty,
            presence_penalty: opts.presence_penalty,
        });

        let request = Request {
            model: model.to_string(),
            messages: ollama_messages,
            stream: false,
            options: ollama_options,
        };

        let response = self.client.post(&url).json(&request).send().await?;
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(LlmError::Api(format!("HTTP {}: {}", status, error_text)));
        }
        let response_text = response.text().await?;

        #[derive(Deserialize)]
        struct Response {
            message: OllamaMessage,
            done: bool,
        }

        let parsed: Response = serde_json::from_str(&response_text)?;
        if parsed.done {
            Ok(parsed.message.content)
        } else {
            Err(LlmError::Api("Chat not done".to_string()))
        }
    }

    async fn embed(&self, text: &str, model: &str) -> Result<Vec<f32>, LlmError> {
        let url = format!("{}/api/embeddings", self.base_url);

        #[derive(Serialize)]
        struct Request {
            model: String,
            prompt: String,
        }

        let request = Request {
            model: model.to_string(),
            prompt: text.to_string(),
        };

        let response = self.client.post(&url).json(&request).send().await?;
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(LlmError::Api(format!("HTTP {}: {}", status, error_text)));
        }
        let response_text = response.text().await?;

        #[derive(Deserialize)]
        struct Response {
            embedding: Vec<f32>,
        }

        let parsed: Response = serde_json::from_str(&response_text)?;
        Ok(parsed.embedding)
    }
}

pub struct GrokApiBackend {
    client: Client,
    api_key: String,
    base_url: String,
}

impl GrokApiBackend {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
            base_url: "https://api.x.ai".to_string(),
        }
    }
}

#[async_trait]
impl LlmBackend for GrokApiBackend {
    async fn generate(
        &self,
        prompt: &str,
        model: &str,
        options: Option<GenerateOptions>,
    ) -> Result<String, LlmError> {
        let messages = vec![ChatMessage {
            role: Role::User,
            content: prompt.to_string(),
        }];
        self.chat(messages, model, options).await
    }

    async fn chat(
        &self,
        messages: Vec<ChatMessage>,
        model: &str,
        options: Option<GenerateOptions>,
    ) -> Result<String, LlmError> {
        let url = "https://api.x.ai/v1/chat/completions";

        #[derive(Serialize, Deserialize)]
        struct GrokMessage {
            role: String,
            content: String,
        }

        #[derive(Serialize)]
        struct Request {
            model: String,
            messages: Vec<GrokMessage>,
            temperature: Option<f32>,
            max_tokens: Option<u32>,
            top_p: Option<f32>,
            frequency_penalty: Option<f32>,
            presence_penalty: Option<f32>,
        }

        let grok_messages: Vec<GrokMessage> = messages
            .into_iter()
            .map(|msg| GrokMessage {
                role: msg.role.to_string(),
                content: msg.content,
            })
            .collect();

        let request = Request {
            model: model.to_string(),
            messages: grok_messages,
            temperature: options.as_ref().and_then(|o| o.temperature),
            max_tokens: options.as_ref().and_then(|o| o.max_tokens),
            top_p: options.as_ref().and_then(|o| o.top_p),
            frequency_penalty: options.as_ref().and_then(|o| o.frequency_penalty),
            presence_penalty: options.as_ref().and_then(|o| o.presence_penalty),
        };

        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(LlmError::Api(format!("HTTP {}: {}", status, error_text)));
        }
        let response_text = response.text().await?;

        #[derive(Deserialize)]
        struct GrokResponse {
            choices: Vec<GrokChoice>,
        }

        #[derive(Deserialize)]
        struct GrokChoice {
            message: GrokMessage,
        }

        let parsed: GrokResponse = serde_json::from_str(&response_text)?;
        if let Some(choice) = parsed.choices.first() {
            Ok(choice.message.content.clone())
        } else {
            Err(LlmError::Api("No choices in response".to_string()))
        }
    }

    async fn embed(&self, text: &str, model: &str) -> Result<Vec<f32>, LlmError> {
        let url = format!("{}/api/embeddings", self.base_url);

        #[derive(Serialize)]
        struct Request {
            model: String,
            prompt: String,
        }

        let request = Request {
            model: model.to_string(),
            prompt: text.to_string(),
        };

        let response = self.client.post(&url).json(&request).send().await?;
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(LlmError::Api(format!("HTTP {}: {}", status, error_text)));
        }
        let response_text = response.text().await?;

        #[derive(Deserialize)]
        struct Response {
            embedding: Vec<f32>,
        }

        let parsed: Response = serde_json::from_str(&response_text)?;
        Ok(parsed.embedding)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum LogSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for LogSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogSeverity::Low => write!(f, "Low"),
            LogSeverity::Medium => write!(f, "Medium"),
            LogSeverity::High => write!(f, "High"),
            LogSeverity::Critical => write!(f, "Critical"),
        }
    }
}

impl FromStr for LogSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(LogSeverity::Low),
            "medium" => Ok(LogSeverity::Medium),
            "high" => Ok(LogSeverity::High),
            "critical" => Ok(LogSeverity::Critical),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: LogSeverity,
    pub summary: String,
    pub details: Option<String>,
    pub related_alerts: Vec<String>,
    pub confidence: f32,
}

pub struct SiemAnalyzer {
    backend: Box<dyn LlmBackend + Send + Sync>,
    model: String,
    grok_backend: Option<Box<dyn LlmBackend + Send + Sync>>,
    grok_model: Option<String>,
    confidence_threshold: f32,
    chroma_store: Option<storage::ChromaStore>,
    embedding_model: String,
    pub alert_min_severity: LogSeverity,
    pub alert_channels: Vec<alerting::AlertChannel>,
}

/// Helper function to emit pipeline events through the broadcast channel
/// 
/// # Arguments
/// * `tx` - Optional broadcast sender for pipeline events
/// * `stage` - Stage name (e.g., "Input.Syslog", "Anonymizer", "Ollama.Triage")
/// * `status` - Pipeline status (Started, Completed, Error)
/// * `log_snippet` - First 100 chars of the log being processed
/// * `model` - Optional model name that processed this stage
/// * `latency_ms` - Optional processing time in milliseconds
/// * `confidence` - Optional confidence score (0.0-1.0)
/// * `next_stage` - Optional next stage in the pipeline
fn emit_pipeline_event(
    tx: &Option<&broadcast::Sender<PipelineEvent>>,
    stage: &str,
    status: PipelineStatus,
    log_snippet: &str,
    model: Option<String>,
    latency_ms: Option<u64>,
    confidence: Option<f32>,
    next_stage: Option<&str>,
) {
    if let Some(tx) = tx {
        let event = PipelineEvent {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            stage: stage.to_string(),
            status,
            log_snippet: log_snippet.to_string(),
            model,
            latency_ms,
            confidence,
            next_stage: next_stage.map(|s| s.to_string()),
        };
        
        // Console logging for verification
        let status_str = format!("{:?}", event.status);
        match (event.latency_ms, event.confidence) {
            (Some(lat), Some(conf)) => println!("📊 [{}] {} {} ({}ms, confidence: {:.2})", 
                event.stage, status_str, 
                event.model.as_deref().unwrap_or("-"), 
                lat, conf),
            (Some(lat), None) => println!("📊 [{}] {} {} ({}ms)", 
                event.stage, status_str, 
                event.model.as_deref().unwrap_or("-"), 
                lat),
            (None, Some(conf)) => println!("📊 [{}] {} (confidence: {:.2})", 
                event.stage, status_str, conf),
            (None, None) => println!("📊 [{}] {}", event.stage, status_str),
        }
        
        let _ = tx.send(event);
    }
}

impl SiemAnalyzer {
    pub fn new(backend: Box<dyn LlmBackend + Send + Sync>, model: String) -> Self {
        Self {
            backend,
            model,
            grok_backend: None,
            grok_model: None,
            confidence_threshold: 0.7,
            chroma_store: None,
            embedding_model: "nomic-embed-text".to_string(),
            alert_min_severity: LogSeverity::High,
            alert_channels: vec![alerting::AlertChannel::Console],
        }
    }

    pub fn with_grok_backend(mut self, backend: Box<dyn LlmBackend + Send + Sync>, model: String) -> Self {
        self.grok_backend = Some(backend);
        self.grok_model = Some(model);
        self
    }

    pub fn with_confidence_threshold(mut self, threshold: f32) -> Self {
        self.confidence_threshold = threshold;
        self
    }

    pub fn with_chroma_store(mut self, store: storage::ChromaStore) -> Self {
        self.chroma_store = Some(store);
        self
    }

    pub fn with_embedding_model(mut self, model: String) -> Self {
        self.embedding_model = model;
        self
    }

    pub fn with_alerting(mut self, min_severity: LogSeverity, channels: Vec<alerting::AlertChannel>) -> Self {
        self.alert_min_severity = min_severity;
        self.alert_channels = channels;
        self
    }

    async fn analyze_with_backend(
        &self,
        backend: &dyn LlmBackend,
        model: &str,
        sanitized_log: &str,
        retrieved_contexts: &[storage::RetrievedContext],
    ) -> Result<AnalysisResult, LlmError> {
        let prompt = ingestion::build_analysis_prompt(sanitized_log, None, Some(retrieved_contexts));
        let response = backend.generate(&prompt, model, None).await?;

        // Parse the JSON response
        let mut parsed: AnalysisResult = serde_json::from_str(&response)
            .map_err(|e| LlmError::Parse(e))?;

        // Ensure confidence is within valid range
        parsed.confidence = parsed.confidence.clamp(0.0, 1.0);

        Ok(parsed)
    }

    pub async fn analyze_log_with_events(&self, log_entry: &str, event_tx: Option<&broadcast::Sender<PipelineEvent>>) -> Result<AnalysisResult, LlmError> {
        let log_snippet = log_entry.chars().take(100).collect::<String>();

        // Input stage - Started
        emit_pipeline_event(
            &event_tx,
            "Input.Syslog",
            PipelineStatus::Started,
            &log_snippet,
            None,
            None,
            None,
            Some("Anonymizer"),
        );

        let start_time = std::time::Instant::now();
        let (sanitized, masked) = ingestion::anonymize_log(log_entry);
        let anonymize_latency = start_time.elapsed().as_millis() as u64;

        // Anonymizer stage - Completed
        let sanitized_snippet = sanitized.chars().take(100).collect::<String>();
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

        // Embedding stage
        let embed_start = std::time::Instant::now();
        let retrieved_contexts = if let Some(store) = &self.chroma_store {
            match self.backend.embed(&sanitized, &self.embedding_model).await {
                Ok(query_embedding) => {
                    let embed_latency = embed_start.elapsed().as_millis() as u64;
                    emit_pipeline_event(
                        &event_tx,
                        "Embedder",
                        PipelineStatus::Completed,
                        &sanitized_snippet,
                        Some(self.embedding_model.clone()),
                        Some(embed_latency),
                        None,
                        Some("Chroma.RAG"),
                    );
                    store.retrieve_context(query_embedding, 3, 0.7).await
                        .map_err(|e| LlmError::Other(anyhow::anyhow!("Storage error: {}", e)))?
                }
                Err(e) => {
                    emit_pipeline_event(
                        &event_tx,
                        "Embedder",
                        PipelineStatus::Error,
                        &sanitized_snippet,
                        Some(self.embedding_model.clone()),
                        Some(embed_start.elapsed().as_millis() as u64),
                        None,
                        None,
                    );
                    return Err(e);
                }
            }
        } else {
            Vec::new()
        };

        // Chroma RAG stage
        emit_pipeline_event(
            &event_tx,
            "Chroma.RAG",
            PipelineStatus::Completed,
            &log_snippet,
            None,
            None,
            None,
            Some("Ollama.Triage"),
        );

        // Triage stage
        let triage_start = std::time::Instant::now();
        let mut result = self.analyze_with_backend(
            self.backend.as_ref(),
            &self.model,
            &sanitized,
            &retrieved_contexts,
        ).await?;
        let triage_latency = triage_start.elapsed().as_millis() as u64;

        emit_pipeline_event(
            &event_tx,
            "Ollama.Triage",
            PipelineStatus::Completed,
            &log_snippet,
            Some(self.model.clone()),
            Some(triage_latency),
            Some(result.confidence),
            Some("ConfidenceRouter"),
        );

        // Confidence Router
        if result.confidence < self.confidence_threshold {
            emit_pipeline_event(
                &event_tx,
                "ConfidenceRouter",
                PipelineStatus::Completed,
                &log_snippet,
                None,
                None,
                Some(result.confidence),
                Some("Grok.Fallback"),
            );

            // Grok Fallback
            if let (Some(grok_backend), Some(grok_model)) = (&self.grok_backend, &self.grok_model) {
                let grok_start = std::time::Instant::now();
                match self.analyze_with_backend(
                    grok_backend.as_ref(),
                    grok_model,
                    &sanitized,
                    &retrieved_contexts,
                ).await {
                    Ok(grok_result) => {
                        let grok_latency = grok_start.elapsed().as_millis() as u64;
                        if grok_result.confidence > result.confidence {
                            result = grok_result;
                        }
                        emit_pipeline_event(
                            &event_tx,
                            "Grok.Fallback",
                            PipelineStatus::Completed,
                            &log_snippet,
                            Some(grok_model.clone()),
                            Some(grok_latency),
                            Some(result.confidence),
                            Some("AlertGenerator"),
                        );
                    }
                    Err(_) => {
                        emit_pipeline_event(
                            &event_tx,
                            "Grok.Fallback",
                            PipelineStatus::Error,
                            &log_snippet,
                            Some(grok_model.clone()),
                            Some(grok_start.elapsed().as_millis() as u64),
                            None,
                            Some("AlertGenerator"),
                        );
                    }
                }
            }
        } else {
            emit_pipeline_event(
                &event_tx,
                "ConfidenceRouter",
                PipelineStatus::Completed,
                &log_snippet,
                None,
                None,
                Some(result.confidence),
                Some("AlertGenerator"),
            );
        }

        // Alert Generator
        emit_pipeline_event(
            &event_tx,
            "AlertGenerator",
            PipelineStatus::Completed,
            &log_snippet,
            None,
            None,
            Some(result.confidence),
            Some("Storage"),
        );

        // Storage
        if let Some(store) = &self.chroma_store {
            let embedding = self.backend.embed(&sanitized, &self.embedding_model).await?;
            let id = uuid::Uuid::new_v4().to_string();
            let mut metadata = std::collections::HashMap::new();
            metadata.insert("severity".to_string(), serde_json::to_value(&result.severity).unwrap());
            metadata.insert("confidence".to_string(), serde_json::to_value(result.confidence).unwrap());
            metadata.insert("timestamp".to_string(), serde_json::to_value(chrono::Utc::now()).unwrap());
            store.store_embedding(&id, &sanitized, embedding, metadata).await
                .map_err(|e| LlmError::Other(anyhow::anyhow!("Storage error: {}", e)))?;
        }

        emit_pipeline_event(
            &event_tx,
            "Storage",
            PipelineStatus::Completed,
            &log_snippet,
            None,
            None,
            None,
            None,
        );

        Ok(result)
    }

    pub async fn analyze_log(&self, log_entry: &str) -> Result<AnalysisResult, LlmError> {
        self.analyze_log_with_events(log_entry, None).await
    }

    pub async fn analyze_logs_batch(&self, log_entries: Vec<String>, alert_manager: Option<&mut alerting::AlertManager>) -> Result<Vec<AnalysisResult>, LlmError> {
        let mut results = Vec::new();
        for log in log_entries {
            let result = self.analyze_log(&log).await?;
            results.push(result);
        }

        // Check for alerting after all analysis
        if let Some(manager) = alert_manager {
            for result in &results {
                if result.severity >= self.alert_min_severity || (result.severity == LogSeverity::Medium && result.confidence < 0.5) {
                    let alert = alerting::Alert::new(
                        // We don't have the original log here, so use summary as id
                        result.summary.clone(),
                        result.severity.clone(),
                        result.summary.clone(),
                        "Review and investigate".to_string(),
                        result.confidence,
                    );
                    if let Err(e) = alerting::trigger_alert(&alert, &self.alert_channels, manager).await {
                        eprintln!("Alert error: {}", e);
                    }
                }
            }
        }

        Ok(results)
    }

    pub async fn process_log_file(&self, file_path: &str, alert_manager: Option<&mut alerting::AlertManager>) -> Result<Vec<AnalysisResult>, LlmError> {
        let log_entries = ingestion::ingest_logs(file_path)
            .await
            .map_err(|e| LlmError::Other(anyhow::anyhow!("Ingestion error: {}", e)))?;

        let raw_logs: Vec<String> = log_entries.into_iter().map(|e| e.raw).collect();

        self.analyze_logs_batch(raw_logs, alert_manager).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::fs;
    use tokio::test;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Unit tests for anonymize_log
    #[tokio::test]
    async fn test_anonymize_log_masks_ipv4() {
        let log = "Failed login from 192.168.1.100";
        let (result, masked) = ingestion::anonymize_log(log);
        assert_eq!(result, "Failed login from [IP]");
        assert!(masked.contains(&"IPv4 address".to_string()));
    }

    #[tokio::test]
    async fn test_anonymize_log_masks_ipv6() {
        let log = "Connect from 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let (result, masked) = ingestion::anonymize_log(log);
        assert_eq!(result, "Connect from [IPV6]");
    }

    #[tokio::test]
    async fn test_anonymize_log_masks_username() {
        let log = "user=admin logged in";
        let (result, masked) = ingestion::anonymize_log(log);
        assert_eq!(result, "user=[USER] logged in");
        assert!(masked.contains(&"username".to_string()));
    }

    #[tokio::test]
    async fn test_anonymize_log_masks_email() {
        let log = "Email sent to user@example.com";
        let (result, masked) = ingestion::anonymize_log(log);
        assert_eq!(result, "Email sent to [EMAIL]");
    }

    #[tokio::test]
    async fn test_anonymize_log_masks_api_key() {
        let log = "API key: abc123def456ghi789jkl012mno345pqr678stu901vwx";
        let (result, masked) = ingestion::anonymize_log(log);
        assert_eq!(result, "API key: [KEY]");
    }

    #[tokio::test]
    async fn test_anonymize_log_empty_string() {
        let log = "";
        let (result, masked) = ingestion::anonymize_log(log);
        assert_eq!(result, "");
        assert!(masked.is_empty());
    }

    #[tokio::test]
    async fn test_anonymize_log_no_matches() {
        let log = "This is a normal log message";
        let (result, masked) = ingestion::anonymize_log(log);
        assert_eq!(result, log);
        assert!(masked.is_empty());
    }



    // Unit tests for build_analysis_prompt
    #[tokio::test]
    async fn test_build_analysis_prompt_basic() {
        let log = "Failed login attempt";
        let prompt = ingestion::build_analysis_prompt(log, None, None);
        assert!(prompt.contains("Log Entry: Failed login attempt"));
        assert!(prompt.contains("Respond ONLY with valid JSON"));
    }

    #[tokio::test]
    async fn test_build_analysis_prompt_with_context() {
        let log = "Error occurred";
        let context = "Previous logs show similar errors";
        let prompt = ingestion::build_analysis_prompt(log, Some(context), None);
        assert!(prompt.contains("Log Entry: Error occurred"));
        assert!(prompt.contains("Additional Context: Previous logs show similar errors"));
    }

    // Integration test for process_log_file
    #[tokio::test]
    async fn test_process_log_file_integration() {
        // Create a temporary log file
        let temp_file = "test_logs.txt";
        let log_content = "Feb 20 14:30:15 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2\n\
                           Feb 20 14:31:00 server kernel: [ 1234.567890] CPU0: Core temperature above threshold, running at 95 C\n";
        fs::write(temp_file, log_content).unwrap();

        // Start mock server
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "response": "{\"id\": \"test-id\", \"timestamp\": \"2026-02-20T14:30:00Z\", \"severity\": \"medium\", \"summary\": \"Test explanation\", \"details\": null, \"related_alerts\": [], \"confidence\": 0.8}",
                "done": true
            })))
            .mount(&mock_server)
            .await;

        let backend = OllamaBackend::new(mock_server.uri());
        let analyzer = SiemAnalyzer::new(Box::new(backend), "test-model".to_string());

        let results = analyzer.process_log_file(temp_file, None).await.unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].severity, LogSeverity::Medium);

        // Cleanup
        fs::remove_file(temp_file).unwrap();
    }

    #[tokio::test]
    async fn test_ollama_embed() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/embeddings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "embedding": [0.1, 0.2, 0.3]
            })))
            .mount(&mock_server)
            .await;

        let backend = OllamaBackend::new(mock_server.uri());
        let result = backend.embed("test text", "nomic-embed-text").await.unwrap();
        assert_eq!(result, vec![0.1, 0.2, 0.3]);
    }
}
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IngestionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub raw: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub source: String,
    pub sanitized: Option<String>,
}

impl LogEntry {
    pub fn new(raw: String, source: String) -> Self {
        Self {
            raw,
            timestamp: None, // Could parse from raw if needed
            source,
            sanitized: None,
        }
    }

    pub fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
}

pub async fn ingest_logs(path: &str) -> Result<Vec<LogEntry>, IngestionError> {
    let content = fs::read_to_string(path)?;
    let mut entries = Vec::new();

    for line in content.lines() {
        if !line.trim().is_empty() {
            let entry = LogEntry::new(line.to_string(), path.to_string());
            entries.push(entry);
        }
    }

    Ok(entries)
}

pub fn anonymize_log(raw: &str) -> (String, Vec<String>) {
    let mut result = raw.to_string();
    let mut masked_fields = Vec::new();

    // Mask IPv4 addresses
    let ipv4_regex = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
    if ipv4_regex.is_match(&result) {
        masked_fields.push("IPv4 address".to_string());
        result = ipv4_regex.replace_all(&result, "[IP]").to_string();
    }

    // Mask IPv6 addresses (simplified)
    let ipv6_regex = Regex::new(r"\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b").unwrap();
    if ipv6_regex.is_match(&result) {
        masked_fields.push("IPv6 address".to_string());
        result = ipv6_regex.replace_all(&result, "[IPV6]").to_string();
    }

    // Mask usernames (patterns like user=..., username: ...)
    let user_regex = Regex::new(r"\b(user|username)[=:]\s*([^\s]+)").unwrap();
    if user_regex.is_match(&result) {
        masked_fields.push("username".to_string());
        result = user_regex.replace_all(&result, "$1=[USER]").to_string();
    }

    // Mask emails
    let email_regex = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
    if email_regex.is_match(&result) {
        masked_fields.push("email".to_string());
        result = email_regex.replace_all(&result, "[EMAIL]").to_string();
    }

    // Mask API keys/hashes (long alphanumeric strings)
    let key_regex = Regex::new(r"\b[A-Za-z0-9]{20,}\b").unwrap();
    if key_regex.is_match(&result) {
        masked_fields.push("API key/hash".to_string());
        result = key_regex.replace_all(&result, "[KEY]").to_string();
    }

    // Mask hex values (0x...)
    let hex_regex = Regex::new(r"\b0x[0-9a-fA-F]+\b").unwrap();
    if hex_regex.is_match(&result) {
        masked_fields.push("hex value".to_string());
        result = hex_regex.replace_all(&result, "[HEX]").to_string();
    }

    (result, masked_fields)
}

pub fn build_analysis_prompt(sanitized_log: &str, context: Option<&str>, retrieved_contexts: Option<&[super::storage::RetrievedContext]>) -> String {
    let base_prompt = format!(
        "You are a SIEM threat analyst. Analyze this sanitized log line for anomalies, threats, or suspicious activity:\n\n\
        Log Entry: {}\n\n\
        Respond ONLY with valid JSON: {{\"severity\": \"medium\", \"explanation\": \"brief explanation\", \"recommended_action\": \"action to take\", \"confidence\": 0.8}}",
        sanitized_log
    );

    let mut prompt = base_prompt;

    if let Some(ctx) = context {
        prompt = format!("{}\n\nAdditional Context: {}", prompt, ctx);
    }

    if let Some(contexts) = retrieved_contexts {
        if !contexts.is_empty() {
            prompt = format!("{}\n\nHistorical similar incidents:", prompt);
            for (i, ctx) in contexts.iter().enumerate() {
                prompt = format!("{}\n{}. {}", prompt, i + 1, ctx.text);
            }
        }
    }

    prompt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ingest_logs() {
        // Create a temporary log file
        let temp_file = "test_ingest.log";
        let log_content = "Feb 20 14:30:15 server sshd[1234]: Failed password\n\
                           Feb 20 14:31:00 server kernel: CPU temp high\n";
        fs::write(temp_file, log_content).unwrap();

        let entries = ingest_logs(temp_file).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].raw, "Feb 20 14:30:15 server sshd[1234]: Failed password");
        assert_eq!(entries[0].source, temp_file);

        fs::remove_file(temp_file).unwrap();
    }

    #[tokio::test]
    async fn test_anonymize_log() {
        let log = "Failed login from 192.168.1.100 by user=admin with key abc123def456ghi789jkl012mno345pqr678stu901vwx";
        let (sanitized, masked) = anonymize_log(log);
        assert_eq!(sanitized, "Failed login from [IP] by user=[USER] with key [KEY]");
        assert!(masked.contains(&"IPv4 address".to_string()));
        assert!(masked.contains(&"username".to_string()));
        assert!(masked.contains(&"API key/hash".to_string()));
    }

    #[tokio::test]
    async fn test_build_analysis_prompt() {
        let log = "Failed login attempt";
        let prompt = build_analysis_prompt(log, None, None);
        assert!(prompt.contains("Log Entry: Failed login attempt"));
        assert!(prompt.contains("Respond ONLY with valid JSON"));
    }
}
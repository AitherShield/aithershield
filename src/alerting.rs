use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum AlertError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub log_entry_id: String,
    pub severity: crate::LogSeverity,
    pub explanation: String,
    pub action: String,
    pub confidence: f32,
}

impl Alert {
    pub fn new(
        log_entry_id: String,
        severity: crate::LogSeverity,
        explanation: String,
        action: String,
        confidence: f32,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            log_entry_id,
            severity,
            explanation,
            action,
            confidence,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AlertChannel {
    Console,
    File(String), // path
}

pub struct AlertManager {
    dedup_cache: HashSet<String>, // hash of content + severity
    dedup_ttl_secs: i64, // time to live in seconds
    last_cleanup: DateTime<Utc>,
}

impl Default for AlertManager {
    fn default() -> Self {
        Self {
            dedup_cache: HashSet::new(),
            dedup_ttl_secs: 600, // 10 minutes
            last_cleanup: Utc::now(),
        }
    }
}

impl AlertManager {
    pub fn new(dedup_ttl_secs: i64) -> Self {
        Self {
            dedup_cache: HashSet::new(),
            dedup_ttl_secs,
            last_cleanup: Utc::now(),
        }
    }

    // Check if alert should be deduplicated
    pub fn should_alert(&mut self, alert: &Alert) -> bool {
        // Cleanup old entries periodically
        if (Utc::now() - self.last_cleanup).num_seconds() > 60 {
            // In a real impl, we'd remove expired entries, but for simplicity, just reset every minute
            self.dedup_cache.clear();
            self.last_cleanup = Utc::now();
        }

        let hash = format!("{}:{:?}", alert.log_entry_id, alert.severity);
        if self.dedup_cache.contains(&hash) {
            false
        } else {
            self.dedup_cache.insert(hash);
            true
        }
    }
}

pub async fn trigger_alert(
    alert: &Alert,
    channels: &[AlertChannel],
    manager: &mut AlertManager,
) -> Result<(), AlertError> {
    if !manager.should_alert(alert) {
        return Ok(()); // Deduplicated
    }

    for channel in channels {
        match channel {
            AlertChannel::Console => {
                let color = match alert.severity {
                    crate::LogSeverity::Low => "green",
                    crate::LogSeverity::Medium => "yellow",
                    crate::LogSeverity::High => "red",
                    crate::LogSeverity::Critical => "magenta",
                };
                println!(
                    "{} {} [{}] {} (Confidence: {:.2})",
                    "🚨 ALERT".color(color).bold(),
                    alert.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    alert.severity,
                    alert.explanation,
                    alert.confidence
                );
                println!("   Action: {}", alert.action);
            }
            AlertChannel::File(path) => {
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                let json = serde_json::to_string(alert)?;
                writeln!(file, "{}", json)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LogSeverity;

    #[tokio::test]
    async fn test_console_alert() {
        let alert = Alert::new(
            "test-log".to_string(),
            LogSeverity::High,
            "Test alert".to_string(),
            "Take action".to_string(),
            0.9,
        );
        let channels = vec![AlertChannel::Console];
        let mut manager = AlertManager::default();

        // This should print to console
        trigger_alert(&alert, &channels, &mut manager).await.unwrap();
    }

    #[tokio::test]
    async fn test_file_alert() {
        let alert = Alert::new(
            "test-log".to_string(),
            LogSeverity::High,
            "Test alert".to_string(),
            "Take action".to_string(),
            0.9,
        );
        let channels = vec![AlertChannel::File("test_alerts.log".to_string())];
        let mut manager = AlertManager::default();

        trigger_alert(&alert, &channels, &mut manager).await.unwrap();

        // Check file exists and has content
        let content = std::fs::read_to_string("test_alerts.log").unwrap();
        assert!(content.contains("Test alert"));
    }

    #[test]
    fn test_deduplication() {
        let mut manager = AlertManager::default();
        let alert1 = Alert::new(
            "same-log".to_string(),
            LogSeverity::High,
            "Alert".to_string(),
            "Action".to_string(),
            0.9,
        );
        let alert2 = Alert::new(
            "same-log".to_string(),
            LogSeverity::High,
            "Alert".to_string(),
            "Action".to_string(),
            0.9,
        );

        assert!(manager.should_alert(&alert1));
        assert!(!manager.should_alert(&alert2)); // Should be deduped
    }
}
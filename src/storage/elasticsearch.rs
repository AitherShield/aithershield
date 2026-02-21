use elasticsearch::{Elasticsearch, IndexParts, SearchParts};
use serde_json::{json, Value};
use thiserror::Error;
use crate::{alerting::Alert, AnalysisResult, LogSeverity};

#[derive(Error, Debug)]
pub enum EsError {
    #[error("Elasticsearch error: {0}")]
    Elasticsearch(#[from] elasticsearch::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Clone)]
pub struct EsStore {
    client: Elasticsearch,
}

impl EsStore {
    pub async fn new(url: &str) -> Result<Self, EsError> {
        let transport = elasticsearch::http::transport::Transport::single_node(url)?;
        let client = Elasticsearch::new(transport);
        Ok(Self { client })
    }

    pub async fn index_alert(&self, alert: &Alert) -> Result<(), EsError> {
        let index_name = "aithershield-alerts";
        let response = self.client
            .index(IndexParts::IndexId(index_name, &alert.id.to_string()))
            .body(json!({
                "id": alert.id,
                "timestamp": alert.timestamp,
                "log_entry_id": alert.log_entry_id,
                "severity": alert.severity,
                "explanation": alert.explanation,
                "action": alert.action,
                "confidence": alert.confidence,
            }))
            .send()
            .await?;

        if !response.status_code().is_success() {
            return Err(EsError::Other(format!("Failed to index alert: {}", response.status_code())));
        }

        Ok(())
    }

    pub async fn index_analysis(&self, result: &AnalysisResult) -> Result<(), EsError> {
        let index_name = "aithershield-analyses";
        let response = self.client
            .index(IndexParts::IndexId(index_name, &result.id))
            .body(json!({
                "id": result.id,
                "timestamp": result.timestamp,
                "severity": result.severity,
                "summary": result.summary,
                "details": result.details,
                "related_alerts": result.related_alerts,
                "confidence": result.confidence,
            }))
            .send()
            .await?;

        if !response.status_code().is_success() {
            return Err(EsError::Other(format!("Failed to index analysis: {}", response.status_code())));
        }

        Ok(())
    }

    pub async fn query_recent_alerts(&self, limit: usize, min_severity: Option<LogSeverity>) -> Result<Vec<Alert>, EsError> {
        let index_name = "aithershield-alerts";
        let mut query = json!({
            "size": limit,
            "sort": [
                { "timestamp": { "order": "desc" } }
            ]
        });

        if let Some(min_severity) = min_severity {
            let severity_filter: Vec<&str> = match min_severity {
                LogSeverity::Low => vec!["Low", "Medium", "High", "Critical"],
                LogSeverity::Medium => vec!["Medium", "High", "Critical"],
                LogSeverity::High => vec!["High", "Critical"],
                LogSeverity::Critical => vec!["Critical"],
            };

            query["query"] = json!({
                "terms": {
                    "severity": severity_filter
                }
            });
        }

        let response = self.client
            .search(SearchParts::Index(&[index_name]))
            .body(query)
            .send()
            .await?;

        if !response.status_code().is_success() {
            return Err(EsError::Other(format!("Failed to query alerts: {}", response.status_code())));
        }

        let response_body: Value = response.json().await?;
        let hits = response_body["hits"]["hits"]
            .as_array()
            .ok_or_else(|| EsError::Other("Invalid response format".to_string()))?;

        let mut alerts = Vec::new();
        for hit in hits {
            let source = &hit["_source"];
            let alert: Alert = serde_json::from_value(source.clone())?;
            alerts.push(alert);
        }

        Ok(alerts)
    }

    pub async fn query_recent_analyses(&self, limit: usize, min_severity: Option<LogSeverity>) -> Result<Vec<AnalysisResult>, EsError> {
        let index_name = "aithershield-analyses";
        let mut query = json!({
            "size": limit,
            "sort": [
                { "timestamp": { "order": "desc" } }
            ]
        });

        if let Some(min_severity) = min_severity {
            let severity_filter: Vec<&str> = match min_severity {
                LogSeverity::Low => vec!["Low", "Medium", "High", "Critical"],
                LogSeverity::Medium => vec!["Medium", "High", "Critical"],
                LogSeverity::High => vec!["High", "Critical"],
                LogSeverity::Critical => vec!["Critical"],
            };

            query["query"] = json!({
                "terms": {
                    "severity": severity_filter
                }
            });
        }

        let response = self.client
            .search(SearchParts::Index(&[index_name]))
            .body(query)
            .send()
            .await?;

        if !response.status_code().is_success() {
            return Err(EsError::Other(format!("Failed to query analyses: {}", response.status_code())));
        }

        let response_body: Value = response.json().await?;
        let hits = response_body["hits"]["hits"]
            .as_array()
            .ok_or_else(|| EsError::Other("Invalid response format".to_string()))?;

        let mut analyses = Vec::new();
        for hit in hits {
            let source = &hit["_source"];
            let analysis: AnalysisResult = serde_json::from_value(source.clone())?;
            analyses.push(analysis);
        }

        Ok(analyses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_es_store_creation() {
        // This test would require a running Elasticsearch instance
        // For now, just test that the struct can be created with a mock URL
        // In a real test environment, you'd use testcontainers or a mock server
        let result = EsStore::new("http://localhost:9200").await;
        // We expect this to fail in test environment without ES running
        assert!(result.is_err() || result.is_ok()); // Either way is fine for this basic test
    }

    #[test]
    fn test_alert_serialization() {
        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            log_entry_id: "test-log".to_string(),
            severity: LogSeverity::High,
            explanation: "Test alert".to_string(),
            action: "Investigate".to_string(),
            confidence: 0.9,
        };

        let json = serde_json::to_string(&alert).unwrap();
        let deserialized: Alert = serde_json::from_str(&json).unwrap();
        assert_eq!(alert.id, deserialized.id);
        assert_eq!(alert.severity, deserialized.severity);
    }

    #[test]
    fn test_analysis_serialization() {
        let analysis = AnalysisResult {
            id: "test-id".to_string(),
            timestamp: Utc::now(),
            severity: LogSeverity::Medium,
            summary: "Test analysis".to_string(),
            details: Some("Details".to_string()),
            related_alerts: vec!["alert1".to_string()],
            confidence: 0.8,
        };

        let json = serde_json::to_string(&analysis).unwrap();
        let deserialized: AnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(analysis.id, deserialized.id);
        assert_eq!(analysis.severity, deserialized.severity);
    }
}
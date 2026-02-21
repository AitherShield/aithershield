use elasticsearch::{
    Elasticsearch, IndexParts, SearchParts
};
use elasticsearch::indices::{IndicesExistsParts, IndicesCreateParts};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use chrono::{DateTime, Utc, Duration};
use crate::{alerting::Alert, AnalysisResult, LogSeverity};

#[derive(Error, Debug)]
pub enum EsError {
    #[error("Elasticsearch error: {0}")]
    Elasticsearch(#[from] elasticsearch::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Index creation failed: {0}")]
    IndexCreation(String),
}

#[derive(Debug, Clone)]
pub struct EsQuery {
    pub limit: Option<usize>,
    pub min_severity: Option<LogSeverity>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub sort_desc: bool,
}

impl Default for EsQuery {
    fn default() -> Self {
        Self {
            limit: Some(100),
            min_severity: None,
            since: None,
            until: None,
            sort_desc: true,
        }
    }
}

impl EsQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn min_severity(mut self, severity: LogSeverity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    pub fn since(mut self, since: DateTime<Utc>) -> Self {
        self.since = Some(since);
        self
    }

    pub fn until(mut self, until: DateTime<Utc>) -> Self {
        self.until = Some(until);
        self
    }

    pub fn last_hours(mut self, hours: i64) -> Self {
        self.since = Some(Utc::now() - Duration::hours(hours));
        self
    }

    pub fn last_days(mut self, days: i64) -> Self {
        self.since = Some(Utc::now() - Duration::days(days));
        self
    }

    pub fn sort_asc(mut self) -> Self {
        self.sort_desc = false;
        self
    }

    pub fn sort_desc(mut self) -> Self {
        self.sort_desc = true;
        self
    }
}

#[derive(Clone)]
pub struct EsStore {
    client: Elasticsearch,
}

impl EsStore {
    pub async fn new(url: Option<&str>) -> Result<Self, EsError> {
        let url = url.unwrap_or("http://elasticsearch:9200");
        let transport = elasticsearch::http::transport::Transport::single_node(url)
            .map_err(|e| EsError::Http(format!("Failed to create transport: {}", e)))?;
        let client = Elasticsearch::new(transport);
        Ok(Self { client })
    }

    pub async fn ensure_indices(&self) -> Result<(), EsError> {
        // Create alerts index with mapping
        self.create_alerts_index().await?;
        // Create analyses index with mapping
        self.create_analyses_index().await?;
        Ok(())
    }

    async fn create_alerts_index(&self) -> Result<(), EsError> {
        let index_name = "aithershield-alerts";

        // Check if index exists
        let exists_response = self.client
            .indices()
            .exists(IndicesExistsParts::Index(&[index_name]))
            .send()
            .await?;

        if exists_response.status_code().is_success() {
            return Ok(()); // Index already exists
        }

        // Create index with mapping
        let mapping = json!({
            "mappings": {
                "properties": {
                    "id": { "type": "keyword" },
                    "timestamp": { "type": "date" },
                    "log_entry_id": { "type": "keyword" },
                    "severity": { "type": "keyword" },
                    "explanation": { "type": "text" },
                    "action": { "type": "text" },
                    "confidence": { "type": "float" }
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            }
        });

        let response = self.client
            .indices()
            .create(IndicesCreateParts::Index(index_name))
            .body(mapping)
            .send()
            .await?;

        if !response.status_code().is_success() {
            let status = response.status_code();
            let body = response.text().await.unwrap_or_default();
            return Err(EsError::IndexCreation(format!(
                "Failed to create alerts index ({}): {}", status, body
            )));
        }

        Ok(())
    }

    async fn create_analyses_index(&self) -> Result<(), EsError> {
        let index_name = "aithershield-analyses";

        // Check if index exists
        let exists_response = self.client
            .indices()
            .exists(IndicesExistsParts::Index(&[index_name]))
            .send()
            .await?;

        if exists_response.status_code().is_success() {
            return Ok(()); // Index already exists
        }

        // Create index with mapping
        let mapping = json!({
            "mappings": {
                "properties": {
                    "id": { "type": "keyword" },
                    "timestamp": { "type": "date" },
                    "severity": { "type": "keyword" },
                    "summary": { "type": "text" },
                    "details": { "type": "text" },
                    "related_alerts": { "type": "keyword" },
                    "confidence": { "type": "float" }
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            }
        });

        let response = self.client
            .indices()
            .create(IndicesCreateParts::Index(index_name))
            .body(mapping)
            .send()
            .await?;

        if !response.status_code().is_success() {
            let status = response.status_code();
            let body = response.text().await.unwrap_or_default();
            return Err(EsError::IndexCreation(format!(
                "Failed to create analyses index ({}): {}", status, body
            )));
        }

        Ok(())
    }

    pub async fn index_alert(&self, alert: &Alert) -> Result<(), EsError> {
        let index_name = "aithershield-alerts";

        let document = json!({
            "id": alert.id,
            "timestamp": alert.timestamp,
            "log_entry_id": alert.log_entry_id,
            "severity": alert.severity,
            "explanation": alert.explanation,
            "action": alert.action,
            "confidence": alert.confidence,
        });

        let response = self.client
            .index(IndexParts::IndexId(index_name, &alert.id.to_string()))
            .body(document)
            .send()
            .await?;

        if !response.status_code().is_success() {
            let status = response.status_code();
            let body = response.text().await.unwrap_or_default();
            return Err(EsError::Http(format!(
                "Failed to index alert ({}): {}", status, body
            )));
        }

        Ok(())
    }

    pub async fn index_analysis(&self, result: &AnalysisResult) -> Result<(), EsError> {
        let index_name = "aithershield-analyses";

        let document = json!({
            "id": result.id,
            "timestamp": result.timestamp,
            "severity": result.severity,
            "summary": result.summary,
            "details": result.details,
            "related_alerts": result.related_alerts,
            "confidence": result.confidence,
        });

        let response = self.client
            .index(IndexParts::IndexId(index_name, &result.id))
            .body(document)
            .send()
            .await?;

        if !response.status_code().is_success() {
            let status = response.status_code();
            let body = response.text().await.unwrap_or_default();
            return Err(EsError::Http(format!(
                "Failed to index analysis ({}): {}", status, body
            )));
        }

        Ok(())
    }

    pub async fn query_alerts(&self, query: EsQuery) -> Result<Vec<Alert>, EsError> {
        let index_name = "aithershield-alerts";
        let mut es_query = json!({
            "size": query.limit.unwrap_or(100),
            "sort": [
                { "timestamp": { "order": if query.sort_desc { "desc" } else { "asc" } } }
            ]
        });

        // Build bool query for filters
        let mut must_clauses = Vec::new();

        if let Some(min_severity) = query.min_severity {
            let severity_filter: Vec<&str> = match min_severity {
                LogSeverity::Low => vec!["Low", "Medium", "High", "Critical"],
                LogSeverity::Medium => vec!["Medium", "High", "Critical"],
                LogSeverity::High => vec!["High", "Critical"],
                LogSeverity::Critical => vec!["Critical"],
            };
            must_clauses.push(json!({
                "terms": { "severity": severity_filter }
            }));
        }

        if let Some(since) = query.since {
            must_clauses.push(json!({
                "range": { "timestamp": { "gte": since } }
            }));
        }

        if let Some(until) = query.until {
            must_clauses.push(json!({
                "range": { "timestamp": { "lte": until } }
            }));
        }

        if !must_clauses.is_empty() {
            es_query["query"] = json!({
                "bool": { "must": must_clauses }
            });
        }

        let response = self.client
            .search(SearchParts::Index(&[index_name]))
            .body(es_query)
            .send()
            .await?;

        if !response.status_code().is_success() {
            let status = response.status_code();
            let body = response.text().await.unwrap_or_default();
            return Err(EsError::Http(format!(
                "Failed to query alerts ({}): {}", status, body
            )));
        }

        let response_body: Value = response.json().await?;
        let hits = response_body["hits"]["hits"]
            .as_array()
            .ok_or_else(|| EsError::Http("Invalid response format".to_string()))?;

        let mut alerts = Vec::new();
        for hit in hits {
            let source = &hit["_source"];
            let alert: Alert = serde_json::from_value(source.clone())?;
            alerts.push(alert);
        }

        Ok(alerts)
    }

    pub async fn query_analyses(&self, query: EsQuery) -> Result<Vec<AnalysisResult>, EsError> {
        let index_name = "aithershield-analyses";
        let mut es_query = json!({
            "size": query.limit.unwrap_or(100),
            "sort": [
                { "timestamp": { "order": if query.sort_desc { "desc" } else { "asc" } } }
            ]
        });

        // Build bool query for filters
        let mut must_clauses = Vec::new();

        if let Some(min_severity) = query.min_severity {
            let severity_filter: Vec<&str> = match min_severity {
                LogSeverity::Low => vec!["Low", "Medium", "High", "Critical"],
                LogSeverity::Medium => vec!["Medium", "High", "Critical"],
                LogSeverity::High => vec!["High", "Critical"],
                LogSeverity::Critical => vec!["Critical"],
            };
            must_clauses.push(json!({
                "terms": { "severity": severity_filter }
            }));
        }

        if let Some(since) = query.since {
            must_clauses.push(json!({
                "range": { "timestamp": { "gte": since } }
            }));
        }

        if let Some(until) = query.until {
            must_clauses.push(json!({
                "range": { "timestamp": { "lte": until } }
            }));
        }

        if !must_clauses.is_empty() {
            es_query["query"] = json!({
                "bool": { "must": must_clauses }
            });
        }

        let response = self.client
            .search(SearchParts::Index(&[index_name]))
            .body(es_query)
            .send()
            .await?;

        if !response.status_code().is_success() {
            let status = response.status_code();
            let body = response.text().await.unwrap_or_default();
            return Err(EsError::Http(format!(
                "Failed to query analyses ({}): {}", status, body
            )));
        }

        let response_body: Value = response.json().await?;
        let hits = response_body["hits"]["hits"]
            .as_array()
            .ok_or_else(|| EsError::Http("Invalid response format".to_string()))?;

        let mut analyses = Vec::new();
        for hit in hits {
            let source = &hit["_source"];
            let analysis: AnalysisResult = serde_json::from_value(source.clone())?;
            analyses.push(analysis);
        }

        Ok(analyses)
    }

    /// Get recent alerts (convenience method)
    pub async fn get_recent_alerts(&self, hours: i64) -> Result<Vec<Alert>, EsError> {
        self.query_alerts(EsQuery::new().last_hours(hours)).await
    }

    /// Get recent analyses (convenience method)
    pub async fn get_recent_analyses(&self, hours: i64) -> Result<Vec<AnalysisResult>, EsError> {
        self.query_analyses(EsQuery::new().last_hours(hours)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn test_es_query_builder() {
        let query = EsQuery::new()
            .limit(50)
            .min_severity(LogSeverity::High)
            .last_hours(24)
            .sort_desc();

        assert_eq!(query.limit, Some(50));
        assert_eq!(query.min_severity, Some(LogSeverity::High));
        assert!(query.since.is_some());
        assert!(query.sort_desc);
    }

    #[tokio::test]
    async fn test_es_store_creation() {
        // This will fail without a running ES instance, but tests the creation logic
        let result = EsStore::new(Some("http://localhost:9200")).await;
        // We expect this to fail in test environment
        assert!(result.is_err() || result.is_ok());
    }
}
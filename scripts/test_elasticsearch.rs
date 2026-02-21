// Quick test script for Elasticsearch integration
// Run with: rustc scripts/test_elasticsearch.rs && ./test_elasticsearch

use std::env;
use aithershield::storage;
use aithershield::{Alert, AnalysisResult, LogSeverity};
use chrono::Utc;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let es_url = env::var("ELASTICSEARCH_URL").unwrap_or_else(|_| "http://localhost:9200".to_string());

    println!("Testing Elasticsearch connection to: {}", es_url);

    let store = match storage::elasticsearch::EsStore::new(&es_url).await {
        Ok(store) => {
            println!("✓ Connected to Elasticsearch");
            store
        }
        Err(e) => {
            println!("✗ Failed to connect: {}", e);
            return Ok(());
        }
    };

    // Create test alert
    let alert = Alert::new(
        "test-log-entry".to_string(),
        LogSeverity::High,
        "Test security alert".to_string(),
        "Investigate immediately".to_string(),
        0.95,
    );

    // Index alert
    match store.index_alert(&alert).await {
        Ok(_) => println!("✓ Indexed alert successfully"),
        Err(e) => println!("✗ Failed to index alert: {}", e),
    }

    // Create test analysis
    let analysis = AnalysisResult {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        severity: LogSeverity::Medium,
        summary: "Test analysis result".to_string(),
        details: Some("Detailed analysis information".to_string()),
        related_alerts: vec![alert.id.to_string()],
        confidence: 0.85,
    };

    // Index analysis
    match store.index_analysis(&analysis).await {
        Ok(_) => println!("✓ Indexed analysis successfully"),
        Err(e) => println!("✗ Failed to index analysis: {}", e),
    }

    // Query recent alerts
    match store.query_recent_alerts(10, None).await {
        Ok(alerts) => println!("✓ Queried {} alerts", alerts.len()),
        Err(e) => println!("✗ Failed to query alerts: {}", e),
    }

    // Query recent analyses
    match store.query_recent_analyses(10, None).await {
        Ok(analyses) => println!("✓ Queried {} analyses", analyses.len()),
        Err(e) => println!("✗ Failed to query analyses: {}", e),
    }

    // Query high severity alerts only
    match store.query_recent_alerts(10, Some(LogSeverity::High)).await {
        Ok(alerts) => println!("✓ Queried {} high-severity alerts", alerts.len()),
        Err(e) => println!("✗ Failed to query high-severity alerts: {}", e),
    }

    println!("Elasticsearch integration test complete!");
    Ok(())
}
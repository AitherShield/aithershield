// Test script for the new EsStore implementation
// Run with: rustc --edition 2024 scripts/test_es_store.rs -L target/debug/deps --extern aithershield=target/debug/libaithershield.rlib && ./test_es_store

use std::env;
use aithershield::storage::es_store::{EsStore, EsQuery, EsError};
use aithershield::{alerting::Alert, AnalysisResult, LogSeverity};
use chrono::{Utc, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let es_url = env::var("ELASTICSEARCH_URL").unwrap_or_else(|_| "http://elasticsearch:9200".to_string());

    println!("Testing EsStore with Elasticsearch at: {}", es_url);

    let store = match EsStore::new(Some(&es_url)).await {
        Ok(store) => {
            println!("✓ Connected to Elasticsearch");
            store
        }
        Err(e) => {
            println!("✗ Failed to connect: {}", e);
            return Ok(());
        }
    };

    // Ensure indices exist
    match store.ensure_indices().await {
        Ok(_) => println!("✓ Indices ensured"),
        Err(e) => {
            println!("✗ Failed to ensure indices: {}", e);
            return Ok(());
        }
    }

    // Create test alert
    let alert = Alert::new(
        "test-log-entry".to_string(),
        LogSeverity::High,
        "Test security alert from EsStore".to_string(),
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
        id: format!("test-analysis-{}", Utc::now().timestamp()),
        timestamp: Utc::now(),
        severity: LogSeverity::Medium,
        summary: "Test analysis result from EsStore".to_string(),
        details: Some("Detailed analysis information".to_string()),
        related_alerts: vec![alert.id.to_string()],
        confidence: 0.85,
    };

    // Index analysis
    match store.index_analysis(&analysis).await {
        Ok(_) => println!("✓ Indexed analysis successfully"),
        Err(e) => println!("✗ Failed to index analysis: {}", e),
    }

    // Test various queries
    println!("\n--- Testing Queries ---");

    // Query recent alerts (last 1 hour)
    match store.get_recent_alerts(1).await {
        Ok(alerts) => println!("✓ Queried {} recent alerts", alerts.len()),
        Err(e) => println!("✗ Failed to query recent alerts: {}", e),
    }

    // Query recent analyses (last 1 hour)
    match store.get_recent_analyses(1).await {
        Ok(analyses) => println!("✓ Queried {} recent analyses", analyses.len()),
        Err(e) => println!("✗ Failed to query recent analyses: {}", e),
    }

    // Query with custom EsQuery
    let custom_query = EsQuery::new()
        .limit(10)
        .min_severity(LogSeverity::Medium)
        .last_hours(24)
        .sort_desc();

    match store.query_alerts(custom_query).await {
        Ok(alerts) => println!("✓ Queried {} alerts with custom filter", alerts.len()),
        Err(e) => println!("✗ Failed to query alerts with filter: {}", e),
    }

    // Query high severity alerts only
    let high_severity_query = EsQuery::new()
        .min_severity(LogSeverity::High)
        .last_days(7);

    match store.query_alerts(high_severity_query).await {
        Ok(alerts) => println!("✓ Queried {} high-severity alerts", alerts.len()),
        Err(e) => println!("✗ Failed to query high-severity alerts: {}", e),
    }

    println!("\nEsStore integration test complete!");
    Ok(())
}
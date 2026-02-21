use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;

pub mod elasticsearch;
pub mod es_store;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Chroma error: {0}")]
    Chroma(#[from] chroma::client::ChromaHttpClientError),
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub struct RetrievedContext {
    pub text: String,
    pub metadata: HashMap<String, Value>,
    pub distance: f32,
}

#[cfg(not(feature = "mock-chroma"))]
pub struct ChromaStore {
    collection: chroma::ChromaCollection,
}

#[cfg(feature = "mock-chroma")]
#[derive(Clone)]
struct StoredItem {
    text: String,
    embedding: Vec<f32>,
    metadata: HashMap<String, Value>,
}

#[cfg(feature = "mock-chroma")]
pub struct ChromaStore {
    collection_name: String,
    storage: std::sync::Mutex<Vec<StoredItem>>,
}

impl ChromaStore {
    pub async fn new(url: &str, collection_name: &str) -> Result<Self, StorageError> {
        #[cfg(not(feature = "mock-chroma"))]
        {
            use chroma::client::ChromaHttpClientOptions;

            let options = ChromaHttpClientOptions {
                endpoint: url.parse().map_err(|e| StorageError::Other(format!("Invalid URL: {}", e)))?,
                ..Default::default()
            };
            let client = chroma::ChromaHttpClient::new(options);
            // Create collection with metadata for embedding dimension
            use chroma::types::Metadata;
            let mut collection_metadata = Metadata::new();
            collection_metadata.insert("dimension".to_string(), chroma::types::MetadataValue::Int(768));
            collection_metadata.insert("embedding_function".to_string(), chroma::types::MetadataValue::Str("ollama".to_string()));

            let collection = client.get_or_create_collection(
                collection_name,
                None, // schema
                Some(collection_metadata),
            ).await?;
            Ok(Self { collection })
        }

        #[cfg(feature = "mock-chroma")]
        {
            Ok(Self {
                collection_name: collection_name.to_string(),
                storage: std::sync::Mutex::new(Vec::new()),
            })
        }
    }

    pub async fn store_embedding(
        &self,
        id: &str,
        sanitized_text: &str,
        embedding: Vec<f32>,
        metadata: HashMap<String, Value>,
    ) -> Result<(), StorageError> {
        #[cfg(not(feature = "mock-chroma"))]
        {
            use chroma::types::Metadata;

            let chroma_metadata: Metadata = metadata.into_iter()
                .map(|(k, v)| (k, chroma::types::MetadataValue::Str(v.to_string())))
                .collect();

            self.collection.add(
                vec![id.to_string()],
                vec![embedding],
                Some(vec![Some(sanitized_text.to_string())]),
                None, // uris
                Some(vec![Some(chroma_metadata)]),
            ).await?;
            Ok(())
        }

        #[cfg(feature = "mock-chroma")]
        {
            let item = StoredItem {
                text: sanitized_text.to_string(),
                embedding,
                metadata,
            };
            self.storage.lock().unwrap().push(item);
            Ok(())
        }
    }

    pub async fn retrieve_context(
        &self,
        query_embedding: Vec<f32>,
        n_results: u32,
        min_score: f32,
    ) -> Result<Vec<RetrievedContext>, StorageError> {
        #[cfg(not(feature = "mock-chroma"))]
        {
            // TODO: Implement real Chroma query
            // For now, return empty vec until we can test with actual Chroma server
            Ok(Vec::new())
        }

        #[cfg(feature = "mock-chroma")]
        {
            let storage = self.storage.lock().unwrap();
            let mut contexts: Vec<(f32, RetrievedContext)> = Vec::new();

            for item in storage.iter() {
                let distance = cosine_similarity(&query_embedding, &item.embedding);
                if distance >= min_score {
                    contexts.push((distance, RetrievedContext {
                        text: item.text.clone(),
                        metadata: item.metadata.clone(),
                        distance,
                    }));
                }
            }

            contexts.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
            contexts.truncate(n_results as usize);

            Ok(contexts.into_iter().map(|(_, ctx)| ctx).collect())
        }
    }
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot_product / (norm_a * norm_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_chroma_store_and_retrieve() {
        let store = ChromaStore::new("http://dummy", "test-collection").await.unwrap();

        // Store
        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), Value::String("value".to_string()));
        store.store_embedding("test-id", "stored text", vec![1.0, 0.0], metadata).await.unwrap();

        // Retrieve with similar vector
        let contexts = store.retrieve_context(vec![1.0, 0.0], 5, 0.8).await.unwrap();
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].text, "stored text");
        assert!((contexts[0].distance - 1.0).abs() < 0.01);

        // Retrieve with dissimilar vector
        let contexts = store.retrieve_context(vec![0.0, 1.0], 5, 0.8).await.unwrap();
        assert_eq!(contexts.len(), 0);
    }
}
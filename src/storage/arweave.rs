/// Arweave permanent storage backend.
///
/// Arweave provides permanent data storage with a one-time payment model.
/// Data stored on Arweave is guaranteed to persist indefinitely through
/// the Arweave endowment mechanism.
///
/// In zk-vault, Arweave is used exclusively for small manifests (few KB),
/// NOT for bulk data storage (which would be prohibitively expensive at
/// $6-8/GB). The manifest contains pointers to data on Storj/Filecoin/IPFS.
///
/// Uses the Arweave HTTP API for transaction creation and data retrieval.
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{StorageBackend, UploadResult};
use crate::crypto::hash;
use crate::error::{Result, VaultError};

/// Configuration for Arweave access.
#[derive(Debug, Clone)]
pub struct ArweaveConfig {
    /// Arweave gateway URL (e.g., "https://arweave.net").
    pub gateway_url: String,
    /// Arweave bundler/uploader URL (e.g., Irys/Bundlr endpoint).
    /// Bundlers batch transactions for lower cost and faster confirmation.
    pub bundler_url: String,
    /// API key or wallet JWK for signing transactions.
    pub api_key: String,
}

/// Arweave permanent storage backend.
pub struct ArweaveBackend {
    client: Client,
    config: ArweaveConfig,
}

/// Bundler upload response.
#[derive(Debug, Deserialize)]
struct BundlerResponse {
    /// Transaction ID on Arweave.
    id: String,
}

impl ArweaveBackend {
    pub fn new(config: ArweaveConfig) -> Self {
        Self {
            client: Client::new(),
            config,
        }
    }
}

#[async_trait]
impl StorageBackend for ArweaveBackend {
    fn name(&self) -> &str {
        "Arweave"
    }

    /// Upload data permanently to Arweave via a bundler (Irys/Bundlr).
    ///
    /// Bundlers aggregate multiple data items into a single Arweave
    /// transaction, reducing cost and improving confirmation time.
    /// Tags are used to mark the content for later discovery.
    async fn upload(&self, key: &str, data: &[u8]) -> Result<UploadResult> {
        let content_hash = hash::hash(data);

        let resp = self
            .client
            .post(format!("{}/tx", self.config.bundler_url))
            .header("Content-Type", "application/octet-stream")
            .header("X-Api-Key", &self.config.api_key)
            // Arweave tags for content discovery
            .header("X-Tag-App-Name", "zk-vault")
            .header("X-Tag-Content-Type", "application/octet-stream")
            .header("X-Tag-Key", key)
            .header("X-Tag-Content-Hash", hex::encode(content_hash))
            .body(data.to_vec())
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Io(std::io::Error::other(format!(
                "Arweave upload failed: {body}"
            ))));
        }

        let bundler_resp: BundlerResponse = resp
            .json()
            .await
            .map_err(|e| VaultError::Serialization(format!("Arweave response parse error: {e}")))?;

        Ok(UploadResult {
            storage_key: bundler_resp.id,
            content_hash,
            size: data.len() as u64,
        })
    }

    /// Download data from Arweave by transaction ID.
    async fn download(&self, key: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(format!("{}/{key}", self.config.gateway_url))
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Io(std::io::Error::other(format!(
                "Arweave download failed: {body}"
            ))));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        Ok(bytes.to_vec())
    }

    /// Check if a transaction exists on Arweave.
    async fn exists(&self, key: &str) -> Result<bool> {
        let resp = self
            .client
            .head(format!("{}/{key}", self.config.gateway_url))
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        Ok(resp.status().is_success())
    }

    /// Arweave data is permanent and cannot be deleted.
    /// This is a no-op that returns Ok.
    async fn delete(&self, _key: &str) -> Result<()> {
        // Arweave is permanent storage — deletion is not possible.
        // This is by design: manifests should persist forever.
        Ok(())
    }

    /// List is not natively supported on Arweave.
    /// In production, use Arweave GraphQL to query by tags.
    async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
        // Arweave doesn't have a simple list API.
        // Use GraphQL queries on gateway for tag-based discovery:
        //   query { transactions(tags: [{name: "App-Name", values: ["zk-vault"]}]) { ... } }
        Ok(vec![])
    }
}

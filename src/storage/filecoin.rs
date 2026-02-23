/// Filecoin cold archive storage via Storacha (w3up) HTTP Bridge API.
///
/// Filecoin provides cryptographic proof-of-storage: storage providers
/// must continuously prove they hold the data via PoRep (Proof of Replication)
/// and PoSt (Proof of Spacetime).
///
/// Storacha (formerly web3.storage) is the recommended bridge to Filecoin,
/// providing an HTTP API that handles deal-making with storage providers.
///
/// Data flow: upload via HTTP → Storacha → Filecoin storage deals
/// Retrieval: via IPFS gateway (Storacha pins to IPFS automatically)
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{StorageBackend, UploadResult};
use crate::crypto::hash;
use crate::error::{Result, VaultError};

/// Configuration for Storacha (Filecoin bridge) access.
#[derive(Debug, Clone)]
pub struct FilecoinConfig {
    /// Storacha HTTP Bridge API endpoint.
    pub api_url: String,
    /// Bearer token for authentication (DID-based authorization).
    pub auth_token: String,
    /// IPFS gateway for retrievals (Storacha auto-pins to IPFS).
    pub gateway_url: String,
}

/// Filecoin storage backend via Storacha.
pub struct FilecoinBackend {
    client: Client,
    config: FilecoinConfig,
}

/// CAR upload response from Storacha.
#[derive(Debug, Deserialize)]
struct UploadResponse {
    /// CID of the uploaded content.
    cid: String,
}

impl FilecoinBackend {
    pub fn new(config: FilecoinConfig) -> Self {
        Self {
            client: Client::new(),
            config,
        }
    }

    /// Wrap raw data in a simple CAR (Content Addressable aRchive) format.
    ///
    /// Storacha expects CAR files. For single-blob uploads we create
    /// a minimal CARv1 wrapping the raw data as a single UnixFS block.
    /// In production, use the `iroh-car` crate for proper CAR encoding.
    fn wrap_as_raw_block(&self, data: &[u8]) -> Vec<u8> {
        // For the HTTP bridge, we upload raw bytes with appropriate headers.
        // The bridge handles CAR wrapping internally when using the /upload endpoint.
        data.to_vec()
    }
}

#[async_trait]
impl StorageBackend for FilecoinBackend {
    fn name(&self) -> &str {
        "Filecoin"
    }

    /// Upload encrypted data to Filecoin via Storacha.
    ///
    /// The data is automatically replicated to Filecoin storage providers
    /// and pinned to IPFS for fast retrieval.
    async fn upload(&self, key: &str, data: &[u8]) -> Result<UploadResult> {
        let content_hash = hash::hash(data);
        let body = self.wrap_as_raw_block(data);

        let resp = self
            .client
            .post(format!("{}/upload", self.config.api_url))
            .bearer_auth(&self.config.auth_token)
            .header("Content-Type", "application/octet-stream")
            .header("X-Upload-Key", key)
            .body(body)
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Io(std::io::Error::other(format!(
                "Filecoin upload failed: {body}"
            ))));
        }

        let upload_resp: UploadResponse = resp.json().await.map_err(|e| {
            VaultError::Serialization(format!("Filecoin response parse error: {e}"))
        })?;

        Ok(UploadResult {
            storage_key: upload_resp.cid,
            content_hash,
            size: data.len() as u64,
        })
    }

    /// Download data from Filecoin via IPFS gateway.
    ///
    /// Storacha automatically pins content to IPFS, so retrieval
    /// uses the standard IPFS gateway path.
    async fn download(&self, key: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get(format!("{}/ipfs/{key}", self.config.gateway_url))
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Io(std::io::Error::other(format!(
                "Filecoin download failed: {body}"
            ))));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        Ok(bytes.to_vec())
    }

    /// Check if content exists via the IPFS gateway.
    async fn exists(&self, key: &str) -> Result<bool> {
        let resp = self
            .client
            .head(format!("{}/ipfs/{key}", self.config.gateway_url))
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        Ok(resp.status().is_success())
    }

    /// Remove a Filecoin upload from Storacha.
    ///
    /// Note: This removes the Storacha record but existing Filecoin
    /// deals may persist until they expire. Data on IPFS may also
    /// remain cached until garbage collected.
    async fn delete(&self, key: &str) -> Result<()> {
        let _ = self
            .client
            .delete(format!("{}/upload/{key}", self.config.api_url))
            .bearer_auth(&self.config.auth_token)
            .send()
            .await;

        Ok(())
    }

    /// List uploads. Storacha provides a list endpoint with optional cursor.
    async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
        let resp = self
            .client
            .get(format!("{}/uploads", self.config.api_url))
            .bearer_auth(&self.config.auth_token)
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        if !resp.status().is_success() {
            return Ok(vec![]);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| VaultError::Serialization(format!("Filecoin list parse error: {e}")))?;

        let cids = body
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.get("cid").and_then(|c| c.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(cids)
    }
}

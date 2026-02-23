/// IPFS storage backend via HTTP API.
///
/// IPFS provides content-addressed storage where each piece of data
/// gets a unique CID (Content Identifier) based on its hash.
///
/// Note: IPFS does not guarantee persistence. Data must be pinned
/// or replicated to other backends (Filecoin, Storj) for durability.
///
/// Uses the IPFS HTTP API (typically Kubo at localhost:5001).
use async_trait::async_trait;
use reqwest::multipart;
use reqwest::Client;
use serde::Deserialize;

use super::{StorageBackend, UploadResult};
use crate::crypto::hash;
use crate::error::{Result, VaultError};

/// Configuration for IPFS HTTP API.
#[derive(Debug, Clone)]
pub struct IpfsConfig {
    /// IPFS API endpoint (e.g., "http://localhost:5001").
    pub api_url: String,
    /// IPFS gateway URL for downloads (e.g., "http://localhost:8080").
    pub gateway_url: String,
}

/// IPFS storage backend.
pub struct IpfsBackend {
    client: Client,
    config: IpfsConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct IpfsAddResponse {
    hash: String,
    #[allow(dead_code)]
    size: String,
}

impl IpfsBackend {
    pub fn new(config: IpfsConfig) -> Self {
        Self {
            client: Client::new(),
            config,
        }
    }
}

#[async_trait]
impl StorageBackend for IpfsBackend {
    fn name(&self) -> &str {
        "IPFS"
    }

    /// Upload data to IPFS. The `key` parameter is ignored; the CID is the key.
    /// Returns the CID as `storage_key`.
    async fn upload(&self, _key: &str, data: &[u8]) -> Result<UploadResult> {
        let content_hash = hash::hash(data);

        let part = multipart::Part::bytes(data.to_vec()).file_name("data");
        let form = multipart::Form::new().part("file", part);

        let resp = self
            .client
            .post(format!("{}/api/v0/add", self.config.api_url))
            .query(&[("pin", "true"), ("cid-version", "1")])
            .multipart(form)
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Io(std::io::Error::other(format!(
                "IPFS add failed: {body}"
            ))));
        }

        let add_resp: IpfsAddResponse = resp
            .json()
            .await
            .map_err(|e| VaultError::Serialization(format!("IPFS response parse error: {e}")))?;

        Ok(UploadResult {
            storage_key: add_resp.hash,
            content_hash,
            size: data.len() as u64,
        })
    }

    /// Download data from IPFS by CID (passed as `key`).
    async fn download(&self, key: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .post(format!("{}/api/v0/cat", self.config.api_url))
            .query(&[("arg", key)])
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Io(std::io::Error::other(format!(
                "IPFS cat failed: {body}"
            ))));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        Ok(bytes.to_vec())
    }

    /// Check if a CID is pinned locally.
    async fn exists(&self, key: &str) -> Result<bool> {
        let resp = self
            .client
            .post(format!("{}/api/v0/pin/ls", self.config.api_url))
            .query(&[("arg", key)])
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        Ok(resp.status().is_success())
    }

    /// Unpin a CID from local IPFS node.
    async fn delete(&self, key: &str) -> Result<()> {
        // Unpin — don't error if not pinned
        let _ = self
            .client
            .post(format!("{}/api/v0/pin/rm", self.config.api_url))
            .query(&[("arg", key)])
            .send()
            .await;

        Ok(())
    }

    /// List pinned CIDs (IPFS doesn't support prefix-based listing natively).
    async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
        let resp = self
            .client
            .post(format!("{}/api/v0/pin/ls", self.config.api_url))
            .query(&[("type", "recursive")])
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        if !resp.status().is_success() {
            return Ok(vec![]);
        }

        // The pin/ls response is {"Keys": {"CID": {"Type": "recursive"}, ...}}
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| VaultError::Serialization(format!("IPFS pin/ls parse error: {e}")))?;

        let keys = body
            .get("Keys")
            .and_then(|k| k.as_object())
            .map(|obj| obj.keys().cloned().collect())
            .unwrap_or_default();

        Ok(keys)
    }
}

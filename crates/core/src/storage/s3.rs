/// S3-compatible storage backend for Mode A (Personal Mode).
///
/// Works with any S3-compatible provider:
/// AWS S3, Google Cloud Storage, Backblaze B2, Wasabi, MinIO, etc.
///
/// All data is already encrypted before reaching this backend.
use async_trait::async_trait;
use s3::creds::Credentials;
use s3::{Bucket, Region};
use serde::{Deserialize, Serialize};

use super::{StorageBackend, UploadResult};
use crate::crypto::hash;
use crate::error::{Result, VaultError};

/// Configuration for S3-compatible storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    /// S3 bucket name.
    pub bucket: String,
    /// AWS region or custom region name (e.g., "us-east-1", "auto").
    pub region: String,
    /// Custom endpoint URL for S3-compatible providers (e.g., MinIO, Backblaze B2).
    /// Leave empty for AWS S3.
    pub endpoint: Option<String>,
    /// Access key ID.
    pub access_key: String,
    /// Secret access key.
    pub secret_key: String,
    /// Use path-style addressing (required for MinIO and some S3-compatible providers).
    #[serde(default)]
    pub path_style: bool,
}

/// S3-compatible storage backend.
pub struct S3Backend {
    bucket: Box<Bucket>,
}

impl S3Backend {
    pub fn new(config: &S3Config) -> Result<Self> {
        let region = match &config.endpoint {
            Some(endpoint) => Region::Custom {
                region: config.region.clone(),
                endpoint: endpoint.clone(),
            },
            None => config.region.parse::<Region>().map_err(|e| {
                VaultError::Io(std::io::Error::other(format!("Invalid region: {e}")))
            })?,
        };

        let credentials = Credentials::new(
            Some(&config.access_key),
            Some(&config.secret_key),
            None,
            None,
            None,
        )
        .map_err(|e| VaultError::Io(std::io::Error::other(format!("Invalid credentials: {e}"))))?;

        let mut bucket = Bucket::new(&config.bucket, region, credentials).map_err(|e| {
            VaultError::Io(std::io::Error::other(format!("Invalid bucket config: {e}")))
        })?;

        if config.path_style {
            bucket = bucket.with_path_style();
        }

        Ok(Self { bucket })
    }
}

#[async_trait]
impl StorageBackend for S3Backend {
    fn name(&self) -> &str {
        "S3"
    }

    async fn upload(&self, key: &str, data: &[u8]) -> Result<UploadResult> {
        let content_hash = hash::hash(data);

        self.bucket
            .put_object(key, data)
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(format!("S3 upload failed: {e}"))))?;

        Ok(UploadResult {
            storage_key: key.to_string(),
            content_hash,
            size: data.len() as u64,
        })
    }

    async fn download(&self, key: &str) -> Result<Vec<u8>> {
        let response = self.bucket.get_object(key).await.map_err(|e| {
            VaultError::Io(std::io::Error::other(format!("S3 download failed: {e}")))
        })?;

        if response.status_code() != 200 {
            return Err(VaultError::Io(std::io::Error::other(format!(
                "S3 download returned status {}",
                response.status_code()
            ))));
        }

        Ok(response.to_vec())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        match self.bucket.head_object(key).await {
            Ok(_) => Ok(true),
            Err(s3::error::S3Error::HttpFailWithBody(404, _)) => Ok(false),
            Err(e) => Err(VaultError::Io(std::io::Error::other(format!(
                "S3 exists check failed: {e}"
            )))),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.bucket
            .delete_object(key)
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(format!("S3 delete failed: {e}"))))?;

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let results = self
            .bucket
            .list(prefix.to_string(), None)
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(format!("S3 list failed: {e}"))))?;

        let keys = results
            .into_iter()
            .flat_map(|page| page.contents)
            .map(|obj| obj.key)
            .collect();

        Ok(keys)
    }
}

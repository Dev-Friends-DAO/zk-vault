/// Storj storage backend (S3-compatible).
///
/// Storj provides decentralized hot storage with an S3-compatible API.
/// Files are encrypted client-side before upload, so Storj never sees plaintext.
///
/// Configuration requires:
/// - Endpoint URL (e.g., https://gateway.storjshare.io)
/// - Access key ID
/// - Secret access key
/// - Bucket name
use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sdk_s3::config::{Builder as S3ConfigBuilder, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;

use super::{StorageBackend, UploadResult};
use crate::crypto::hash;
use crate::error::{Result, VaultError};

/// Configuration for Storj S3 gateway.
#[derive(Debug, Clone)]
pub struct StorjConfig {
    pub endpoint: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub bucket: String,
    pub region: String,
}

/// Storj storage backend using S3-compatible API.
pub struct StorjBackend {
    client: S3Client,
    bucket: String,
}

impl StorjBackend {
    /// Create a new Storj backend from configuration.
    pub fn new(config: &StorjConfig) -> Self {
        let credentials = Credentials::new(
            &config.access_key_id,
            &config.secret_access_key,
            None,
            None,
            "storj",
        );

        let s3_config = S3ConfigBuilder::new()
            .endpoint_url(&config.endpoint)
            .region(Region::new(config.region.clone()))
            .credentials_provider(credentials)
            .force_path_style(true)
            .build();

        let client = S3Client::from_conf(s3_config);

        Self {
            client,
            bucket: config.bucket.clone(),
        }
    }
}

#[async_trait]
impl StorageBackend for StorjBackend {
    fn name(&self) -> &str {
        "Storj"
    }

    async fn upload(&self, key: &str, data: &[u8]) -> Result<UploadResult> {
        let content_hash = hash::hash(data);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(data.to_vec()))
            .content_length(data.len() as i64)
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        Ok(UploadResult {
            storage_key: key.to_string(),
            content_hash,
            size: data.len() as u64,
        })
    }

    async fn download(&self, key: &str) -> Result<Vec<u8>> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        let bytes = resp
            .body
            .collect()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
            .into_bytes();

        Ok(bytes.to_vec())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let service_err = e.into_service_error();
                if service_err.is_not_found() {
                    Ok(false)
                } else {
                    Err(VaultError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        service_err,
                    )))
                }
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);

            if let Some(token) = &continuation_token {
                request = request.continuation_token(token);
            }

            let resp = request
                .send()
                .await
                .map_err(|e| VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

            if let Some(contents) = resp.contents {
                for obj in contents {
                    if let Some(key) = obj.key {
                        keys.push(key);
                    }
                }
            }

            match resp.next_continuation_token {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }

        Ok(keys)
    }
}

/// Pluggable storage backend abstraction for zk-vault.
///
/// Storage backends handle the actual persistence of encrypted data.
/// The tiered hybrid architecture uses multiple backends:
/// - Tier 1: Storj (S3-compatible hot storage, fast retrieval)
/// - Tier 2: Filecoin (cold archive with cryptographic storage proofs)
/// - Tier 3: IPFS (content-addressed distribution layer)
/// - Tier 4: Arweave (permanent manifest storage)
pub mod ipfs;
pub mod storj;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Metadata returned after a successful upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    /// Backend-specific storage key/identifier.
    pub storage_key: String,
    /// Content hash (BLAKE3) of the uploaded data.
    pub content_hash: [u8; 32],
    /// Size in bytes of the uploaded data.
    pub size: u64,
}

/// Trait for pluggable storage backends.
///
/// All data passed to storage backends is already encrypted.
/// Backends never see plaintext.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Human-readable name of this backend (e.g., "Storj", "IPFS").
    fn name(&self) -> &str;

    /// Upload encrypted data. Returns a storage key for later retrieval.
    async fn upload(&self, key: &str, data: &[u8]) -> Result<UploadResult>;

    /// Download data by storage key.
    async fn download(&self, key: &str) -> Result<Vec<u8>>;

    /// Check if an object exists.
    async fn exists(&self, key: &str) -> Result<bool>;

    /// Delete an object. Returns Ok even if the object doesn't exist.
    async fn delete(&self, key: &str) -> Result<()>;

    /// List objects with a given prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

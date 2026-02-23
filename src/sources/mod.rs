/// Pluggable data source abstraction for zk-vault.
///
/// Each data source (Google Drive, Gmail, Notion, etc.) implements the
/// `DataSource` trait to provide a uniform interface for:
/// - OAuth2 authentication (PKCE-based, client-side)
/// - Change detection (incremental backup)
/// - File downloading (streaming)
pub mod google_drive;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tokio::io::AsyncRead;

use crate::error::Result;

/// Configuration for connecting to a data source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceConfig {
    /// OAuth2 client ID.
    pub client_id: String,
    /// OAuth2 redirect URI.
    pub redirect_uri: String,
    /// Scopes required by this source.
    pub scopes: Vec<String>,
}

/// Persistent state for a connected data source (e.g., page tokens, last sync time).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceState {
    /// Opaque cursor/token for incremental sync (source-specific).
    pub sync_cursor: Option<String>,
    /// Timestamp of the last successful sync (RFC 3339).
    pub last_sync: Option<String>,
}

/// Encrypted OAuth token (stored server-side, decrypted only on client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedToken {
    /// Encrypted token blob (encrypted with user's master key derivative).
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption.
    pub nonce: Vec<u8>,
}

/// Metadata for a single file from the data source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Source-specific file ID (e.g., Google Drive file ID).
    pub source_id: String,
    /// Human-readable file name.
    pub name: String,
    /// MIME type.
    pub mime_type: Option<String>,
    /// File size in bytes (if known).
    pub size: Option<u64>,
    /// Last modified timestamp (RFC 3339).
    pub modified_at: Option<String>,
    /// MD5/SHA256 checksum from the source (if available).
    pub checksum: Option<String>,
    /// Parent folder path (source-specific).
    pub path: Option<String>,
}

/// A set of changes detected since the last sync.
#[derive(Debug, Clone, Default)]
pub struct ChangeSet {
    /// Files that were added or modified.
    pub upserted: Vec<FileMetadata>,
    /// File IDs that were deleted.
    pub deleted: Vec<String>,
    /// Updated sync cursor for next incremental sync.
    pub new_cursor: Option<String>,
}

/// A boxed async reader for streaming file downloads.
pub type BoxAsyncRead = Pin<Box<dyn AsyncRead + Send>>;

/// Trait for pluggable data sources.
///
/// All authentication happens client-side. OAuth tokens are encrypted
/// before being sent to the server.
#[async_trait]
pub trait DataSource: Send + Sync {
    /// Human-readable name of this data source (e.g., "Google Drive").
    fn name(&self) -> &str;

    /// Generate the OAuth2 authorization URL for the PKCE flow.
    /// Returns (auth_url, pkce_verifier) — the verifier stays on the client.
    fn auth_url(&self, config: &SourceConfig) -> Result<(String, String)>;

    /// Exchange the authorization code for tokens (client-side).
    /// The tokens are returned as raw bytes to be encrypted by the caller.
    async fn exchange_code(
        &self,
        config: &SourceConfig,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<Vec<u8>>;

    /// Detect changes since the last sync.
    /// Uses the access token (already decrypted by the client).
    async fn detect_changes(
        &self,
        access_token: &str,
        state: &SourceState,
    ) -> Result<ChangeSet>;

    /// Download a file by its source-specific ID.
    /// Returns a streaming async reader.
    async fn download(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<BoxAsyncRead>;
}

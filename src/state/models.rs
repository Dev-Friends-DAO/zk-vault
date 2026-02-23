/// Database models for zk-vault.
///
/// These structs map directly to PostgreSQL tables and are used
/// for both reading and writing via sqlx.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A registered user.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    /// OPAQUE server registration blob (no password hash stored).
    pub opaque_registration: Vec<u8>,
    /// Encrypted key store (JSON blob, encrypted client-side).
    pub encrypted_key_store: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Backup job status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "backup_status", rename_all = "snake_case")]
pub enum BackupStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

/// A backup job record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct BackupJob {
    pub id: Uuid,
    pub user_id: Uuid,
    pub source_type: String,
    pub status: BackupStatus,
    /// Number of files processed.
    pub files_processed: i64,
    /// Total bytes uploaded (encrypted).
    pub bytes_uploaded: i64,
    /// User's Merkle root for this backup.
    pub merkle_root: Option<Vec<u8>>,
    /// Error message if failed.
    pub error_message: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// A connected data source for a user.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SourceConnection {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Source type identifier (e.g., "google_drive").
    pub source_type: String,
    /// Encrypted OAuth tokens (encrypted client-side with master key).
    pub encrypted_tokens: Vec<u8>,
    /// Nonce for token encryption.
    pub token_nonce: Vec<u8>,
    /// Sync cursor for incremental backup.
    pub sync_cursor: Option<String>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A blockchain anchor receipt.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AnchorReceipt {
    pub id: Uuid,
    /// The Super Merkle Root that was anchored.
    pub super_root: Vec<u8>,
    /// Which blockchain (e.g., "bitcoin", "ethereum").
    pub chain: String,
    /// Transaction hash on the blockchain.
    pub tx_hash: String,
    /// Block number (if confirmed).
    pub block_number: Option<i64>,
    /// Timestamp of the anchor.
    pub anchored_at: DateTime<Utc>,
}

/// A backed-up file record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct BackedUpFile {
    pub id: Uuid,
    pub user_id: Uuid,
    pub backup_job_id: Uuid,
    /// Source-specific file ID.
    pub source_file_id: String,
    /// Original file name.
    pub file_name: String,
    /// Original file size in bytes.
    pub original_size: i64,
    /// Encrypted file size in bytes.
    pub encrypted_size: i64,
    /// BLAKE3 hash of the encrypted file (for Merkle tree leaf).
    pub content_hash: Vec<u8>,
    /// Storage location (e.g., Storj object key).
    pub storage_key: Option<String>,
    /// IPFS CID (if stored on IPFS).
    pub ipfs_cid: Option<String>,
    pub created_at: DateTime<Utc>,
}

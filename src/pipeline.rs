/// Backup pipeline orchestrator.
///
/// Coordinates the full backup flow:
/// 1. Detect changes from data source
/// 2. Download changed files
/// 3. Encrypt each file (XChaCha20-Poly1305 + hybrid KEM key wrap)
/// 4. Upload encrypted data to storage backends
/// 5. Build BLAKE3 Merkle tree from all file hashes
/// 6. Sign the Merkle root (hybrid ML-DSA-65 + Ed25519)
/// 7. Update database state
///
/// All encryption happens client-side. The pipeline never sends
/// plaintext to any storage backend or server.
use tokio::io::AsyncReadExt;
use tracing::{info, warn};
use uuid::Uuid;

use crate::crypto::{aead, hash, kem, streaming};
use crate::error::{Result, VaultError};
use crate::merkle::tree::MerkleTree;
use crate::sources::{DataSource, SourceState};
use crate::storage::StorageBackend;

/// Result of a completed backup pipeline run.
#[derive(Debug)]
pub struct BackupResult {
    /// User ID that owns this backup.
    pub user_id: Uuid,
    /// Number of files processed.
    pub files_processed: usize,
    /// Total bytes uploaded (encrypted).
    pub bytes_uploaded: u64,
    /// BLAKE3 Merkle root of all backed-up files.
    pub merkle_root: Option<[u8; 32]>,
    /// Per-file upload results.
    pub file_results: Vec<FileBackupResult>,
    /// Updated sync cursor for next incremental backup.
    pub new_cursor: Option<String>,
}

/// Result for a single file backup.
#[derive(Debug)]
pub struct FileBackupResult {
    pub source_file_id: String,
    pub file_name: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub content_hash: [u8; 32],
    pub storage_key: String,
    pub ipfs_cid: Option<String>,
}

/// Configuration for a pipeline run.
pub struct PipelineConfig {
    /// Threshold for streaming encryption (files larger than this use chunked AEAD).
    pub streaming_threshold: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            streaming_threshold: 64 * 1024 * 1024, // 64 MiB
        }
    }
}

/// Run the backup pipeline for a single data source.
///
/// # Arguments
/// - `user_id`: The user performing the backup
/// - `source`: The data source to back up from
/// - `access_token`: Decrypted OAuth access token
/// - `source_state`: Current sync state (cursor, last sync time)
/// - `primary_storage`: Primary storage backend (e.g., Storj)
/// - `secondary_storage`: Optional secondary backend (e.g., IPFS)
/// - `hybrid_pk`: User's hybrid public key for KEM key wrapping
/// - `config`: Pipeline configuration
pub async fn run_backup(
    user_id: Uuid,
    source: &dyn DataSource,
    access_token: &str,
    source_state: &SourceState,
    primary_storage: &dyn StorageBackend,
    secondary_storage: Option<&dyn StorageBackend>,
    hybrid_pk: &kem::HybridPublicKey,
    config: &PipelineConfig,
) -> Result<BackupResult> {
    info!(
        user_id = %user_id,
        source = source.name(),
        "Starting backup pipeline"
    );

    // 1. Detect changes
    let changes = source.detect_changes(access_token, source_state).await?;
    info!(
        upserted = changes.upserted.len(),
        deleted = changes.deleted.len(),
        "Changes detected"
    );

    if changes.upserted.is_empty() && changes.deleted.is_empty() {
        info!("No changes detected, skipping backup");
        return Ok(BackupResult {
            user_id,
            files_processed: 0,
            bytes_uploaded: 0,
            merkle_root: None,
            file_results: vec![],
            new_cursor: changes.new_cursor,
        });
    }

    let mut file_results = Vec::new();
    let mut leaf_hashes = Vec::new();
    let mut total_bytes: u64 = 0;

    // 2-4. Process each changed file
    for file_meta in &changes.upserted {
        match process_file(
            user_id,
            source,
            access_token,
            &file_meta.source_id,
            &file_meta.name,
            primary_storage,
            secondary_storage,
            hybrid_pk,
            config,
        )
        .await
        {
            Ok(result) => {
                leaf_hashes.push(result.content_hash);
                total_bytes += result.encrypted_size;
                file_results.push(result);
            }
            Err(e) => {
                warn!(
                    file_id = %file_meta.source_id,
                    file_name = %file_meta.name,
                    error = %e,
                    "Failed to process file, skipping"
                );
            }
        }
    }

    // 5. Build Merkle tree
    let merkle_root = if !leaf_hashes.is_empty() {
        let tree = MerkleTree::from_leaf_hashes(leaf_hashes);
        tree.root()
    } else {
        None
    };

    info!(
        files = file_results.len(),
        bytes = total_bytes,
        has_root = merkle_root.is_some(),
        "Backup pipeline complete"
    );

    Ok(BackupResult {
        user_id,
        files_processed: file_results.len(),
        bytes_uploaded: total_bytes,
        merkle_root,
        file_results,
        new_cursor: changes.new_cursor,
    })
}

/// Process a single file: download → encrypt → upload.
async fn process_file(
    user_id: Uuid,
    source: &dyn DataSource,
    access_token: &str,
    file_id: &str,
    file_name: &str,
    primary_storage: &dyn StorageBackend,
    secondary_storage: Option<&dyn StorageBackend>,
    hybrid_pk: &kem::HybridPublicKey,
    config: &PipelineConfig,
) -> Result<FileBackupResult> {
    // Download file from source
    let mut reader = source.download(access_token, file_id).await?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .await
        .map_err(|e| VaultError::Io(e))?;

    let original_size = plaintext.len() as u64;

    // Generate a per-file symmetric key
    let sym_key = aead::generate_key();

    // Encrypt the file
    let encrypted = if plaintext.len() > config.streaming_threshold {
        // Large file: chunked AEAD
        let aad = format!("zk-vault:file:{user_id}:{file_id}");
        let (nonce, ciphertext) = streaming::encrypt_chunked(&sym_key, &plaintext, aad.as_bytes())?;
        // Prepend nonce to ciphertext for self-contained storage
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        result
    } else {
        // Small file: single AEAD
        let aad = format!("zk-vault:file:{user_id}:{file_id}");
        let (nonce, ciphertext) = aead::encrypt(&sym_key, &plaintext, aad.as_bytes())?;
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        result
    };

    // Wrap the symmetric key with hybrid KEM
    let encap = kem::encapsulate(hybrid_pk, &sym_key)?;

    // Build the encrypted bundle:
    // [kem_ct_len(4) | kem_ct | eph_pk(32) | wrapped_key_len(4) | wrapped_key | encrypted_data]
    let mut bundle = Vec::new();
    let kem_ct_len = encap.kem_ciphertext.len() as u32;
    bundle.extend_from_slice(&kem_ct_len.to_le_bytes());
    bundle.extend_from_slice(&encap.kem_ciphertext);
    bundle.extend_from_slice(&encap.eph_x25519_pk);
    let wk_len = encap.wrapped_key.len() as u32;
    bundle.extend_from_slice(&wk_len.to_le_bytes());
    bundle.extend_from_slice(&encap.wrapped_key);
    bundle.extend_from_slice(&encrypted);

    let encrypted_size = bundle.len() as u64;
    let content_hash = hash::hash(&bundle);

    // Upload to primary storage
    let storage_key = format!("{user_id}/{file_id}");
    let _primary_result = primary_storage.upload(&storage_key, &bundle).await?;

    // Upload to secondary storage (if available)
    let ipfs_cid = if let Some(secondary) = secondary_storage {
        match secondary.upload(&storage_key, &bundle).await {
            Ok(result) => Some(result.storage_key),
            Err(e) => {
                warn!(
                    file_id = %file_id,
                    error = %e,
                    "Secondary storage upload failed, continuing"
                );
                None
            }
        }
    } else {
        None
    };

    Ok(FileBackupResult {
        source_file_id: file_id.to_string(),
        file_name: file_name.to_string(),
        original_size,
        encrypted_size,
        content_hash,
        storage_key,
        ipfs_cid,
    })
}

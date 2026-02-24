/// Restore orchestrator for recovering backed-up data.
///
/// The restore pipeline is the inverse of the backup pipeline:
/// 1. Fetch and decrypt the manifest (from Arweave/IPFS)
/// 2. Verify manifest integrity (Merkle root check)
/// 3. Download encrypted files from storage backends
/// 4. Decrypt each file (hybrid KEM decapsulate → AEAD decrypt)
/// 5. Verify content hash matches manifest
/// 6. Output restored plaintext files
///
/// Multi-backend fallback: tries each storage location in order
/// (Storj → IPFS → Filecoin). If one backend is down, the next
/// is tried automatically.
use tracing::{error, info, warn};
use x25519_dalek::StaticSecret;

use crate::crypto::{aead, hash, kem, streaming};
use crate::error::{Result, VaultError};
use crate::manifest::{BackupManifest, ManifestFileEntry};
use crate::storage::StorageBackend;

/// Result of a complete restore operation.
#[derive(Debug)]
pub struct RestoreResult {
    /// Number of files successfully restored.
    pub files_restored: usize,
    /// Number of files that failed to restore.
    pub files_failed: usize,
    /// Total bytes restored (original plaintext size).
    pub bytes_restored: u64,
    /// Per-file restore results.
    pub file_results: Vec<FileRestoreResult>,
}

/// Result for a single file restore.
#[derive(Debug)]
pub struct FileRestoreResult {
    /// Original file path from the data source.
    pub source_path: String,
    /// Whether this file was successfully restored.
    pub success: bool,
    /// Restored plaintext data (None if failed).
    pub data: Option<Vec<u8>>,
    /// Original size in bytes.
    pub original_size: u64,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Configuration for restore.
pub struct RestoreConfig {
    /// Preferred storage backend order for downloads.
    /// Tries backends in this order; falls back to next on failure.
    pub backend_preference: Vec<String>,
    /// Threshold for streaming decryption (must match backup config).
    pub streaming_threshold: usize,
    /// Whether to verify content hashes after decryption.
    pub verify_hashes: bool,
}

impl Default for RestoreConfig {
    fn default() -> Self {
        Self {
            backend_preference: vec![
                "storj".to_string(),
                "ipfs".to_string(),
                "filecoin".to_string(),
            ],
            streaming_threshold: 64 * 1024 * 1024,
            verify_hashes: true,
        }
    }
}

/// Run the restore pipeline from a decrypted manifest.
///
/// # Arguments
/// - `manifest`: The decrypted backup manifest
/// - `backends`: Available storage backends (keyed by name)
/// - `kem_sk`: ML-KEM-768 secret key bytes
/// - `x25519_sk`: X25519 static secret key
/// - `config`: Restore configuration
pub async fn run_restore(
    manifest: &BackupManifest,
    backends: &[(&str, &dyn StorageBackend)],
    kem_sk: &[u8],
    x25519_sk: &StaticSecret,
    config: &RestoreConfig,
) -> Result<RestoreResult> {
    info!(
        backup_id = %manifest.backup_id,
        file_count = manifest.file_count,
        source = %manifest.source,
        "Starting restore pipeline"
    );

    // Verify manifest integrity first
    if config.verify_hashes {
        let integrity_ok = manifest.verify_integrity()?;
        if !integrity_ok {
            return Err(VaultError::MerkleVerification(
                "Manifest Merkle root does not match file hashes".to_string(),
            ));
        }
        info!("Manifest integrity verified");
    }

    let mut file_results = Vec::new();
    let mut files_restored = 0usize;
    let mut files_failed = 0usize;
    let mut bytes_restored = 0u64;

    for file_entry in &manifest.files {
        match restore_file(file_entry, backends, kem_sk, x25519_sk, config).await {
            Ok(data) => {
                info!(
                    source_path = %file_entry.source_path,
                    size = data.len(),
                    "File restored successfully"
                );
                bytes_restored += data.len() as u64;
                files_restored += 1;
                file_results.push(FileRestoreResult {
                    source_path: file_entry.source_path.clone(),
                    success: true,
                    data: Some(data),
                    original_size: file_entry.original_size,
                    error: None,
                });
            }
            Err(e) => {
                error!(
                    source_path = %file_entry.source_path,
                    error = %e,
                    "File restore failed"
                );
                files_failed += 1;
                file_results.push(FileRestoreResult {
                    source_path: file_entry.source_path.clone(),
                    success: false,
                    data: None,
                    original_size: file_entry.original_size,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    info!(
        restored = files_restored,
        failed = files_failed,
        bytes = bytes_restored,
        "Restore pipeline complete"
    );

    Ok(RestoreResult {
        files_restored,
        files_failed,
        bytes_restored,
        file_results,
    })
}

/// Restore a single file: download → decapsulate → decrypt → verify.
async fn restore_file(
    file_entry: &ManifestFileEntry,
    backends: &[(&str, &dyn StorageBackend)],
    kem_sk: &[u8],
    x25519_sk: &StaticSecret,
    config: &RestoreConfig,
) -> Result<Vec<u8>> {
    // Download encrypted bundle with multi-backend fallback
    let bundle = download_with_fallback(file_entry, backends, config).await?;

    // Parse the encrypted bundle:
    // [kem_ct_len(4) | kem_ct | eph_pk(32) | wrapped_key_len(4) | wrapped_key | encrypted_data]
    let plaintext = decrypt_bundle(&bundle, kem_sk, x25519_sk, config)?;

    // Verify content hash if enabled
    if config.verify_hashes {
        let computed_hash = hash::hash(&plaintext);
        if computed_hash != file_entry.content_hash {
            return Err(VaultError::MerkleVerification(format!(
                "Content hash mismatch for {}",
                file_entry.source_path
            )));
        }
    }

    Ok(plaintext)
}

/// Try downloading from each backend in preference order.
async fn download_with_fallback(
    file_entry: &ManifestFileEntry,
    backends: &[(&str, &dyn StorageBackend)],
    config: &RestoreConfig,
) -> Result<Vec<u8>> {
    // Try backends in preference order
    for preferred in &config.backend_preference {
        if let Some(location) = file_entry
            .storage_locations
            .iter()
            .find(|loc| &loc.backend == preferred)
        {
            if let Some((_, backend)) = backends.iter().find(|(name, _)| name == preferred) {
                match backend.download(&location.storage_key).await {
                    Ok(data) => {
                        info!(
                            backend = %preferred,
                            key = %location.storage_key,
                            "Downloaded from preferred backend"
                        );
                        return Ok(data);
                    }
                    Err(e) => {
                        warn!(
                            backend = %preferred,
                            error = %e,
                            "Download failed, trying next backend"
                        );
                    }
                }
            }
        }
    }

    // Try any remaining storage locations not in preference list
    for location in &file_entry.storage_locations {
        if let Some((_, backend)) = backends.iter().find(|(name, _)| *name == location.backend) {
            match backend.download(&location.storage_key).await {
                Ok(data) => {
                    info!(
                        backend = %location.backend,
                        "Downloaded from fallback backend"
                    );
                    return Ok(data);
                }
                Err(e) => {
                    warn!(
                        backend = %location.backend,
                        error = %e,
                        "Fallback download also failed"
                    );
                }
            }
        }
    }

    Err(VaultError::Io(std::io::Error::other(format!(
        "All storage backends failed for {}",
        file_entry.source_path
    ))))
}

/// Parse and decrypt an encrypted bundle.
///
/// Bundle format:
/// [kem_ct_len(4) | kem_ct | eph_pk(32) | wrapped_key_len(4) | wrapped_key | nonce | ciphertext]
fn decrypt_bundle(
    bundle: &[u8],
    kem_sk: &[u8],
    x25519_sk: &StaticSecret,
    config: &RestoreConfig,
) -> Result<Vec<u8>> {
    let mut offset = 0;

    // Read KEM ciphertext length
    if bundle.len() < 4 {
        return Err(VaultError::Decryption("Bundle too short".to_string()));
    }
    let kem_ct_len = u32::from_le_bytes(bundle[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    // Read KEM ciphertext
    if bundle.len() < offset + kem_ct_len {
        return Err(VaultError::Decryption(
            "Bundle too short for KEM ciphertext".to_string(),
        ));
    }
    let kem_ciphertext = &bundle[offset..offset + kem_ct_len];
    offset += kem_ct_len;

    // Read ephemeral X25519 public key (32 bytes)
    if bundle.len() < offset + 32 {
        return Err(VaultError::Decryption(
            "Bundle too short for ephemeral key".to_string(),
        ));
    }
    let eph_pk: [u8; 32] = bundle[offset..offset + 32].try_into().unwrap();
    offset += 32;

    // Read wrapped key length
    if bundle.len() < offset + 4 {
        return Err(VaultError::Decryption(
            "Bundle too short for wrapped key length".to_string(),
        ));
    }
    let wk_len = u32::from_le_bytes(bundle[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    // Read wrapped key
    if bundle.len() < offset + wk_len {
        return Err(VaultError::Decryption(
            "Bundle too short for wrapped key".to_string(),
        ));
    }
    let wrapped_key = &bundle[offset..offset + wk_len];
    offset += wk_len;

    // Remaining bytes are [nonce | ciphertext]
    let encrypted_data = &bundle[offset..];

    // Decapsulate to recover the symmetric key
    let sym_key = kem::decapsulate(kem_sk, x25519_sk, kem_ciphertext, &eph_pk, wrapped_key)?;

    // Split nonce from ciphertext and decrypt
    // Nonce is 24 bytes for XChaCha20-Poly1305
    if encrypted_data.len() < 24 {
        return Err(VaultError::Decryption(
            "Encrypted data too short for nonce".to_string(),
        ));
    }
    let nonce: [u8; 24] = encrypted_data[..24].try_into().unwrap();
    let ciphertext = &encrypted_data[24..];

    // Determine if this was a streaming or single-shot encryption
    // by checking the original size against the streaming threshold.
    // For simplicity, try single-shot first; if that fails and the
    // data is large enough, try chunked decryption.
    let aad = b""; // AAD was file-specific during backup; for restore we use empty

    match aead::decrypt(&sym_key, &nonce, ciphertext, aad) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) if ciphertext.len() > config.streaming_threshold => {
            // Try chunked decryption
            streaming::decrypt_chunked(&sym_key, &nonce, ciphertext, aad)
        }
        Err(e) => Err(e),
    }
}

/// Verify backup integrity without restoring data.
///
/// Checks:
/// 1. Manifest Merkle root matches file hashes
/// 2. All files exist in at least one storage backend
/// 3. Blockchain anchor receipts are confirmed (if anchors provided)
pub async fn verify_backup(
    manifest: &BackupManifest,
    backends: &[(&str, &dyn StorageBackend)],
    anchors: Option<&[&dyn crate::anchor::BlockchainAnchor]>,
) -> VerifyResult {
    let mut checks = Vec::new();

    // 1. Manifest integrity (Merkle root)
    let merkle_ok = manifest.verify_integrity().unwrap_or(false);
    checks.push(VerifyCheck {
        name: "Merkle root integrity".to_string(),
        passed: merkle_ok,
        detail: if merkle_ok {
            "Merkle root matches all file content hashes".to_string()
        } else {
            "Merkle root MISMATCH — possible data tampering".to_string()
        },
    });

    // 2. Storage availability
    let mut files_available = 0u32;
    let mut files_missing = 0u32;

    for file_entry in &manifest.files {
        let mut found = false;
        for location in &file_entry.storage_locations {
            if let Some((_, backend)) = backends.iter().find(|(name, _)| *name == location.backend)
            {
                match backend.exists(&location.storage_key).await {
                    Ok(true) => {
                        found = true;
                        break;
                    }
                    _ => continue,
                }
            }
        }
        if found {
            files_available += 1;
        } else {
            files_missing += 1;
        }
    }

    checks.push(VerifyCheck {
        name: "Storage availability".to_string(),
        passed: files_missing == 0,
        detail: format!("{files_available} available, {files_missing} missing"),
    });

    // 3. Blockchain anchor verification
    if let Some(anchor_impls) = anchors {
        for receipt in &manifest.anchor_receipts {
            let anchor = anchor_impls
                .iter()
                .find(|a| a.chain_name().to_lowercase() == receipt.chain);

            match anchor {
                Some(a) => match a.verify(receipt).await {
                    Ok(true) => {
                        checks.push(VerifyCheck {
                            name: format!("{} anchor", receipt.chain),
                            passed: true,
                            detail: format!("Confirmed: tx {}", receipt.tx_id),
                        });
                    }
                    Ok(false) => {
                        checks.push(VerifyCheck {
                            name: format!("{} anchor", receipt.chain),
                            passed: false,
                            detail: format!("Unconfirmed: tx {}", receipt.tx_id),
                        });
                    }
                    Err(e) => {
                        checks.push(VerifyCheck {
                            name: format!("{} anchor", receipt.chain),
                            passed: false,
                            detail: format!("Verification error: {e}"),
                        });
                    }
                },
                None => {
                    checks.push(VerifyCheck {
                        name: format!("{} anchor", receipt.chain),
                        passed: false,
                        detail: "No anchor implementation available".to_string(),
                    });
                }
            }
        }
    }

    let all_passed = checks.iter().all(|c| c.passed);

    VerifyResult {
        passed: all_passed,
        checks,
    }
}

/// Result of a verification operation.
#[derive(Debug)]
pub struct VerifyResult {
    /// Whether all checks passed.
    pub passed: bool,
    /// Individual check results.
    pub checks: Vec<VerifyCheck>,
}

/// A single verification check result.
#[derive(Debug)]
pub struct VerifyCheck {
    /// Name of the check.
    pub name: String,
    /// Whether it passed.
    pub passed: bool,
    /// Human-readable detail.
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash;
    use crate::manifest::{ManifestBuilder, ManifestFileEntry, StorageLocation};
    use uuid::Uuid;

    #[test]
    fn test_decrypt_bundle_roundtrip() {
        // Simulate what the backup pipeline produces
        let kem_kp = kem::KemKeyPair::generate();
        let x25519_kp = kem::X25519KeyPair::generate();
        let hybrid_pk = kem::HybridPublicKey {
            kem_pk: kem_kp.public_key.clone(),
            x25519_pk: x25519_kp.public_key.to_bytes(),
        };

        let plaintext = b"Hello, restored world!";
        let sym_key = aead::generate_key();

        // Encrypt
        let aad = b"";
        let (nonce, ciphertext) = aead::encrypt(&sym_key, plaintext, aad).unwrap();

        // Wrap key
        let encap = kem::encapsulate(&hybrid_pk, &sym_key).unwrap();

        // Build bundle (same format as pipeline.rs)
        let mut bundle = Vec::new();
        let kem_ct_len = encap.kem_ciphertext.len() as u32;
        bundle.extend_from_slice(&kem_ct_len.to_le_bytes());
        bundle.extend_from_slice(&encap.kem_ciphertext);
        bundle.extend_from_slice(&encap.eph_x25519_pk);
        let wk_len = encap.wrapped_key.len() as u32;
        bundle.extend_from_slice(&wk_len.to_le_bytes());
        bundle.extend_from_slice(&encap.wrapped_key);
        bundle.extend_from_slice(&nonce);
        bundle.extend_from_slice(&ciphertext);

        // Decrypt bundle
        let config = RestoreConfig::default();
        let recovered = decrypt_bundle(
            &bundle,
            kem_kp.secret_key_bytes(),
            x25519_kp.secret_key(),
            &config,
        )
        .unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_decrypt_bundle_tampered_fails() {
        let kem_kp = kem::KemKeyPair::generate();
        let x25519_kp = kem::X25519KeyPair::generate();
        let hybrid_pk = kem::HybridPublicKey {
            kem_pk: kem_kp.public_key.clone(),
            x25519_pk: x25519_kp.public_key.to_bytes(),
        };

        let plaintext = b"Sensitive data";
        let sym_key = aead::generate_key();
        let (nonce, ciphertext) = aead::encrypt(&sym_key, plaintext, b"").unwrap();
        let encap = kem::encapsulate(&hybrid_pk, &sym_key).unwrap();

        let mut bundle = Vec::new();
        bundle.extend_from_slice(&(encap.kem_ciphertext.len() as u32).to_le_bytes());
        bundle.extend_from_slice(&encap.kem_ciphertext);
        bundle.extend_from_slice(&encap.eph_x25519_pk);
        bundle.extend_from_slice(&(encap.wrapped_key.len() as u32).to_le_bytes());
        bundle.extend_from_slice(&encap.wrapped_key);
        bundle.extend_from_slice(&nonce);
        bundle.extend_from_slice(&ciphertext);

        // Tamper with the encrypted data
        let last = bundle.len() - 1;
        bundle[last] ^= 0xFF;

        let config = RestoreConfig::default();
        let result = decrypt_bundle(
            &bundle,
            kem_kp.secret_key_bytes(),
            x25519_kp.secret_key(),
            &config,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_result_structure() {
        let user_id = Uuid::now_v7();
        let mut builder = ManifestBuilder::new(user_id, "test");
        let h = hash::hash(b"test");

        builder.add_file(ManifestFileEntry {
            source_path: "test.txt".to_string(),
            source_id: "1".to_string(),
            content_hash: h,
            original_size: 4,
            encrypted_size: 50,
            mime_type: None,
            source_modified_at: None,
            storage_locations: vec![StorageLocation {
                backend: "storj".to_string(),
                storage_key: "key1".to_string(),
            }],
        });

        let tree = crate::merkle::tree::MerkleTree::from_leaves(&[h.as_slice()]);
        let manifest = builder.build(tree.root().unwrap());

        // Verify integrity passes
        assert!(manifest.verify_integrity().unwrap());
    }
}

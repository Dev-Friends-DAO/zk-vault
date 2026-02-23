/// Backup manifest: a complete record of a single backup operation.
///
/// The manifest ties together all pieces of a backup:
/// - Which files were backed up and where they're stored
/// - The Merkle root proving integrity of all files
/// - Blockchain anchor receipts for tamper-proof timestamping
/// - Hybrid signatures for authenticity
///
/// Manifests are encrypted before upload to Arweave (permanent) and
/// IPFS (content-addressed). Only the user with the correct keys
/// can read the manifest — the storage layer sees only ciphertext.
///
/// Recovery flow: passphrase → derive keys → fetch manifest from
/// Arweave/IPFS → decrypt → use file locations to restore data.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::anchor::AnchorReceipt;
use crate::error::{Result, VaultError};

/// Current manifest format version.
pub const MANIFEST_VERSION: u8 = 1;

/// A complete backup manifest.
///
/// This is the "table of contents" for a backup. It contains everything
/// needed to locate, verify, and restore all backed-up data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Format version for forward compatibility.
    pub version: u8,
    /// Unique identifier for this backup.
    pub backup_id: Uuid,
    /// User who created this backup.
    pub user_id: Uuid,
    /// When the backup was created.
    pub created_at: DateTime<Utc>,
    /// Data source identifier (e.g., "google_drive").
    pub source: String,
    /// Individual file entries.
    pub files: Vec<ManifestFileEntry>,
    /// BLAKE3 Merkle root of all file content hashes.
    pub merkle_root: [u8; 32],
    /// Blockchain anchor receipts (Bitcoin, Ethereum, etc.).
    pub anchor_receipts: Vec<AnchorReceipt>,
    /// Total size of all original (pre-encryption) files in bytes.
    pub total_original_size: u64,
    /// Total size of all encrypted files in bytes.
    pub total_encrypted_size: u64,
    /// Number of files in this backup.
    pub file_count: u32,
}

/// A single file entry in the manifest.
///
/// Contains all storage locations and metadata needed to
/// retrieve and verify a specific file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    /// Original file path/name from the data source.
    pub source_path: String,
    /// Source-specific file identifier (e.g., Google Drive file ID).
    pub source_id: String,
    /// BLAKE3 hash of the original plaintext.
    pub content_hash: [u8; 32],
    /// Size of the original file in bytes.
    pub original_size: u64,
    /// Size of the encrypted file in bytes.
    pub encrypted_size: u64,
    /// MIME type (if known).
    pub mime_type: Option<String>,
    /// Last modified timestamp from the source.
    pub source_modified_at: Option<DateTime<Utc>>,
    /// Storage locations — where the encrypted data lives.
    pub storage_locations: Vec<StorageLocation>,
}

/// A storage location for encrypted data.
///
/// Each file may be stored in multiple backends for redundancy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageLocation {
    /// Backend name (e.g., "storj", "ipfs", "filecoin").
    pub backend: String,
    /// Backend-specific key/identifier (S3 key, CID, tx ID, etc.).
    pub storage_key: String,
}

/// Builder for constructing manifests incrementally.
pub struct ManifestBuilder {
    backup_id: Uuid,
    user_id: Uuid,
    source: String,
    files: Vec<ManifestFileEntry>,
    anchor_receipts: Vec<AnchorReceipt>,
    total_original_size: u64,
    total_encrypted_size: u64,
}

impl ManifestBuilder {
    /// Create a new manifest builder.
    pub fn new(user_id: Uuid, source: &str) -> Self {
        Self {
            backup_id: Uuid::now_v7(),
            user_id,
            source: source.to_string(),
            files: Vec::new(),
            anchor_receipts: Vec::new(),
            total_original_size: 0,
            total_encrypted_size: 0,
        }
    }

    /// Add a file entry to the manifest.
    pub fn add_file(&mut self, entry: ManifestFileEntry) {
        self.total_original_size += entry.original_size;
        self.total_encrypted_size += entry.encrypted_size;
        self.files.push(entry);
    }

    /// Add a blockchain anchor receipt.
    pub fn add_anchor_receipt(&mut self, receipt: AnchorReceipt) {
        self.anchor_receipts.push(receipt);
    }

    /// Build the final manifest.
    ///
    /// Computes the Merkle root from all file content hashes.
    pub fn build(self, merkle_root: [u8; 32]) -> BackupManifest {
        let file_count = self.files.len() as u32;

        BackupManifest {
            version: MANIFEST_VERSION,
            backup_id: self.backup_id,
            user_id: self.user_id,
            created_at: Utc::now(),
            source: self.source,
            files: self.files,
            merkle_root,
            anchor_receipts: self.anchor_receipts,
            total_original_size: self.total_original_size,
            total_encrypted_size: self.total_encrypted_size,
            file_count,
        }
    }
}

impl BackupManifest {
    /// Serialize the manifest to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| VaultError::Serialization(e.to_string()))
    }

    /// Deserialize a manifest from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| VaultError::Serialization(e.to_string()))
    }

    /// Verify that the manifest's merkle root matches the file hashes.
    ///
    /// Rebuilds the Merkle tree from the file content hashes and
    /// checks that the computed root matches the stored root.
    pub fn verify_integrity(&self) -> Result<bool> {
        if self.files.is_empty() {
            return Ok(self.merkle_root == [0u8; 32]);
        }

        let leaf_data: Vec<&[u8]> = self
            .files
            .iter()
            .map(|f| f.content_hash.as_slice())
            .collect();

        let tree = crate::merkle::tree::MerkleTree::from_leaves(&leaf_data);
        Ok(tree.root() == Some(self.merkle_root))
    }

    /// Get all storage locations for a specific backend.
    pub fn locations_for_backend(&self, backend: &str) -> Vec<(&ManifestFileEntry, &str)> {
        self.files
            .iter()
            .filter_map(|file| {
                file.storage_locations
                    .iter()
                    .find(|loc| loc.backend == backend)
                    .map(|loc| (file, loc.storage_key.as_str()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_roundtrip() {
        let user_id = Uuid::now_v7();
        let mut builder = ManifestBuilder::new(user_id, "google_drive");

        let hash1 = crate::crypto::hash::hash(b"file1 content");
        let hash2 = crate::crypto::hash::hash(b"file2 content");

        builder.add_file(ManifestFileEntry {
            source_path: "documents/report.pdf".to_string(),
            source_id: "gdrive_abc123".to_string(),
            content_hash: hash1,
            original_size: 1024,
            encrypted_size: 1100,
            mime_type: Some("application/pdf".to_string()),
            source_modified_at: None,
            storage_locations: vec![
                StorageLocation {
                    backend: "storj".to_string(),
                    storage_key: "backups/user1/file1.enc".to_string(),
                },
                StorageLocation {
                    backend: "ipfs".to_string(),
                    storage_key: "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
                        .to_string(),
                },
            ],
        });

        builder.add_file(ManifestFileEntry {
            source_path: "photos/vacation.jpg".to_string(),
            source_id: "gdrive_def456".to_string(),
            content_hash: hash2,
            original_size: 2048,
            encrypted_size: 2200,
            mime_type: Some("image/jpeg".to_string()),
            source_modified_at: None,
            storage_locations: vec![StorageLocation {
                backend: "storj".to_string(),
                storage_key: "backups/user1/file2.enc".to_string(),
            }],
        });

        // Build Merkle tree and manifest
        let tree =
            crate::merkle::tree::MerkleTree::from_leaves(&[hash1.as_slice(), hash2.as_slice()]);
        let manifest = builder.build(tree.root().unwrap());

        assert_eq!(manifest.version, MANIFEST_VERSION);
        assert_eq!(manifest.user_id, user_id);
        assert_eq!(manifest.source, "google_drive");
        assert_eq!(manifest.file_count, 2);
        assert_eq!(manifest.total_original_size, 3072);
        assert_eq!(manifest.total_encrypted_size, 3300);

        // Serialize → deserialize roundtrip
        let bytes = manifest.to_bytes().unwrap();
        let restored = BackupManifest::from_bytes(&bytes).unwrap();
        assert_eq!(restored.backup_id, manifest.backup_id);
        assert_eq!(restored.files.len(), 2);
        assert_eq!(restored.merkle_root, manifest.merkle_root);
    }

    #[test]
    fn test_manifest_integrity_verification() {
        let user_id = Uuid::now_v7();
        let mut builder = ManifestBuilder::new(user_id, "test");

        let hash1 = crate::crypto::hash::hash(b"data1");
        let hash2 = crate::crypto::hash::hash(b"data2");

        builder.add_file(ManifestFileEntry {
            source_path: "a.txt".to_string(),
            source_id: "1".to_string(),
            content_hash: hash1,
            original_size: 5,
            encrypted_size: 50,
            mime_type: None,
            source_modified_at: None,
            storage_locations: vec![],
        });

        builder.add_file(ManifestFileEntry {
            source_path: "b.txt".to_string(),
            source_id: "2".to_string(),
            content_hash: hash2,
            original_size: 5,
            encrypted_size: 50,
            mime_type: None,
            source_modified_at: None,
            storage_locations: vec![],
        });

        let tree =
            crate::merkle::tree::MerkleTree::from_leaves(&[hash1.as_slice(), hash2.as_slice()]);
        let manifest = builder.build(tree.root().unwrap());

        // Valid manifest should pass integrity check
        assert!(manifest.verify_integrity().unwrap());

        // Tampered manifest should fail
        let mut tampered = manifest;
        tampered.files[0].content_hash = [0xFFu8; 32];
        assert!(!tampered.verify_integrity().unwrap());
    }

    #[test]
    fn test_locations_for_backend() {
        let user_id = Uuid::now_v7();
        let mut builder = ManifestBuilder::new(user_id, "test");

        builder.add_file(ManifestFileEntry {
            source_path: "a.txt".to_string(),
            source_id: "1".to_string(),
            content_hash: [0u8; 32],
            original_size: 100,
            encrypted_size: 150,
            mime_type: None,
            source_modified_at: None,
            storage_locations: vec![
                StorageLocation {
                    backend: "storj".to_string(),
                    storage_key: "key1".to_string(),
                },
                StorageLocation {
                    backend: "ipfs".to_string(),
                    storage_key: "cid1".to_string(),
                },
            ],
        });

        builder.add_file(ManifestFileEntry {
            source_path: "b.txt".to_string(),
            source_id: "2".to_string(),
            content_hash: [1u8; 32],
            original_size: 200,
            encrypted_size: 250,
            mime_type: None,
            source_modified_at: None,
            storage_locations: vec![StorageLocation {
                backend: "storj".to_string(),
                storage_key: "key2".to_string(),
            }],
        });

        let manifest = builder.build([0u8; 32]);

        let storj_locs = manifest.locations_for_backend("storj");
        assert_eq!(storj_locs.len(), 2);

        let ipfs_locs = manifest.locations_for_backend("ipfs");
        assert_eq!(ipfs_locs.len(), 1);

        let filecoin_locs = manifest.locations_for_backend("filecoin");
        assert_eq!(filecoin_locs.len(), 0);
    }
}

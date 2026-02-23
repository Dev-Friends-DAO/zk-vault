/// Key management types for zk-vault.
///
/// Defines the master key hierarchy and serialization formats.
use serde::{Deserialize, Serialize};

/// Encrypted key store format, serialized to disk.
#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyStore {
    /// Version of the key store format.
    pub version: u32,
    /// Argon2id salt for passphrase derivation (32 bytes, hex-encoded).
    pub kdf_salt: String,
    /// Encrypted master key blob (hex-encoded).
    pub encrypted_master_key: String,
    /// Nonce used to encrypt the master key (hex-encoded).
    pub master_key_nonce: String,
    /// Encrypted ML-KEM-768 secret key (hex-encoded).
    pub encrypted_kem_sk: String,
    /// Nonce for KEM SK encryption (hex-encoded).
    pub kem_sk_nonce: String,
    /// ML-KEM-768 public key (hex-encoded).
    pub kem_pk: String,
    /// Encrypted X25519 secret key (hex-encoded).
    pub encrypted_x25519_sk: String,
    /// Nonce for X25519 SK encryption (hex-encoded).
    pub x25519_sk_nonce: String,
    /// X25519 public key (hex-encoded).
    pub x25519_pk: String,
    /// Encrypted ML-DSA-65 secret key (hex-encoded).
    pub encrypted_mldsa_sk: String,
    /// Nonce for ML-DSA SK encryption (hex-encoded).
    pub mldsa_sk_nonce: String,
    /// ML-DSA-65 public key (hex-encoded).
    pub mldsa_pk: String,
    /// Encrypted Ed25519 secret key (hex-encoded).
    pub encrypted_ed25519_sk: String,
    /// Nonce for Ed25519 SK encryption (hex-encoded).
    pub ed25519_sk_nonce: String,
    /// Ed25519 public (verifying) key (hex-encoded).
    pub ed25519_pk: String,
}

impl EncryptedKeyStore {
    pub const CURRENT_VERSION: u32 = 1;
}

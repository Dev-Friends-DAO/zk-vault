/// Key management for zk-vault.
///
/// Key hierarchy:
///   Passphrase (never stored)
///       |
///       v  Argon2id (t=3, m=256MB, p=4)
///   Passphrase-Derived Key (PDK) -- used to encrypt all secret keys
///       |
///       +-- Master Key (MK) -- 256-bit random
///       |     +-- ML-KEM-768 key pair   (post-quantum KEM)
///       |     +-- X25519 key pair       (classical KEM)
///       |     +-- ML-DSA-65 key pair    (post-quantum signatures)
///       |     +-- Ed25519 key pair      (classical signatures)
use serde::{Deserialize, Serialize};

use crate::crypto::{aead, kdf, kem, sensitive::SensitiveBytes32, sign};
use crate::error::{Result, VaultError};

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

/// Generate a new key store: create all key pairs, encrypt secret keys with
/// a passphrase-derived key, and return the encrypted key store.
pub fn generate_key_store(passphrase: &[u8]) -> Result<EncryptedKeyStore> {
    // 1. Derive passphrase-derived key (PDK) via Argon2id
    let salt = kdf::generate_salt();
    let pdk = kdf::derive_key(passphrase, &salt)?;

    // 2. Generate master key
    let master_key = aead::generate_key();

    // 3. Generate all key pairs
    let kem_kp = kem::KemKeyPair::generate();
    let x25519_kp = kem::X25519KeyPair::generate();
    let mldsa_kp = sign::MlDsaKeyPair::generate();
    let ed25519_kp = sign::Ed25519KeyPair::generate();

    // 4. Encrypt each secret key with PDK
    let (mk_nonce, mk_ct) = aead::encrypt(&pdk, master_key.as_bytes(), b"zk-vault:mk")?;
    let (kem_nonce, kem_ct) = aead::encrypt(&pdk, kem_kp.secret_key_bytes(), b"zk-vault:kem-sk")?;
    let (x25519_nonce, x25519_ct) = aead::encrypt(
        &pdk,
        x25519_kp.secret_key().to_bytes().as_ref(),
        b"zk-vault:x25519-sk",
    )?;
    let (mldsa_nonce, mldsa_ct) =
        aead::encrypt(&pdk, mldsa_kp.secret_key_bytes(), b"zk-vault:mldsa-sk")?;
    let (ed25519_nonce, ed25519_ct) = aead::encrypt(
        &pdk,
        ed25519_kp.signing_key().to_bytes().as_ref(),
        b"zk-vault:ed25519-sk",
    )?;

    Ok(EncryptedKeyStore {
        version: EncryptedKeyStore::CURRENT_VERSION,
        kdf_salt: hex::encode(salt),
        encrypted_master_key: hex::encode(mk_ct),
        master_key_nonce: hex::encode(mk_nonce),
        encrypted_kem_sk: hex::encode(kem_ct),
        kem_sk_nonce: hex::encode(kem_nonce),
        kem_pk: hex::encode(&kem_kp.public_key),
        encrypted_x25519_sk: hex::encode(x25519_ct),
        x25519_sk_nonce: hex::encode(x25519_nonce),
        x25519_pk: hex::encode(x25519_kp.public_key.as_bytes()),
        encrypted_mldsa_sk: hex::encode(mldsa_ct),
        mldsa_sk_nonce: hex::encode(mldsa_nonce),
        mldsa_pk: hex::encode(&mldsa_kp.public_key),
        encrypted_ed25519_sk: hex::encode(ed25519_ct),
        ed25519_sk_nonce: hex::encode(ed25519_nonce),
        ed25519_pk: hex::encode(ed25519_kp.verifying_key.to_bytes()),
    })
}

/// Unlock the master key from an encrypted key store using a passphrase.
pub fn unlock_master_key(passphrase: &[u8], store: &EncryptedKeyStore) -> Result<SensitiveBytes32> {
    let salt = hex::decode(&store.kdf_salt)
        .map_err(|e| VaultError::KeyDerivation(format!("Invalid salt hex: {e}")))?;

    let pdk = kdf::derive_key(passphrase, &salt)?;

    let nonce_bytes = hex::decode(&store.master_key_nonce)
        .map_err(|e| VaultError::Decryption(format!("Invalid nonce hex: {e}")))?;
    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| VaultError::Decryption("Invalid nonce length".to_string()))?;

    let ciphertext = hex::decode(&store.encrypted_master_key)
        .map_err(|e| VaultError::Decryption(format!("Invalid ciphertext hex: {e}")))?;

    let mk_bytes = aead::decrypt(&pdk, &nonce, &ciphertext, b"zk-vault:mk")
        .map_err(|_| VaultError::InvalidPassphrase)?;

    SensitiveBytes32::from_slice(&mk_bytes)
        .ok_or_else(|| VaultError::Decryption("Master key is not 32 bytes".to_string()))
}

/// Decrypt a specific secret key from the store.
fn decrypt_field(
    pdk: &SensitiveBytes32,
    nonce_hex: &str,
    ciphertext_hex: &str,
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce_bytes =
        hex::decode(nonce_hex).map_err(|e| VaultError::Decryption(format!("Invalid hex: {e}")))?;
    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| VaultError::Decryption("Invalid nonce length".to_string()))?;
    let ciphertext = hex::decode(ciphertext_hex)
        .map_err(|e| VaultError::Decryption(format!("Invalid hex: {e}")))?;

    aead::decrypt(pdk, &nonce, &ciphertext, aad)
}

/// Decrypted key material from a key store.
pub struct UnlockedKeys {
    pub master_key: SensitiveBytes32,
    pub kem_sk: Vec<u8>,
    pub kem_pk: Vec<u8>,
    pub x25519_sk: Vec<u8>,
    pub x25519_pk: [u8; 32],
    pub mldsa_sk: Vec<u8>,
    pub mldsa_pk: Vec<u8>,
    pub ed25519_sk: [u8; 32],
    pub ed25519_pk: [u8; 32],
}

impl Drop for UnlockedKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.kem_sk.zeroize();
        self.x25519_sk.zeroize();
        self.mldsa_sk.zeroize();
        self.ed25519_sk.zeroize();
    }
}

/// Unlock all keys from the store.
pub fn unlock_all_keys(passphrase: &[u8], store: &EncryptedKeyStore) -> Result<UnlockedKeys> {
    let salt = hex::decode(&store.kdf_salt)
        .map_err(|e| VaultError::KeyDerivation(format!("Invalid salt hex: {e}")))?;
    let pdk = kdf::derive_key(passphrase, &salt)?;

    let mk_bytes = decrypt_field(
        &pdk,
        &store.master_key_nonce,
        &store.encrypted_master_key,
        b"zk-vault:mk",
    )
    .map_err(|_| VaultError::InvalidPassphrase)?;
    let master_key = SensitiveBytes32::from_slice(&mk_bytes)
        .ok_or_else(|| VaultError::Decryption("Master key is not 32 bytes".to_string()))?;

    let kem_sk = decrypt_field(
        &pdk,
        &store.kem_sk_nonce,
        &store.encrypted_kem_sk,
        b"zk-vault:kem-sk",
    )?;
    let x25519_sk = decrypt_field(
        &pdk,
        &store.x25519_sk_nonce,
        &store.encrypted_x25519_sk,
        b"zk-vault:x25519-sk",
    )?;
    let mldsa_sk = decrypt_field(
        &pdk,
        &store.mldsa_sk_nonce,
        &store.encrypted_mldsa_sk,
        b"zk-vault:mldsa-sk",
    )?;
    let ed25519_sk_bytes = decrypt_field(
        &pdk,
        &store.ed25519_sk_nonce,
        &store.encrypted_ed25519_sk,
        b"zk-vault:ed25519-sk",
    )?;

    let kem_pk = hex::decode(&store.kem_pk)
        .map_err(|e| VaultError::Decryption(format!("Invalid hex: {e}")))?;
    let x25519_pk_bytes = hex::decode(&store.x25519_pk)
        .map_err(|e| VaultError::Decryption(format!("Invalid hex: {e}")))?;
    let mldsa_pk = hex::decode(&store.mldsa_pk)
        .map_err(|e| VaultError::Decryption(format!("Invalid hex: {e}")))?;
    let ed25519_pk_bytes = hex::decode(&store.ed25519_pk)
        .map_err(|e| VaultError::Decryption(format!("Invalid hex: {e}")))?;

    let x25519_pk: [u8; 32] = x25519_pk_bytes
        .try_into()
        .map_err(|_| VaultError::Decryption("X25519 pk not 32 bytes".to_string()))?;
    let ed25519_sk: [u8; 32] = ed25519_sk_bytes
        .try_into()
        .map_err(|_| VaultError::Decryption("Ed25519 sk not 32 bytes".to_string()))?;
    let ed25519_pk: [u8; 32] = ed25519_pk_bytes
        .try_into()
        .map_err(|_| VaultError::Decryption("Ed25519 pk not 32 bytes".to_string()))?;

    Ok(UnlockedKeys {
        master_key,
        kem_sk,
        kem_pk,
        x25519_sk,
        x25519_pk,
        mldsa_sk,
        mldsa_pk,
        ed25519_sk,
        ed25519_pk,
    })
}

/// Default vault directory path.
pub fn vault_dir() -> std::path::PathBuf {
    dirs::home_dir()
        .expect("Cannot determine home directory")
        .join(".zk-vault")
}

/// Path to the key store file.
pub fn keystore_path() -> std::path::PathBuf {
    vault_dir().join("keystore.json")
}

/// Save an encrypted key store to disk.
pub fn save_key_store(store: &EncryptedKeyStore) -> Result<()> {
    let dir = vault_dir();
    std::fs::create_dir_all(&dir).map_err(VaultError::Io)?;

    let path = keystore_path();
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| VaultError::Serialization(e.to_string()))?;
    std::fs::write(&path, json).map_err(VaultError::Io)?;

    // Restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(VaultError::Io)?;
    }

    Ok(())
}

/// Load an encrypted key store from disk.
pub fn load_key_store() -> Result<EncryptedKeyStore> {
    let path = keystore_path();
    let json = std::fs::read_to_string(&path).map_err(VaultError::Io)?;
    serde_json::from_str(&json).map_err(|e| VaultError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_store_fast(passphrase: &[u8]) -> EncryptedKeyStore {
        // Use fast KDF for tests by generating with a pre-derived PDK
        let salt = kdf::generate_salt();
        let pdk = crate::crypto::kdf::derive_key_test(passphrase, &salt).unwrap();

        let master_key = aead::generate_key();
        let kem_kp = kem::KemKeyPair::generate();
        let x25519_kp = kem::X25519KeyPair::generate();
        let mldsa_kp = sign::MlDsaKeyPair::generate();
        let ed25519_kp = sign::Ed25519KeyPair::generate();

        let (mk_nonce, mk_ct) = aead::encrypt(&pdk, master_key.as_bytes(), b"zk-vault:mk").unwrap();
        let (kem_nonce, kem_ct) =
            aead::encrypt(&pdk, kem_kp.secret_key_bytes(), b"zk-vault:kem-sk").unwrap();
        let (x25519_nonce, x25519_ct) = aead::encrypt(
            &pdk,
            x25519_kp.secret_key().to_bytes().as_ref(),
            b"zk-vault:x25519-sk",
        )
        .unwrap();
        let (mldsa_nonce, mldsa_ct) =
            aead::encrypt(&pdk, mldsa_kp.secret_key_bytes(), b"zk-vault:mldsa-sk").unwrap();
        let (ed25519_nonce, ed25519_ct) = aead::encrypt(
            &pdk,
            ed25519_kp.signing_key().to_bytes().as_ref(),
            b"zk-vault:ed25519-sk",
        )
        .unwrap();

        EncryptedKeyStore {
            version: EncryptedKeyStore::CURRENT_VERSION,
            kdf_salt: hex::encode(salt),
            encrypted_master_key: hex::encode(mk_ct),
            master_key_nonce: hex::encode(mk_nonce),
            encrypted_kem_sk: hex::encode(kem_ct),
            kem_sk_nonce: hex::encode(kem_nonce),
            kem_pk: hex::encode(&kem_kp.public_key),
            encrypted_x25519_sk: hex::encode(x25519_ct),
            x25519_sk_nonce: hex::encode(x25519_nonce),
            x25519_pk: hex::encode(x25519_kp.public_key.as_bytes()),
            encrypted_mldsa_sk: hex::encode(mldsa_ct),
            mldsa_sk_nonce: hex::encode(mldsa_nonce),
            mldsa_pk: hex::encode(&mldsa_kp.public_key),
            encrypted_ed25519_sk: hex::encode(ed25519_ct),
            ed25519_sk_nonce: hex::encode(ed25519_nonce),
            ed25519_pk: hex::encode(ed25519_kp.verifying_key.to_bytes()),
        }
    }

    #[test]
    fn test_unlock_master_key_roundtrip() {
        let passphrase = b"test-passphrase-12345";
        let store = generate_store_fast(passphrase);
        // unlock_master_key uses production KDF, so we test with decrypt_field directly
        let salt = hex::decode(&store.kdf_salt).unwrap();
        let pdk = crate::crypto::kdf::derive_key_test(passphrase, &salt).unwrap();
        let mk = decrypt_field(
            &pdk,
            &store.master_key_nonce,
            &store.encrypted_master_key,
            b"zk-vault:mk",
        )
        .unwrap();
        assert_eq!(mk.len(), 32);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let store = generate_store_fast(b"correct-passphrase");
        let salt = hex::decode(&store.kdf_salt).unwrap();
        let wrong_pdk = crate::crypto::kdf::derive_key_test(b"wrong-passphrase", &salt).unwrap();
        let result = decrypt_field(
            &wrong_pdk,
            &store.master_key_nonce,
            &store.encrypted_master_key,
            b"zk-vault:mk",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_unlock_all_keys() {
        let passphrase = b"test-passphrase-12345";
        let store = generate_store_fast(passphrase);
        let salt = hex::decode(&store.kdf_salt).unwrap();
        // Manually construct PDK with test params to verify all fields decrypt
        let pdk = crate::crypto::kdf::derive_key_test(passphrase, &salt).unwrap();

        // Verify each field decrypts
        let mk = decrypt_field(
            &pdk,
            &store.master_key_nonce,
            &store.encrypted_master_key,
            b"zk-vault:mk",
        )
        .unwrap();
        assert_eq!(mk.len(), 32);

        let kem_sk = decrypt_field(
            &pdk,
            &store.kem_sk_nonce,
            &store.encrypted_kem_sk,
            b"zk-vault:kem-sk",
        )
        .unwrap();
        assert!(!kem_sk.is_empty());

        let x25519_sk = decrypt_field(
            &pdk,
            &store.x25519_sk_nonce,
            &store.encrypted_x25519_sk,
            b"zk-vault:x25519-sk",
        )
        .unwrap();
        assert_eq!(x25519_sk.len(), 32);

        let mldsa_sk = decrypt_field(
            &pdk,
            &store.mldsa_sk_nonce,
            &store.encrypted_mldsa_sk,
            b"zk-vault:mldsa-sk",
        )
        .unwrap();
        assert!(!mldsa_sk.is_empty());

        let ed25519_sk = decrypt_field(
            &pdk,
            &store.ed25519_sk_nonce,
            &store.encrypted_ed25519_sk,
            b"zk-vault:ed25519-sk",
        )
        .unwrap();
        assert_eq!(ed25519_sk.len(), 32);
    }

    #[test]
    fn test_key_store_serialization() {
        let store = generate_store_fast(b"test");
        let json = serde_json::to_string(&store).unwrap();
        let loaded: EncryptedKeyStore = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.version, EncryptedKeyStore::CURRENT_VERSION);
        assert_eq!(loaded.kdf_salt, store.kdf_salt);
        assert_eq!(loaded.kem_pk, store.kem_pk);
    }
}

/// Key management for zk-vault.
///
/// Key hierarchy:
///   Passphrase (never stored)
///       |
///       v  Argon2id (t=3, m=256MB, p=4)
///   Passphrase-Derived Key (PDK) -- encrypts only the Master Key
///       |
///       v
///   Master Key (MK) -- 256-bit random, encrypts all individual secret keys
///       +-- ML-KEM-768 key pair   (post-quantum KEM)
///       +-- X25519 key pair       (classical KEM)
///       +-- ML-DSA-65 key pair    (post-quantum signatures)
///       +-- Ed25519 key pair      (classical signatures)
use serde::{Deserialize, Serialize};

use crate::crypto::{aead, hash, kdf, kem, sensitive::SensitiveBytes32, sign};
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
    /// BLAKE3 hash of the keyfile (hex-encoded), if keyfile was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyfile_hash: Option<String>,
    /// Whether a hardware key was used during key derivation.
    #[serde(default)]
    pub hwkey_enabled: bool,
}

impl EncryptedKeyStore {
    pub const CURRENT_VERSION: u32 = 2;
}

/// Generate a new key store: create all key pairs, encrypt secret keys with
/// the master key (which is itself encrypted by the PDK), and return the
/// encrypted key store along with a BIP-39 mnemonic for MK recovery.
pub fn generate_key_store(
    passphrase: &[u8],
    keyfile: Option<&[u8]>,
    hwkey_response: Option<&[u8; 32]>,
) -> Result<(EncryptedKeyStore, String)> {
    use crate::crypto::mnemonic;

    // 1. Derive passphrase-derived key (PDK) via Argon2id + optional factors
    let salt = kdf::generate_salt();
    let pdk = kdf::derive_pdk(passphrase, &salt, keyfile, hwkey_response)?;

    // 2. Generate master key
    let master_key = aead::generate_key();

    // 3. Convert MK to mnemonic for recovery
    let mnemonic_phrase = mnemonic::master_key_to_mnemonic(&master_key)?;

    // 4. Generate all key pairs
    let kem_kp = kem::KemKeyPair::generate();
    let x25519_kp = kem::X25519KeyPair::generate();
    let mldsa_kp = sign::MlDsaKeyPair::generate();
    let ed25519_kp = sign::Ed25519KeyPair::generate();

    // 5. Encrypt MK with PDK
    let (mk_nonce, mk_ct) = aead::encrypt(&pdk, master_key.as_bytes(), b"zk-vault:mk")?;
    // 6. Encrypt individual secret keys with MK
    let (kem_nonce, kem_ct) =
        aead::encrypt(&master_key, kem_kp.secret_key_bytes(), b"zk-vault:kem-sk")?;
    let (x25519_nonce, x25519_ct) = aead::encrypt(
        &master_key,
        x25519_kp.secret_key().to_bytes().as_ref(),
        b"zk-vault:x25519-sk",
    )?;
    let (mldsa_nonce, mldsa_ct) = aead::encrypt(
        &master_key,
        mldsa_kp.secret_key_bytes(),
        b"zk-vault:mldsa-sk",
    )?;
    let (ed25519_nonce, ed25519_ct) = aead::encrypt(
        &master_key,
        ed25519_kp.signing_key().to_bytes().as_ref(),
        b"zk-vault:ed25519-sk",
    )?;

    let store = EncryptedKeyStore {
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
        keyfile_hash: keyfile.map(|kf| hex::encode(hash::hash(kf))),
        hwkey_enabled: hwkey_response.is_some(),
    };

    Ok((store, mnemonic_phrase))
}

/// Recover a vault from a mnemonic phrase. Generates fresh key pairs,
/// encrypts them under the recovered MK (which is encrypted by the new PDK).
pub fn recover_from_mnemonic(
    mnemonic: &str,
    passphrase: &[u8],
    keyfile: Option<&[u8]>,
    hwkey_response: Option<&[u8; 32]>,
) -> Result<EncryptedKeyStore> {
    use crate::crypto::mnemonic as mnem;
    let master_key = mnem::mnemonic_to_master_key(mnemonic)?;

    let salt = kdf::generate_salt();
    let pdk = kdf::derive_pdk(passphrase, &salt, keyfile, hwkey_response)?;

    // Generate fresh key pairs
    let kem_kp = kem::KemKeyPair::generate();
    let x25519_kp = kem::X25519KeyPair::generate();
    let mldsa_kp = sign::MlDsaKeyPair::generate();
    let ed25519_kp = sign::Ed25519KeyPair::generate();

    // Encrypt MK with PDK
    let (mk_nonce, mk_ct) = aead::encrypt(&pdk, master_key.as_bytes(), b"zk-vault:mk")?;

    // Encrypt individual keys with MK
    let (kem_nonce, kem_ct) =
        aead::encrypt(&master_key, kem_kp.secret_key_bytes(), b"zk-vault:kem-sk")?;
    let (x25519_nonce, x25519_ct) = aead::encrypt(
        &master_key,
        x25519_kp.secret_key().to_bytes().as_ref(),
        b"zk-vault:x25519-sk",
    )?;
    let (mldsa_nonce, mldsa_ct) = aead::encrypt(
        &master_key,
        mldsa_kp.secret_key_bytes(),
        b"zk-vault:mldsa-sk",
    )?;
    let (ed25519_nonce, ed25519_ct) = aead::encrypt(
        &master_key,
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
        keyfile_hash: keyfile.map(|kf| hex::encode(hash::hash(kf))),
        hwkey_enabled: hwkey_response.is_some(),
    })
}

/// Recover a vault from a mnemonic phrase (test variant with fast KDF).
#[cfg(test)]
pub fn recover_from_mnemonic_test(
    mnemonic: &str,
    passphrase: &[u8],
    keyfile: Option<&[u8]>,
    hwkey_response: Option<&[u8; 32]>,
) -> Result<EncryptedKeyStore> {
    use crate::crypto::mnemonic as mnem;
    let master_key = mnem::mnemonic_to_master_key(mnemonic)?;

    let salt = kdf::generate_salt();
    let pdk = kdf::derive_pdk_test(passphrase, &salt, keyfile, hwkey_response)?;

    let kem_kp = kem::KemKeyPair::generate();
    let x25519_kp = kem::X25519KeyPair::generate();
    let mldsa_kp = sign::MlDsaKeyPair::generate();
    let ed25519_kp = sign::Ed25519KeyPair::generate();

    let (mk_nonce, mk_ct) = aead::encrypt(&pdk, master_key.as_bytes(), b"zk-vault:mk")?;
    let (kem_nonce, kem_ct) =
        aead::encrypt(&master_key, kem_kp.secret_key_bytes(), b"zk-vault:kem-sk")?;
    let (x25519_nonce, x25519_ct) = aead::encrypt(
        &master_key,
        x25519_kp.secret_key().to_bytes().as_ref(),
        b"zk-vault:x25519-sk",
    )?;
    let (mldsa_nonce, mldsa_ct) = aead::encrypt(
        &master_key,
        mldsa_kp.secret_key_bytes(),
        b"zk-vault:mldsa-sk",
    )?;
    let (ed25519_nonce, ed25519_ct) = aead::encrypt(
        &master_key,
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
        keyfile_hash: keyfile.map(|kf| hex::encode(hash::hash(kf))),
        hwkey_enabled: hwkey_response.is_some(),
    })
}

/// Unlock the master key from an encrypted key store using a passphrase.
pub fn unlock_master_key(
    passphrase: &[u8],
    store: &EncryptedKeyStore,
    keyfile: Option<&[u8]>,
    hwkey_response: Option<&[u8; 32]>,
) -> Result<SensitiveBytes32> {
    // Validate that required factors are provided
    if store.keyfile_hash.is_some() && keyfile.is_none() {
        return Err(VaultError::KeyDerivation(
            "This vault requires a keyfile but none was provided".to_string(),
        ));
    }
    if store.hwkey_enabled && hwkey_response.is_none() {
        return Err(VaultError::KeyDerivation(
            "This vault requires a hardware key but none was provided".to_string(),
        ));
    }

    let salt = hex::decode(&store.kdf_salt)
        .map_err(|e| VaultError::KeyDerivation(format!("Invalid salt hex: {e}")))?;

    let pdk = kdf::derive_pdk(passphrase, &salt, keyfile, hwkey_response)?;

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
    key: &SensitiveBytes32,
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

    aead::decrypt(key, &nonce, &ciphertext, aad)
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
pub fn unlock_all_keys(
    passphrase: &[u8],
    store: &EncryptedKeyStore,
    keyfile: Option<&[u8]>,
    hwkey_response: Option<&[u8; 32]>,
) -> Result<UnlockedKeys> {
    // Validate that required factors are provided
    if store.keyfile_hash.is_some() && keyfile.is_none() {
        return Err(VaultError::KeyDerivation(
            "This vault requires a keyfile but none was provided".to_string(),
        ));
    }
    if store.hwkey_enabled && hwkey_response.is_none() {
        return Err(VaultError::KeyDerivation(
            "This vault requires a hardware key but none was provided".to_string(),
        ));
    }

    let salt = hex::decode(&store.kdf_salt)
        .map_err(|e| VaultError::KeyDerivation(format!("Invalid salt hex: {e}")))?;
    let pdk = kdf::derive_pdk(passphrase, &salt, keyfile, hwkey_response)?;

    // First decrypt MK with PDK
    let mk_bytes = decrypt_field(
        &pdk,
        &store.master_key_nonce,
        &store.encrypted_master_key,
        b"zk-vault:mk",
    )
    .map_err(|_| VaultError::InvalidPassphrase)?;
    let master_key = SensitiveBytes32::from_slice(&mk_bytes)
        .ok_or_else(|| VaultError::Decryption("Master key is not 32 bytes".to_string()))?;

    // Then decrypt individual keys with MK
    let kem_sk = decrypt_field(
        &master_key,
        &store.kem_sk_nonce,
        &store.encrypted_kem_sk,
        b"zk-vault:kem-sk",
    )?;
    let x25519_sk = decrypt_field(
        &master_key,
        &store.x25519_sk_nonce,
        &store.encrypted_x25519_sk,
        b"zk-vault:x25519-sk",
    )?;
    let mldsa_sk = decrypt_field(
        &master_key,
        &store.mldsa_sk_nonce,
        &store.encrypted_mldsa_sk,
        b"zk-vault:mldsa-sk",
    )?;
    let ed25519_sk_bytes = decrypt_field(
        &master_key,
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

    fn generate_store_fast(passphrase: &[u8]) -> (EncryptedKeyStore, String) {
        generate_store_fast_with_factors(passphrase, None, None)
    }

    fn generate_store_fast_with_factors(
        passphrase: &[u8],
        keyfile: Option<&[u8]>,
        hwkey_response: Option<&[u8; 32]>,
    ) -> (EncryptedKeyStore, String) {
        use crate::crypto::mnemonic;

        // Use fast KDF for tests by generating with a pre-derived PDK
        let salt = kdf::generate_salt();
        let pdk = crate::crypto::kdf::derive_pdk_test(passphrase, &salt, keyfile, hwkey_response)
            .unwrap();

        let master_key = aead::generate_key();
        let mnemonic_phrase = mnemonic::master_key_to_mnemonic(&master_key).unwrap();

        let kem_kp = kem::KemKeyPair::generate();
        let x25519_kp = kem::X25519KeyPair::generate();
        let mldsa_kp = sign::MlDsaKeyPair::generate();
        let ed25519_kp = sign::Ed25519KeyPair::generate();

        // Encrypt MK with PDK
        let (mk_nonce, mk_ct) = aead::encrypt(&pdk, master_key.as_bytes(), b"zk-vault:mk").unwrap();
        // Encrypt individual keys with MK
        let (kem_nonce, kem_ct) =
            aead::encrypt(&master_key, kem_kp.secret_key_bytes(), b"zk-vault:kem-sk").unwrap();
        let (x25519_nonce, x25519_ct) = aead::encrypt(
            &master_key,
            x25519_kp.secret_key().to_bytes().as_ref(),
            b"zk-vault:x25519-sk",
        )
        .unwrap();
        let (mldsa_nonce, mldsa_ct) = aead::encrypt(
            &master_key,
            mldsa_kp.secret_key_bytes(),
            b"zk-vault:mldsa-sk",
        )
        .unwrap();
        let (ed25519_nonce, ed25519_ct) = aead::encrypt(
            &master_key,
            ed25519_kp.signing_key().to_bytes().as_ref(),
            b"zk-vault:ed25519-sk",
        )
        .unwrap();

        let store = EncryptedKeyStore {
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
            keyfile_hash: keyfile.map(|kf| hex::encode(hash::hash(kf))),
            hwkey_enabled: hwkey_response.is_some(),
        };

        (store, mnemonic_phrase)
    }

    #[test]
    fn test_unlock_master_key_roundtrip() {
        let passphrase = b"test-passphrase-12345";
        let (store, _mnemonic) = generate_store_fast(passphrase);
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
        let (store, _) = generate_store_fast(b"correct-passphrase");
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
        let (store, _) = generate_store_fast(passphrase);
        let salt = hex::decode(&store.kdf_salt).unwrap();
        // Derive PDK with test params, then decrypt MK, then use MK for individual keys
        let pdk = crate::crypto::kdf::derive_key_test(passphrase, &salt).unwrap();

        // Decrypt MK with PDK
        let mk_bytes = decrypt_field(
            &pdk,
            &store.master_key_nonce,
            &store.encrypted_master_key,
            b"zk-vault:mk",
        )
        .unwrap();
        assert_eq!(mk_bytes.len(), 32);
        let master_key = SensitiveBytes32::from_slice(&mk_bytes).unwrap();

        // Decrypt individual keys with MK
        let kem_sk = decrypt_field(
            &master_key,
            &store.kem_sk_nonce,
            &store.encrypted_kem_sk,
            b"zk-vault:kem-sk",
        )
        .unwrap();
        assert!(!kem_sk.is_empty());

        let x25519_sk = decrypt_field(
            &master_key,
            &store.x25519_sk_nonce,
            &store.encrypted_x25519_sk,
            b"zk-vault:x25519-sk",
        )
        .unwrap();
        assert_eq!(x25519_sk.len(), 32);

        let mldsa_sk = decrypt_field(
            &master_key,
            &store.mldsa_sk_nonce,
            &store.encrypted_mldsa_sk,
            b"zk-vault:mldsa-sk",
        )
        .unwrap();
        assert!(!mldsa_sk.is_empty());

        let ed25519_sk = decrypt_field(
            &master_key,
            &store.ed25519_sk_nonce,
            &store.encrypted_ed25519_sk,
            b"zk-vault:ed25519-sk",
        )
        .unwrap();
        assert_eq!(ed25519_sk.len(), 32);
    }

    #[test]
    fn test_key_store_serialization() {
        let (store, _) = generate_store_fast(b"test");
        let json = serde_json::to_string(&store).unwrap();
        let loaded: EncryptedKeyStore = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.version, EncryptedKeyStore::CURRENT_VERSION);
        assert_eq!(loaded.kdf_salt, store.kdf_salt);
        assert_eq!(loaded.kem_pk, store.kem_pk);
    }

    #[test]
    fn test_generate_store_returns_mnemonic() {
        let (_, mnemonic) = generate_store_fast(b"test");
        let word_count = mnemonic.split_whitespace().count();
        assert_eq!(word_count, 24);
    }

    #[test]
    fn test_recover_from_mnemonic() {
        let passphrase = b"original-passphrase";
        let (store, mnemonic) = generate_store_fast(passphrase);

        // Recover with mnemonic + new passphrase
        let new_passphrase = b"new-passphrase";
        let recovered_store =
            recover_from_mnemonic_test(&mnemonic, new_passphrase, None, None).unwrap();

        // Verify the recovered store can be unlocked with the new passphrase
        let new_salt = hex::decode(&recovered_store.kdf_salt).unwrap();
        let new_pdk = crate::crypto::kdf::derive_key_test(new_passphrase, &new_salt).unwrap();

        // Decrypt MK from recovered store
        let mk_bytes = decrypt_field(
            &new_pdk,
            &recovered_store.master_key_nonce,
            &recovered_store.encrypted_master_key,
            b"zk-vault:mk",
        )
        .unwrap();
        assert_eq!(mk_bytes.len(), 32);

        // Decrypt MK from original store
        let orig_salt = hex::decode(&store.kdf_salt).unwrap();
        let orig_pdk = crate::crypto::kdf::derive_key_test(passphrase, &orig_salt).unwrap();
        let orig_mk_bytes = decrypt_field(
            &orig_pdk,
            &store.master_key_nonce,
            &store.encrypted_master_key,
            b"zk-vault:mk",
        )
        .unwrap();

        // The master keys should be identical
        assert_eq!(mk_bytes, orig_mk_bytes);

        // Verify individual keys can be decrypted with the recovered MK
        let master_key = SensitiveBytes32::from_slice(&mk_bytes).unwrap();
        let kem_sk = decrypt_field(
            &master_key,
            &recovered_store.kem_sk_nonce,
            &recovered_store.encrypted_kem_sk,
            b"zk-vault:kem-sk",
        )
        .unwrap();
        assert!(!kem_sk.is_empty());
    }
}

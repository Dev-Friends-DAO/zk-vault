//! Encrypted keystore for BTC/ETH anchor keys.
//!
//! Stores blockchain private keys (BTC WIF, ETH hex) encrypted with
//! Argon2id + XChaCha20-Poly1305, following the same security model
//! as the main zk-vault keystore.
//!
//! Keys are NEVER stored in plain text. Access requires a passphrase.

use serde::{Deserialize, Serialize};

use super::aead;
use super::kdf;
use super::sensitive::{SensitiveBytes32, SensitiveVec};

use crate::error::{Result, VaultError};

/// Domain separator for anchor key encryption AAD.
const AAD_BTC: &[u8] = b"zk-vault:anchor-key:bitcoin";
const AAD_ETH: &[u8] = b"zk-vault:anchor-key:ethereum";

/// Encrypted anchor keystore, serialized to disk as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorKeyStore {
    /// Format version.
    pub version: u32,
    /// Argon2id salt (hex-encoded, 32 bytes).
    pub kdf_salt: String,
    /// KDF parameters.
    pub kdf_time_cost: u32,
    pub kdf_memory_kib: u32,
    pub kdf_parallelism: u32,
    /// Encrypted BTC WIF key (if configured).
    pub btc_key: Option<EncryptedKey>,
    /// Encrypted ETH private key hex (if configured).
    pub eth_key: Option<EncryptedKey>,
}

/// An individual encrypted key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    /// XChaCha20 nonce (hex-encoded, 24 bytes).
    pub nonce: String,
    /// Ciphertext + Poly1305 tag (hex-encoded).
    pub ciphertext: String,
}

/// Unlocked anchor keys (zeroized on drop).
pub struct UnlockedAnchorKeys {
    /// BTC WIF private key (if configured).
    pub btc_wif: Option<SensitiveVec>,
    /// ETH private key hex (if configured).
    pub eth_private_key: Option<SensitiveVec>,
}

impl Drop for UnlockedAnchorKeys {
    fn drop(&mut self) {
        // SensitiveVec handles zeroization automatically
    }
}

/// Create a new anchor keystore with the given keys, encrypted under passphrase.
///
/// Either or both keys may be None (configured later).
pub fn create_anchor_keystore(
    passphrase: &[u8],
    btc_wif: Option<&str>,
    eth_private_key: Option<&str>,
) -> Result<AnchorKeyStore> {
    let salt = kdf::generate_salt();
    let pdk = kdf::derive_key(passphrase, &salt)?;

    let btc_key = encrypt_optional_key(&pdk, btc_wif, AAD_BTC)?;
    let eth_key = encrypt_optional_key(&pdk, eth_private_key, AAD_ETH)?;

    Ok(AnchorKeyStore {
        version: 1,
        kdf_salt: hex::encode(salt),
        kdf_time_cost: kdf::ARGON2_TIME_COST,
        kdf_memory_kib: kdf::ARGON2_MEMORY_KIB,
        kdf_parallelism: kdf::ARGON2_PARALLELISM,
        btc_key,
        eth_key,
    })
}

/// Create anchor keystore with fast KDF parameters (for testing only).
#[cfg(test)]
pub fn create_anchor_keystore_test(
    passphrase: &[u8],
    btc_wif: Option<&str>,
    eth_private_key: Option<&str>,
) -> Result<AnchorKeyStore> {
    let salt = kdf::generate_salt();
    let pdk = kdf::derive_key_test(passphrase, &salt)?;

    let btc_key = encrypt_optional_key(&pdk, btc_wif, AAD_BTC)?;
    let eth_key = encrypt_optional_key(&pdk, eth_private_key, AAD_ETH)?;

    Ok(AnchorKeyStore {
        version: 1,
        kdf_salt: hex::encode(salt),
        kdf_time_cost: 1,
        kdf_memory_kib: 1024,
        kdf_parallelism: 1,
        btc_key,
        eth_key,
    })
}

/// Encrypt an optional key string, returning an EncryptedKey if present.
fn encrypt_optional_key(
    pdk: &SensitiveBytes32,
    key: Option<&str>,
    aad: &[u8],
) -> Result<Option<EncryptedKey>> {
    match key {
        Some(k) => {
            let (nonce, ciphertext) = aead::encrypt(pdk, k.as_bytes(), aad)?;
            Ok(Some(EncryptedKey {
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(ciphertext),
            }))
        }
        None => Ok(None),
    }
}

/// Unlock the anchor keystore with a passphrase.
/// Returns the decrypted keys (zeroized on drop).
pub fn unlock_anchor_keystore(
    passphrase: &[u8],
    store: &AnchorKeyStore,
) -> Result<UnlockedAnchorKeys> {
    let salt = hex::decode(&store.kdf_salt)
        .map_err(|e| VaultError::KeyDerivation(format!("Invalid salt hex: {e}")))?;

    let pdk = kdf::derive_key_with_params(
        passphrase,
        &salt,
        store.kdf_time_cost,
        store.kdf_memory_kib,
        store.kdf_parallelism,
    )?;

    let btc_wif = decrypt_optional_key(&pdk, &store.btc_key, AAD_BTC)?;
    let eth_private_key = decrypt_optional_key(&pdk, &store.eth_key, AAD_ETH)?;

    Ok(UnlockedAnchorKeys {
        btc_wif,
        eth_private_key,
    })
}

/// Decrypt an optional encrypted key entry, returning SensitiveVec if present.
fn decrypt_optional_key(
    pdk: &SensitiveBytes32,
    encrypted: &Option<EncryptedKey>,
    aad: &[u8],
) -> Result<Option<SensitiveVec>> {
    match encrypted {
        Some(entry) => {
            let nonce_bytes = hex::decode(&entry.nonce)
                .map_err(|e| VaultError::Decryption(format!("Invalid nonce hex: {e}")))?;
            let nonce: [u8; 24] = nonce_bytes
                .try_into()
                .map_err(|_| VaultError::Decryption("Invalid nonce length".into()))?;
            let ciphertext = hex::decode(&entry.ciphertext)
                .map_err(|e| VaultError::Decryption(format!("Invalid ciphertext hex: {e}")))?;
            let plaintext = aead::decrypt(pdk, &nonce, &ciphertext, aad)?;
            Ok(Some(SensitiveVec::new(plaintext)))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_unlock_both_keys() {
        let passphrase = b"test-passphrase-123";
        let btc_wif = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
        let eth_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

        let store = create_anchor_keystore_test(passphrase, Some(btc_wif), Some(eth_key)).unwrap();
        assert!(store.btc_key.is_some());
        assert!(store.eth_key.is_some());
        assert_eq!(store.version, 1);

        let unlocked = unlock_anchor_keystore(passphrase, &store).unwrap();
        assert_eq!(
            std::str::from_utf8(unlocked.btc_wif.as_ref().unwrap().as_ref()).unwrap(),
            btc_wif
        );
        assert_eq!(
            std::str::from_utf8(unlocked.eth_private_key.as_ref().unwrap().as_ref()).unwrap(),
            eth_key
        );
    }

    #[test]
    fn create_btc_only() {
        let passphrase = b"btc-only";
        let btc_wif = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";

        let store = create_anchor_keystore_test(passphrase, Some(btc_wif), None).unwrap();
        assert!(store.btc_key.is_some());
        assert!(store.eth_key.is_none());

        let unlocked = unlock_anchor_keystore(passphrase, &store).unwrap();
        assert!(unlocked.btc_wif.is_some());
        assert!(unlocked.eth_private_key.is_none());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let store = create_anchor_keystore_test(b"correct", Some("test-wif"), None).unwrap();

        let result = unlock_anchor_keystore(b"wrong", &store);
        assert!(result.is_err());
    }

    #[test]
    fn empty_keystore() {
        let store = create_anchor_keystore_test(b"pass", None, None).unwrap();
        assert!(store.btc_key.is_none());
        assert!(store.eth_key.is_none());

        let unlocked = unlock_anchor_keystore(b"pass", &store).unwrap();
        assert!(unlocked.btc_wif.is_none());
        assert!(unlocked.eth_private_key.is_none());
    }

    #[test]
    fn keystore_json_roundtrip() {
        let store =
            create_anchor_keystore_test(b"json-test", Some("btc-key"), Some("eth-key")).unwrap();

        let json = serde_json::to_string_pretty(&store).unwrap();
        let loaded: AnchorKeyStore = serde_json::from_str(&json).unwrap();

        let unlocked = unlock_anchor_keystore(b"json-test", &loaded).unwrap();
        assert_eq!(
            std::str::from_utf8(unlocked.btc_wif.as_ref().unwrap().as_ref()).unwrap(),
            "btc-key"
        );
    }
}

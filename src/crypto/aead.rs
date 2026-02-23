/// XChaCha20-Poly1305 AEAD encryption for file content.
///
/// Each file gets a unique random key and nonce.
/// The 24-byte nonce of XChaCha20 is large enough for random generation
/// without practical collision risk.
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use crate::crypto::sensitive::SensitiveBytes32;
use crate::error::{Result, VaultError};

pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

/// Generate a random 256-bit symmetric key.
pub fn generate_key() -> SensitiveBytes32 {
    let mut key = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
    SensitiveBytes32::new(key)
}

/// Generate a random 24-byte nonce for XChaCha20-Poly1305.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypt plaintext with XChaCha20-Poly1305.
///
/// Returns (nonce, ciphertext_with_tag).
/// The AAD (additional authenticated data) is authenticated but not encrypted.
pub fn encrypt(
    key: &SensitiveBytes32,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|e| VaultError::Encryption(e.to_string()))?;

    let nonce_bytes = generate_nonce();
    let nonce = XNonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;

    Ok((nonce_bytes, ciphertext))
}

/// Decrypt ciphertext with XChaCha20-Poly1305.
pub fn decrypt(
    key: &SensitiveBytes32,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|e| VaultError::Decryption(e.to_string()))?;

    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(xnonce, payload)
        .map_err(|e| VaultError::Decryption(e.to_string()))?;

    Ok(plaintext)
}

/// Encrypt with a specific nonce (used internally for key wrapping with fixed nonce).
pub fn encrypt_with_nonce(
    key: &SensitiveBytes32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|e| VaultError::Encryption(e.to_string()))?;

    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(xnonce, payload)
        .map_err(|e| VaultError::Encryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"Hello, zk-vault! This is secret data.";
        let aad = b"file:documents/test.txt";

        let (nonce, ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"secret";
        let aad = b"";

        let (nonce, ciphertext) = encrypt(&key1, plaintext, aad).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext, aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = generate_key();
        let plaintext = b"secret";

        let (nonce, ciphertext) = encrypt(&key, plaintext, b"correct aad").unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, b"wrong aad");

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = generate_key();
        let plaintext = b"secret";
        let aad = b"";

        let (nonce, mut ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        ciphertext[0] ^= 0xFF; // flip a byte
        let result = decrypt(&key, &nonce, &ciphertext, aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = generate_key();
        let (nonce, ciphertext) = encrypt(&key, b"", b"").unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, b"").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let key = generate_key();
        let plaintext = vec![0xAB; 1_000_000]; // 1 MB
        let aad = b"large-file";

        let (nonce, ciphertext) = encrypt(&key, &plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}

//! BIP-39 mnemonic encoding for Master Key recovery.
//!
//! The 256-bit Master Key is encoded as a 24-word mnemonic phrase.
//! This mnemonic IS the MK — not a seed derivation.

use crate::crypto::sensitive::SensitiveBytes32;
use crate::error::{Result, VaultError};

/// Convert a 256-bit Master Key to a 24-word BIP-39 mnemonic.
pub fn master_key_to_mnemonic(mk: &SensitiveBytes32) -> Result<String> {
    let mnemonic = bip39::Mnemonic::from_entropy(mk.as_bytes())
        .map_err(|e| VaultError::KeyDerivation(format!("Failed to create mnemonic: {e}")))?;
    Ok(mnemonic.to_string())
}

/// Parse a 24-word BIP-39 mnemonic back to the Master Key.
pub fn mnemonic_to_master_key(words: &str) -> Result<SensitiveBytes32> {
    let mnemonic: bip39::Mnemonic = words
        .parse()
        .map_err(|e| VaultError::KeyDerivation(format!("Invalid mnemonic: {e}")))?;
    let entropy = mnemonic.to_entropy();
    SensitiveBytes32::from_slice(&entropy)
        .ok_or_else(|| VaultError::KeyDerivation("Mnemonic entropy is not 32 bytes".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead;

    #[test]
    fn roundtrip() {
        let mk = aead::generate_key();
        let words = master_key_to_mnemonic(&mk).unwrap();
        let word_count = words.split_whitespace().count();
        assert_eq!(word_count, 24);
        let recovered = mnemonic_to_master_key(&words).unwrap();
        assert_eq!(mk.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn invalid_mnemonic_fails() {
        let result = mnemonic_to_master_key("invalid words that are not a mnemonic");
        assert!(result.is_err());
    }

    #[test]
    fn wrong_word_count_fails() {
        // 12 words instead of 24
        let result = mnemonic_to_master_key("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        // This should succeed as 12 words = 128 bits, but from_slice will fail because it's not 32 bytes
        assert!(result.is_err());
    }

    #[test]
    fn deterministic() {
        let mk = SensitiveBytes32::new([0x42; 32]);
        let w1 = master_key_to_mnemonic(&mk).unwrap();
        let w2 = master_key_to_mnemonic(&mk).unwrap();
        assert_eq!(w1, w2);
    }
}

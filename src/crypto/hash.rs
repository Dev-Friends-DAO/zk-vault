/// BLAKE3 hashing utilities for zk-vault.
///
/// BLAKE3 is used throughout the system for:
/// - Merkle tree construction (with domain separation)
/// - Key combining in hybrid KEM
/// - File integrity verification

/// Hash arbitrary data with BLAKE3.
pub fn hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Keyed hash for domain-separated operations.
/// The key must be exactly 32 bytes.
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(key, data).into()
}

/// Derive a key from input keying material using BLAKE3's key derivation mode.
/// Context should be a unique, hardcoded string identifying the usage.
pub fn derive_key(context: &str, ikm: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut deriver = blake3::Hasher::new_derive_key(context);
    deriver.update(ikm);
    let mut reader = deriver.finalize_xof();
    reader.fill(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let data = b"hello zk-vault";
        assert_eq!(hash(data), hash(data));
    }

    #[test]
    fn test_hash_different_inputs() {
        assert_ne!(hash(b"hello"), hash(b"world"));
    }

    #[test]
    fn test_keyed_hash() {
        let key = [0x42u8; 32];
        let h1 = keyed_hash(&key, b"data");
        let h2 = keyed_hash(&key, b"data");
        assert_eq!(h1, h2);

        let key2 = [0x43u8; 32];
        let h3 = keyed_hash(&key2, b"data");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_derive_key() {
        let k1 = derive_key("zk-vault test context", b"input");
        let k2 = derive_key("zk-vault test context", b"input");
        assert_eq!(k1, k2);

        let k3 = derive_key("different context", b"input");
        assert_ne!(k1, k3);
    }
}

/// Encrypted bundle format for zk-vault.
///
/// Format:
/// [version(1B) | kem_ct(1088B) | eph_x25519_pk(32B) | nonce(24B) | wrapped_key(48B) | ciphertext]
use crate::error::{Result, VaultError};

pub const BUNDLE_VERSION: u8 = 0x01;
pub const KEM_CT_LEN: usize = 1088;
pub const EPH_PK_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const WRAPPED_KEY_LEN: usize = 48; // 32 key + 16 auth tag
pub const HEADER_LEN: usize = 1 + KEM_CT_LEN + EPH_PK_LEN + NONCE_LEN + WRAPPED_KEY_LEN;

/// Parsed encrypted bundle.
pub struct EncryptedBundle {
    pub version: u8,
    pub kem_ciphertext: Vec<u8>,
    pub eph_x25519_pk: [u8; 32],
    pub nonce: [u8; 24],
    pub wrapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl EncryptedBundle {
    /// Serialize the bundle to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        out.push(self.version);
        out.extend_from_slice(&self.kem_ciphertext);
        out.extend_from_slice(&self.eph_x25519_pk);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped_key);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse a bundle from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_LEN {
            return Err(VaultError::Decryption(format!(
                "Bundle too short: {} bytes (minimum {})",
                data.len(),
                HEADER_LEN
            )));
        }

        let version = data[0];
        if version != BUNDLE_VERSION {
            return Err(VaultError::Decryption(format!(
                "Unsupported bundle version: {version}"
            )));
        }

        let mut offset = 1;

        let kem_ciphertext = data[offset..offset + KEM_CT_LEN].to_vec();
        offset += KEM_CT_LEN;

        let mut eph_x25519_pk = [0u8; 32];
        eph_x25519_pk.copy_from_slice(&data[offset..offset + EPH_PK_LEN]);
        offset += EPH_PK_LEN;

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&data[offset..offset + NONCE_LEN]);
        offset += NONCE_LEN;

        let wrapped_key = data[offset..offset + WRAPPED_KEY_LEN].to_vec();
        offset += WRAPPED_KEY_LEN;

        let ciphertext = data[offset..].to_vec();

        Ok(Self {
            version,
            kem_ciphertext,
            eph_x25519_pk,
            nonce,
            wrapped_key,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_roundtrip() {
        let bundle = EncryptedBundle {
            version: BUNDLE_VERSION,
            kem_ciphertext: vec![0xAA; KEM_CT_LEN],
            eph_x25519_pk: [0xBB; 32],
            nonce: [0xCC; 24],
            wrapped_key: vec![0xDD; WRAPPED_KEY_LEN],
            ciphertext: vec![0xEE; 1000],
        };

        let bytes = bundle.to_bytes();
        let parsed = EncryptedBundle::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, BUNDLE_VERSION);
        assert_eq!(parsed.kem_ciphertext, bundle.kem_ciphertext);
        assert_eq!(parsed.eph_x25519_pk, bundle.eph_x25519_pk);
        assert_eq!(parsed.nonce, bundle.nonce);
        assert_eq!(parsed.wrapped_key, bundle.wrapped_key);
        assert_eq!(parsed.ciphertext, bundle.ciphertext);
    }

    #[test]
    fn test_bundle_too_short() {
        assert!(EncryptedBundle::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_bundle_wrong_version() {
        let mut data = vec![0xFF]; // wrong version
        data.extend_from_slice(&vec![0u8; HEADER_LEN - 1]);
        assert!(EncryptedBundle::from_bytes(&data).is_err());
    }
}

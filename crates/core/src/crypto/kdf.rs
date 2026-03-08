/// Argon2id key derivation for passphrase-based encryption.
///
/// Parameters: t=3, m=256MB, p=4
/// Produces a 256-bit (32-byte) key from a passphrase and salt.
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use crate::crypto::sensitive::SensitiveBytes32;
use crate::error::{Result, VaultError};

/// Argon2id parameters matching the security specification.
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_MEMORY_KIB: u32 = 262_144; // 256 MiB
const ARGON2_PARALLELISM: u32 = 4;
const SALT_LEN: usize = 32;

/// Generate a random 32-byte salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a 32-byte key from a passphrase using Argon2id.
pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<SensitiveBytes32> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    Ok(SensitiveBytes32::new(output))
}

/// Derive a key with reduced parameters for testing (fast but insecure).
#[cfg(test)]
pub fn derive_key_test(passphrase: &[u8], salt: &[u8]) -> Result<SensitiveBytes32> {
    let params = Params::new(
        1024, // 1 MiB - fast for tests
        1,
        1,
        Some(32),
    )
    .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;

    Ok(SensitiveBytes32::new(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [0x42u8; 32];
        let k1 = derive_key_test(b"my passphrase", &salt).unwrap();
        let k2 = derive_key_test(b"my passphrase", &salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_derive_key_different_passphrase() {
        let salt = [0x42u8; 32];
        let k1 = derive_key_test(b"passphrase1", &salt).unwrap();
        let k2 = derive_key_test(b"passphrase2", &salt).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_derive_key_different_salt() {
        let k1 = derive_key_test(b"passphrase", &[0x01; 32]).unwrap();
        let k2 = derive_key_test(b"passphrase", &[0x02; 32]).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_generate_salt_unique() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1, s2);
    }
}

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

/// Derive PDK combining passphrase with optional keyfile and hardware key.
/// Uses BLAKE3 key derivation to mix all factors after base Argon2id derivation.
pub fn derive_pdk(
    passphrase: &[u8],
    salt: &[u8],
    keyfile: Option<&[u8]>,
    hwkey_response: Option<&[u8; 32]>,
) -> Result<SensitiveBytes32> {
    // Base derivation with Argon2id
    let base_pdk = derive_key(passphrase, salt)?;

    // If no additional factors, return base PDK
    if keyfile.is_none() && hwkey_response.is_none() {
        return Ok(base_pdk);
    }

    // Combine with additional factors using BLAKE3 derive_key
    let mut ikm = Vec::new();
    ikm.extend_from_slice(base_pdk.as_bytes());
    if let Some(kf) = keyfile {
        ikm.extend_from_slice(kf);
    }
    if let Some(hw) = hwkey_response {
        ikm.extend_from_slice(hw);
    }

    let combined = crate::crypto::hash::derive_key("zk-vault-pdk-combined-v1", &ikm);
    // Zeroize intermediate
    use zeroize::Zeroize;
    ikm.zeroize();

    Ok(SensitiveBytes32::new(combined))
}

/// Generate a random keyfile (64 bytes).
pub fn generate_keyfile() -> Vec<u8> {
    let mut data = vec![0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut data);
    data
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

/// Derive PDK with reduced parameters for testing (fast but insecure).
#[cfg(test)]
pub fn derive_pdk_test(
    passphrase: &[u8],
    salt: &[u8],
    keyfile: Option<&[u8]>,
    hwkey_response: Option<&[u8; 32]>,
) -> Result<SensitiveBytes32> {
    let base_pdk = derive_key_test(passphrase, salt)?;
    if keyfile.is_none() && hwkey_response.is_none() {
        return Ok(base_pdk);
    }
    let mut ikm = Vec::new();
    ikm.extend_from_slice(base_pdk.as_bytes());
    if let Some(kf) = keyfile {
        ikm.extend_from_slice(kf);
    }
    if let Some(hw) = hwkey_response {
        ikm.extend_from_slice(hw);
    }
    let combined = crate::crypto::hash::derive_key("zk-vault-pdk-combined-v1", &ikm);
    use zeroize::Zeroize;
    ikm.zeroize();
    Ok(SensitiveBytes32::new(combined))
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

    #[test]
    fn test_derive_pdk_no_extras_same_as_base() {
        let salt = [0x42u8; 32];
        let base = derive_key_test(b"my passphrase", &salt).unwrap();
        let pdk = derive_pdk_test(b"my passphrase", &salt, None, None).unwrap();
        assert_eq!(base.as_bytes(), pdk.as_bytes());
    }

    #[test]
    fn test_derive_pdk_with_keyfile_differs() {
        let salt = [0x42u8; 32];
        let base = derive_pdk_test(b"my passphrase", &salt, None, None).unwrap();
        let keyfile = vec![0xABu8; 64];
        let with_kf = derive_pdk_test(b"my passphrase", &salt, Some(&keyfile), None).unwrap();
        assert_ne!(base.as_bytes(), with_kf.as_bytes());
    }

    #[test]
    fn test_derive_pdk_with_hwkey_differs() {
        let salt = [0x42u8; 32];
        let base = derive_pdk_test(b"my passphrase", &salt, None, None).unwrap();
        let hwkey = [0xCDu8; 32];
        let with_hw = derive_pdk_test(b"my passphrase", &salt, None, Some(&hwkey)).unwrap();
        assert_ne!(base.as_bytes(), with_hw.as_bytes());
    }

    #[test]
    fn test_derive_pdk_wrong_keyfile_differs() {
        let salt = [0x42u8; 32];
        let kf1 = vec![0xAAu8; 64];
        let kf2 = vec![0xBBu8; 64];
        let pdk1 = derive_pdk_test(b"my passphrase", &salt, Some(&kf1), None).unwrap();
        let pdk2 = derive_pdk_test(b"my passphrase", &salt, Some(&kf2), None).unwrap();
        assert_ne!(pdk1.as_bytes(), pdk2.as_bytes());
    }

    #[test]
    fn test_generate_keyfile_unique() {
        let kf1 = generate_keyfile();
        let kf2 = generate_keyfile();
        assert_ne!(kf1, kf2);
        assert_eq!(kf1.len(), 64);
        assert_eq!(kf2.len(), 64);
    }
}

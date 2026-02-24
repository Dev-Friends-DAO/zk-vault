/// Hybrid post-quantum key encapsulation: ML-KEM-768 + X25519.
///
/// This module implements a hybrid KEM that combines:
/// - ML-KEM-768 (CRYSTALS-Kyber, NIST FIPS 203) for post-quantum resistance
/// - X25519 Diffie-Hellman for classical security
///
/// Both shared secrets are combined via BLAKE3 keyed hash with domain separation.
/// If either algorithm is broken, the other still protects the data.
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as PqPublicKey, SecretKey as PqSecretKey, SharedSecret as _,
};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::aead;
use crate::crypto::hash;
use crate::crypto::sensitive::SensitiveBytes32;
use crate::error::{Result, VaultError};

/// Domain separator for KEM key combining.
const KEM_DOMAIN_SEPARATOR: &[u8; 32] = b"zk-vault-hybrid-kem-v1-combine!!";

/// Domain separator for key wrapping AAD.
const KEY_WRAP_AAD: &[u8] = b"zk-vault-keywrap-v1";

/// Fixed zero nonce for key wrapping (safe because each wrapping key is unique).
const KEY_WRAP_NONCE: [u8; 24] = [0u8; 24];

/// Key pair for ML-KEM-768.
pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl KemKeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = kyber768::keypair();
        Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        }
    }

    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }
}

impl Drop for KemKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Key pair for X25519.
pub struct X25519KeyPair {
    pub public_key: X25519PublicKey,
    secret_key: StaticSecret,
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self {
            public_key: public,
            secret_key: secret,
        }
    }

    pub fn secret_key(&self) -> &StaticSecret {
        &self.secret_key
    }
}

/// Combined public keys for the hybrid KEM.
pub struct HybridPublicKey {
    pub kem_pk: Vec<u8>,
    pub x25519_pk: [u8; 32],
}

/// Result of hybrid encapsulation.
pub struct EncapsulationResult {
    /// ML-KEM-768 ciphertext (1088 bytes)
    pub kem_ciphertext: Vec<u8>,
    /// Ephemeral X25519 public key (32 bytes)
    pub eph_x25519_pk: [u8; 32],
    /// The wrapped symmetric key (32 + 16 = 48 bytes)
    pub wrapped_key: Vec<u8>,
}

/// Combine two shared secrets with domain separation using BLAKE3.
fn combine_shared_secrets(ss_kem: &[u8], ss_x25519: &[u8]) -> SensitiveBytes32 {
    let mut combined = Vec::with_capacity(ss_kem.len() + ss_x25519.len());
    combined.extend_from_slice(ss_kem);
    combined.extend_from_slice(ss_x25519);

    let result = hash::keyed_hash(KEM_DOMAIN_SEPARATOR, &combined);
    combined.zeroize();

    SensitiveBytes32::new(result)
}

/// Encapsulate: generate a wrapped symmetric key using hybrid KEM.
///
/// 1. Generate random sym_key
/// 2. ML-KEM-768 encapsulate → (kem_ct, ss_kem)
/// 3. X25519 DH → (eph_pk, ss_x25519)
/// 4. wrapping_key = BLAKE3(ss_kem || ss_x25519, domain_separator)
/// 5. wrapped_key = encrypt(wrapping_key, sym_key)
pub fn encapsulate(
    hybrid_pk: &HybridPublicKey,
    sym_key: &SensitiveBytes32,
) -> Result<EncapsulationResult> {
    // ML-KEM-768 encapsulation
    let kem_pk = kyber768::PublicKey::from_bytes(&hybrid_pk.kem_pk)
        .map_err(|e| VaultError::Encryption(format!("Invalid ML-KEM-768 public key: {e:?}")))?;
    let (ss_kem, kem_ct) = kyber768::encapsulate(&kem_pk);

    // X25519 ephemeral DH
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_public = X25519PublicKey::from(&eph_secret);
    let recipient_pk = X25519PublicKey::from(hybrid_pk.x25519_pk);
    let ss_x25519 = eph_secret.diffie_hellman(&recipient_pk);

    // Combine shared secrets
    let wrapping_key = combine_shared_secrets(ss_kem.as_bytes(), ss_x25519.as_bytes());

    // Wrap the symmetric key
    let wrapped_key = aead::encrypt_with_nonce(
        &wrapping_key,
        &KEY_WRAP_NONCE,
        sym_key.as_bytes(),
        KEY_WRAP_AAD,
    )?;

    // Zeroize wrapping key
    drop(wrapping_key);

    Ok(EncapsulationResult {
        kem_ciphertext: kem_ct.as_bytes().to_vec(),
        eph_x25519_pk: eph_public.to_bytes(),
        wrapped_key,
    })
}

/// Decapsulate: recover the symmetric key using private keys.
pub fn decapsulate(
    kem_sk: &[u8],
    x25519_sk: &StaticSecret,
    kem_ciphertext: &[u8],
    eph_x25519_pk: &[u8; 32],
    wrapped_key: &[u8],
) -> Result<SensitiveBytes32> {
    // ML-KEM-768 decapsulation
    let sk = kyber768::SecretKey::from_bytes(kem_sk)
        .map_err(|e| VaultError::Decryption(format!("Invalid ML-KEM-768 secret key: {e:?}")))?;
    let ct = kyber768::Ciphertext::from_bytes(kem_ciphertext)
        .map_err(|e| VaultError::Decryption(format!("Invalid ML-KEM-768 ciphertext: {e:?}")))?;
    let ss_kem = kyber768::decapsulate(&ct, &sk);

    // X25519 DH
    let eph_pk = X25519PublicKey::from(*eph_x25519_pk);
    let ss_x25519 = x25519_sk.diffie_hellman(&eph_pk);

    // Reconstruct wrapping key
    let wrapping_key = combine_shared_secrets(ss_kem.as_bytes(), ss_x25519.as_bytes());

    // Unwrap the symmetric key
    let sym_key_bytes = aead::decrypt(&wrapping_key, &KEY_WRAP_NONCE, wrapped_key, KEY_WRAP_AAD)?;

    SensitiveBytes32::from_slice(&sym_key_bytes)
        .ok_or_else(|| VaultError::Decryption("Unwrapped key is not 32 bytes".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        // Generate key pairs
        let kem_kp = KemKeyPair::generate();
        let x25519_kp = X25519KeyPair::generate();

        let hybrid_pk = HybridPublicKey {
            kem_pk: kem_kp.public_key.clone(),
            x25519_pk: x25519_kp.public_key.to_bytes(),
        };

        // Generate a random symmetric key to wrap
        let sym_key = aead::generate_key();

        // Encapsulate
        let encap = encapsulate(&hybrid_pk, &sym_key).unwrap();

        // Decapsulate
        let recovered = decapsulate(
            kem_kp.secret_key_bytes(),
            x25519_kp.secret_key(),
            &encap.kem_ciphertext,
            &encap.eph_x25519_pk,
            &encap.wrapped_key,
        )
        .unwrap();

        assert_eq!(sym_key.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_wrong_kem_key_fails() {
        let kem_kp1 = KemKeyPair::generate();
        let kem_kp2 = KemKeyPair::generate();
        let x25519_kp = X25519KeyPair::generate();

        let hybrid_pk = HybridPublicKey {
            kem_pk: kem_kp1.public_key.clone(),
            x25519_pk: x25519_kp.public_key.to_bytes(),
        };

        let sym_key = aead::generate_key();
        let encap = encapsulate(&hybrid_pk, &sym_key).unwrap();

        // Try decapsulating with wrong KEM key
        let result = decapsulate(
            kem_kp2.secret_key_bytes(),
            x25519_kp.secret_key(),
            &encap.kem_ciphertext,
            &encap.eph_x25519_pk,
            &encap.wrapped_key,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_x25519_key_fails() {
        let kem_kp = KemKeyPair::generate();
        let x25519_kp1 = X25519KeyPair::generate();
        let x25519_kp2 = X25519KeyPair::generate();

        let hybrid_pk = HybridPublicKey {
            kem_pk: kem_kp.public_key.clone(),
            x25519_pk: x25519_kp1.public_key.to_bytes(),
        };

        let sym_key = aead::generate_key();
        let encap = encapsulate(&hybrid_pk, &sym_key).unwrap();

        // Try decapsulating with wrong X25519 key
        let result = decapsulate(
            kem_kp.secret_key_bytes(),
            x25519_kp2.secret_key(),
            &encap.kem_ciphertext,
            &encap.eph_x25519_pk,
            &encap.wrapped_key,
        );
        assert!(result.is_err());
    }
}

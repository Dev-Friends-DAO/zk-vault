//! Guardian share management: PQ-encrypt Shamir shares for individual guardians.
//!
//! Each guardian receives one Shamir share, encrypted using the hybrid
//! post-quantum KEM (ML-KEM-768 + X25519). The guardian can only decrypt
//! their share using their private keys.

use serde::{Deserialize, Serialize};

use crate::crypto::aead;
use crate::crypto::kem::{self, HybridPublicKey};
use crate::crypto::shamir::Share;
use crate::error::{Result, VaultError};

/// A share encrypted for a specific guardian.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedGuardianShare {
    /// Guardian identifier (human-readable label).
    pub guardian_id: String,
    /// Guardian's ML-KEM-768 public key (hex).
    pub guardian_kem_pk: String,
    /// Guardian's X25519 public key (hex).
    pub guardian_x25519_pk: String,
    /// ML-KEM ciphertext (hex).
    pub kem_ciphertext: String,
    /// Ephemeral X25519 public key (hex).
    pub eph_x25519_pk: String,
    /// The symmetric key wrapped by the hybrid KEM wrapping key (hex).
    pub wrapped_key: String,
    /// Share data encrypted with the symmetric key: nonce(24) || ciphertext (hex).
    pub encrypted_share: String,
    /// Share index.
    pub share_index: u8,
}

/// Domain separator for guardian share AEAD encryption.
const GUARDIAN_SHARE_AAD: &[u8] = b"zk-vault:guardian-share";

/// Encrypt a Shamir share for a guardian using their hybrid public key.
///
/// 1. Generate a random symmetric key.
/// 2. AEAD-encrypt the share data with the symmetric key.
/// 3. Hybrid KEM encapsulate the symmetric key using the guardian's public keys.
pub fn encrypt_share_for_guardian(
    guardian_id: &str,
    share: &Share,
    guardian_kem_pk: &[u8],
    guardian_x25519_pk: &[u8; 32],
) -> Result<EncryptedGuardianShare> {
    let hybrid_pk = HybridPublicKey {
        kem_pk: guardian_kem_pk.to_vec(),
        x25519_pk: *guardian_x25519_pk,
    };

    // Step 1: Generate a random symmetric key for encrypting the share data.
    let sym_key = aead::generate_key();

    // Step 2: AEAD-encrypt the share data with the symmetric key.
    let (nonce, ciphertext) = aead::encrypt(&sym_key, &share.data, GUARDIAN_SHARE_AAD)?;

    // Combine nonce + ciphertext into a single blob.
    let mut encrypted_share_blob = Vec::with_capacity(nonce.len() + ciphertext.len());
    encrypted_share_blob.extend_from_slice(&nonce);
    encrypted_share_blob.extend_from_slice(&ciphertext);

    // Step 3: Hybrid KEM encapsulate the symmetric key.
    let encap = kem::encapsulate(&hybrid_pk, &sym_key)?;

    Ok(EncryptedGuardianShare {
        guardian_id: guardian_id.to_string(),
        guardian_kem_pk: hex::encode(guardian_kem_pk),
        guardian_x25519_pk: hex::encode(guardian_x25519_pk),
        kem_ciphertext: hex::encode(&encap.kem_ciphertext),
        eph_x25519_pk: hex::encode(encap.eph_x25519_pk),
        wrapped_key: hex::encode(&encap.wrapped_key),
        encrypted_share: hex::encode(&encrypted_share_blob),
        share_index: share.index,
    })
}

/// Decrypt a guardian share using the guardian's private keys.
///
/// 1. Hybrid KEM decapsulate to recover the symmetric key.
/// 2. AEAD-decrypt the share data with the recovered symmetric key.
pub fn decrypt_guardian_share(
    encrypted: &EncryptedGuardianShare,
    kem_sk: &[u8],
    x25519_sk: &kem::StaticSecret,
) -> Result<Share> {
    // Decode hex fields.
    let kem_ct = hex::decode(&encrypted.kem_ciphertext)
        .map_err(|e| VaultError::Decryption(format!("Invalid kem_ciphertext hex: {e}")))?;
    let eph_pk_bytes = hex::decode(&encrypted.eph_x25519_pk)
        .map_err(|e| VaultError::Decryption(format!("Invalid eph_x25519_pk hex: {e}")))?;
    let eph_pk: [u8; 32] = eph_pk_bytes
        .try_into()
        .map_err(|_| VaultError::Decryption("Invalid ephemeral PK length".into()))?;
    let wrapped_key = hex::decode(&encrypted.wrapped_key)
        .map_err(|e| VaultError::Decryption(format!("Invalid wrapped_key hex: {e}")))?;
    let encrypted_share_blob = hex::decode(&encrypted.encrypted_share)
        .map_err(|e| VaultError::Decryption(format!("Invalid encrypted_share hex: {e}")))?;

    // Step 1: Hybrid KEM decapsulate to recover the symmetric key.
    let sym_key = kem::decapsulate(kem_sk, x25519_sk, &kem_ct, &eph_pk, &wrapped_key)?;

    // Step 2: Split encrypted_share_blob into nonce(24) + ciphertext.
    if encrypted_share_blob.len() < aead::NONCE_LEN {
        return Err(VaultError::Decryption(
            "Encrypted share blob too short".into(),
        ));
    }
    let nonce: [u8; aead::NONCE_LEN] = encrypted_share_blob[..aead::NONCE_LEN].try_into().unwrap();
    let ciphertext = &encrypted_share_blob[aead::NONCE_LEN..];

    // Step 3: AEAD-decrypt the share data.
    let share_data = aead::decrypt(&sym_key, &nonce, ciphertext, GUARDIAN_SHARE_AAD)?;

    Ok(Share {
        index: encrypted.share_index,
        data: share_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::{KemKeyPair, X25519KeyPair};
    use crate::crypto::shamir;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        // Generate guardian key pairs.
        let kem_kp = KemKeyPair::generate();
        let x25519_kp = X25519KeyPair::generate();

        // Create a secret and split it.
        let secret = aead::generate_key();
        let shares = shamir::split(&secret, 2, 3).unwrap();
        let original_share = &shares[0];

        // Encrypt the share for the guardian.
        let encrypted = encrypt_share_for_guardian(
            "guardian-alice",
            original_share,
            &kem_kp.public_key,
            &x25519_kp.public_key.to_bytes(),
        )
        .unwrap();

        assert_eq!(encrypted.guardian_id, "guardian-alice");
        assert_eq!(encrypted.share_index, original_share.index);

        // Decrypt the share.
        let decrypted = decrypt_guardian_share(
            &encrypted,
            kem_kp.secret_key_bytes(),
            x25519_kp.secret_key(),
        )
        .unwrap();

        assert_eq!(decrypted.index, original_share.index);
        assert_eq!(decrypted.data, original_share.data);
    }

    #[test]
    fn wrong_kem_key_fails() {
        let kem_kp1 = KemKeyPair::generate();
        let kem_kp2 = KemKeyPair::generate();
        let x25519_kp = X25519KeyPair::generate();

        let secret = aead::generate_key();
        let shares = shamir::split(&secret, 2, 3).unwrap();

        let encrypted = encrypt_share_for_guardian(
            "guardian-bob",
            &shares[0],
            &kem_kp1.public_key,
            &x25519_kp.public_key.to_bytes(),
        )
        .unwrap();

        // Decrypt with wrong KEM key should fail.
        let result = decrypt_guardian_share(
            &encrypted,
            kem_kp2.secret_key_bytes(),
            x25519_kp.secret_key(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_x25519_key_fails() {
        let kem_kp = KemKeyPair::generate();
        let x25519_kp1 = X25519KeyPair::generate();
        let x25519_kp2 = X25519KeyPair::generate();

        let secret = aead::generate_key();
        let shares = shamir::split(&secret, 2, 3).unwrap();

        let encrypted = encrypt_share_for_guardian(
            "guardian-carol",
            &shares[0],
            &kem_kp.public_key,
            &x25519_kp1.public_key.to_bytes(),
        )
        .unwrap();

        // Decrypt with wrong X25519 key should fail.
        let result = decrypt_guardian_share(
            &encrypted,
            kem_kp.secret_key_bytes(),
            x25519_kp2.secret_key(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn full_guardian_recovery_flow() {
        // Simulate a full flow: split secret, encrypt shares for guardians, decrypt, reconstruct.
        let secret = aead::generate_key();
        let threshold = 2u8;
        let shares = shamir::split(&secret, threshold, 3).unwrap();

        // Each guardian has their own key pair.
        let guardians: Vec<(String, KemKeyPair, X25519KeyPair)> = (0..3)
            .map(|i| {
                (
                    format!("guardian-{i}"),
                    KemKeyPair::generate(),
                    X25519KeyPair::generate(),
                )
            })
            .collect();

        // Encrypt each share for its respective guardian.
        let encrypted_shares: Vec<EncryptedGuardianShare> = shares
            .iter()
            .zip(guardians.iter())
            .map(|(share, (id, kem_kp, x25519_kp))| {
                encrypt_share_for_guardian(
                    id,
                    share,
                    &kem_kp.public_key,
                    &x25519_kp.public_key.to_bytes(),
                )
                .unwrap()
            })
            .collect();

        // Any 2 guardians decrypt their shares.
        let decrypted_shares: Vec<Share> = encrypted_shares[0..2]
            .iter()
            .zip(guardians[0..2].iter())
            .map(|(enc, (_, kem_kp, x25519_kp))| {
                decrypt_guardian_share(enc, kem_kp.secret_key_bytes(), x25519_kp.secret_key())
                    .unwrap()
            })
            .collect();

        // Reconstruct the secret.
        let recovered = shamir::reconstruct(&decrypted_shares, threshold).unwrap();
        assert_eq!(secret.as_bytes(), recovered.as_bytes());
    }
}

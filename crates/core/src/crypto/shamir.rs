//! Shamir Secret Sharing for Master Key recovery.
//!
//! Splits a 256-bit Master Key into N shares with a K-of-N threshold.
//! Any K shares can reconstruct the secret; fewer than K reveals nothing
//! (information-theoretic security over GF(256)).

use serde::{Deserialize, Serialize};

use crate::crypto::sensitive::SensitiveBytes32;
use crate::error::{Result, VaultError};

/// A single Shamir share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Share index (1-based).
    pub index: u8,
    /// Share data (same length as original secret + 1 byte for the x-coordinate).
    pub data: Vec<u8>,
}

/// Split a 256-bit secret into `total` shares with threshold `threshold`.
/// Any `threshold` shares can reconstruct; fewer than `threshold` reveal nothing.
pub fn split(secret: &SensitiveBytes32, threshold: u8, total: u8) -> Result<Vec<Share>> {
    if threshold < 2 {
        return Err(VaultError::Encryption("Threshold must be >= 2".into()));
    }
    if total < threshold {
        return Err(VaultError::Encryption(
            "Total shares must be >= threshold".into(),
        ));
    }

    let dealer = sharks::Sharks(threshold);
    let secret_bytes = secret.as_bytes();

    let shares: Vec<sharks::Share> = dealer.dealer(secret_bytes).take(total as usize).collect();

    let result: Vec<Share> = shares
        .into_iter()
        .enumerate()
        .map(|(i, s)| {
            let bytes: Vec<u8> = Vec::from(&s);
            Share {
                index: (i + 1) as u8,
                data: bytes,
            }
        })
        .collect();

    Ok(result)
}

/// Reconstruct the secret from `threshold` or more shares.
pub fn reconstruct(shares: &[Share], threshold: u8) -> Result<SensitiveBytes32> {
    if shares.len() < 2 {
        return Err(VaultError::Decryption(
            "Need at least 2 shares to reconstruct".into(),
        ));
    }
    if (shares.len() as u8) < threshold {
        return Err(VaultError::Decryption(format!(
            "Need at least {threshold} shares to reconstruct, got {}",
            shares.len()
        )));
    }

    let shark_shares: Vec<sharks::Share> = shares
        .iter()
        .map(|s| {
            sharks::Share::try_from(s.data.as_slice())
                .map_err(|e| VaultError::Decryption(format!("Invalid share data: {e}")))
        })
        .collect::<Result<Vec<_>>>()?;

    let secret = sharks::Sharks(threshold)
        .recover(&shark_shares)
        .map_err(|e| VaultError::Decryption(format!("Failed to reconstruct secret: {e}")))?;

    SensitiveBytes32::from_slice(&secret)
        .ok_or_else(|| VaultError::Decryption("Reconstructed secret is not 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead;

    #[test]
    fn split_and_reconstruct_3_of_5() {
        let secret = aead::generate_key();
        let shares = split(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Any 3 should work
        let recovered = reconstruct(&shares[0..3], 3).unwrap();
        assert_eq!(secret.as_bytes(), recovered.as_bytes());

        let recovered2 = reconstruct(&shares[2..5], 3).unwrap();
        assert_eq!(secret.as_bytes(), recovered2.as_bytes());
    }

    #[test]
    fn fewer_than_threshold_fails_or_wrong() {
        let secret = aead::generate_key();
        let shares = split(&secret, 3, 5).unwrap();

        // 2 shares with threshold 3 should fail validation
        let result = reconstruct(&shares[0..2], 3);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_too_low_fails() {
        let secret = aead::generate_key();
        assert!(split(&secret, 1, 5).is_err());
    }

    #[test]
    fn total_less_than_threshold_fails() {
        let secret = aead::generate_key();
        assert!(split(&secret, 5, 3).is_err());
    }

    #[test]
    fn all_shares_reconstruct() {
        let secret = aead::generate_key();
        let shares = split(&secret, 3, 5).unwrap();
        let recovered = reconstruct(&shares, 3).unwrap();
        assert_eq!(secret.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn reconstruct_2_of_3() {
        let secret = aead::generate_key();
        let shares = split(&secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        let recovered = reconstruct(&shares[0..2], 2).unwrap();
        assert_eq!(secret.as_bytes(), recovered.as_bytes());

        let recovered2 = reconstruct(&shares[1..3], 2).unwrap();
        assert_eq!(secret.as_bytes(), recovered2.as_bytes());
    }
}

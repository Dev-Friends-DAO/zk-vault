/// Hybrid post-quantum digital signatures: ML-DSA-65 + Ed25519.
///
/// Both signatures must verify for the combined signature to be valid.
/// If either algorithm is broken, the other still protects integrity.
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::error::{Result, VaultError};

/// ML-DSA-65 (Dilithium3) signing key pair.
pub struct MlDsaKeyPair {
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl MlDsaKeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = dilithium3::keypair();
        Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        }
    }

    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }
}

impl Drop for MlDsaKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Ed25519 signing key pair.
pub struct Ed25519KeyPair {
    pub verifying_key: VerifyingKey,
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            verifying_key,
            signing_key,
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// Combined hybrid signature (ML-DSA-65 + Ed25519).
pub struct HybridSignature {
    pub mldsa_signature: Vec<u8>,
    pub ed25519_signature: [u8; 64],
}

impl HybridSignature {
    /// Serialize to bytes: [mldsa_sig_len(4) | mldsa_sig | ed25519_sig(64)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mldsa_len = self.mldsa_signature.len() as u32;
        let mut out = Vec::with_capacity(4 + self.mldsa_signature.len() + 64);
        out.extend_from_slice(&mldsa_len.to_le_bytes());
        out.extend_from_slice(&self.mldsa_signature);
        out.extend_from_slice(&self.ed25519_signature);
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 + 64 {
            return Err(VaultError::Decryption("Hybrid signature too short".into()));
        }
        let mldsa_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
        if data.len() != 4 + mldsa_len + 64 {
            return Err(VaultError::Decryption("Invalid hybrid signature length".into()));
        }
        let mldsa_signature = data[4..4 + mldsa_len].to_vec();
        let mut ed25519_signature = [0u8; 64];
        ed25519_signature.copy_from_slice(&data[4 + mldsa_len..]);
        Ok(Self {
            mldsa_signature,
            ed25519_signature,
        })
    }
}

/// Combined public keys for signature verification.
pub struct HybridVerifyingKey {
    pub mldsa_pk: Vec<u8>,
    pub ed25519_pk: VerifyingKey,
}

/// Sign a message with both ML-DSA-65 and Ed25519.
pub fn sign(
    mldsa_sk: &[u8],
    ed25519_sk: &SigningKey,
    message: &[u8],
) -> Result<HybridSignature> {
    // ML-DSA-65 signature
    let sk = dilithium3::SecretKey::from_bytes(mldsa_sk)
        .map_err(|e| VaultError::Encryption(format!("Invalid ML-DSA-65 secret key: {e:?}")))?;
    let mldsa_sig = dilithium3::detached_sign(message, &sk);

    // Ed25519 signature
    let ed_sig = ed25519_sk.sign(message);

    Ok(HybridSignature {
        mldsa_signature: mldsa_sig.as_bytes().to_vec(),
        ed25519_signature: ed_sig.to_bytes(),
    })
}

/// Verify a hybrid signature. Both signatures must be valid.
pub fn verify(
    vk: &HybridVerifyingKey,
    message: &[u8],
    signature: &HybridSignature,
) -> Result<()> {
    // Verify ML-DSA-65
    let mldsa_pk = dilithium3::PublicKey::from_bytes(&vk.mldsa_pk)
        .map_err(|_| VaultError::SignatureVerification)?;
    let mldsa_sig = dilithium3::DetachedSignature::from_bytes(&signature.mldsa_signature)
        .map_err(|_| VaultError::SignatureVerification)?;
    dilithium3::verify_detached_signature(&mldsa_sig, message, &mldsa_pk)
        .map_err(|_| VaultError::SignatureVerification)?;

    // Verify Ed25519
    let ed_sig = ed25519_dalek::Signature::from_bytes(&signature.ed25519_signature);
    vk.ed25519_pk
        .verify(message, &ed_sig)
        .map_err(|_| VaultError::SignatureVerification)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let mldsa_kp = MlDsaKeyPair::generate();
        let ed25519_kp = Ed25519KeyPair::generate();

        let message = b"zk-vault merkle root hash here!";

        let sig = sign(
            mldsa_kp.secret_key_bytes(),
            ed25519_kp.signing_key(),
            message,
        )
        .unwrap();

        let vk = HybridVerifyingKey {
            mldsa_pk: mldsa_kp.public_key.clone(),
            ed25519_pk: ed25519_kp.verifying_key,
        };

        assert!(verify(&vk, message, &sig).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let mldsa_kp = MlDsaKeyPair::generate();
        let ed25519_kp = Ed25519KeyPair::generate();

        let sig = sign(
            mldsa_kp.secret_key_bytes(),
            ed25519_kp.signing_key(),
            b"original",
        )
        .unwrap();

        let vk = HybridVerifyingKey {
            mldsa_pk: mldsa_kp.public_key.clone(),
            ed25519_pk: ed25519_kp.verifying_key,
        };

        assert!(verify(&vk, b"tampered", &sig).is_err());
    }

    #[test]
    fn test_signature_serialization() {
        let mldsa_kp = MlDsaKeyPair::generate();
        let ed25519_kp = Ed25519KeyPair::generate();

        let sig = sign(
            mldsa_kp.secret_key_bytes(),
            ed25519_kp.signing_key(),
            b"test",
        )
        .unwrap();

        let bytes = sig.to_bytes();
        let recovered = HybridSignature::from_bytes(&bytes).unwrap();

        assert_eq!(sig.mldsa_signature, recovered.mldsa_signature);
        assert_eq!(sig.ed25519_signature, recovered.ed25519_signature);
    }
}

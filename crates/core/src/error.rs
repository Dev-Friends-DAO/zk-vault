use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Invalid passphrase")]
    InvalidPassphrase,

    #[error("Merkle proof verification failed for file: {0}")]
    MerkleVerification(String),

    #[error("Signature verification failed")]
    SignatureVerification,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Blockchain anchoring for tamper-proof integrity verification.
///
/// The anchor module provides a pluggable trait for writing 32-byte
/// hashes (Super Merkle Roots) to blockchains. Each chain provides
/// independent, immutable proof that a particular state existed at
/// a given time.
///
/// Supported chains:
/// - Bitcoin: OP_RETURN output (primary anchor, highest trust)
/// - Ethereum: calldata in a transaction (secondary anchor, extensible)
///
/// Chains are independent (multi-chain, NOT cross-chain). The same hash
/// is written to each chain separately. No bridges needed.
pub mod batch;
pub mod bitcoin;
pub mod ethereum;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Receipt returned after a successful blockchain anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorReceipt {
    /// Which blockchain (e.g., "bitcoin", "ethereum").
    pub chain: String,
    /// Transaction hash/ID on the blockchain.
    pub tx_id: String,
    /// The 32-byte hash that was anchored.
    pub anchored_hash: [u8; 32],
    /// Block number (None if unconfirmed).
    pub block_number: Option<u64>,
    /// Estimated fee paid (in the chain's native unit, as string).
    pub fee: Option<String>,
}

/// Trait for pluggable blockchain anchors.
///
/// Each implementation handles the specifics of writing a 32-byte hash
/// to its respective blockchain.
#[async_trait]
pub trait BlockchainAnchor: Send + Sync {
    /// Name of the blockchain (e.g., "Bitcoin", "Ethereum").
    fn chain_name(&self) -> &str;

    /// Anchor a 32-byte hash to the blockchain.
    /// Returns a receipt with the transaction ID.
    async fn anchor(&self, hash: &[u8; 32]) -> Result<AnchorReceipt>;

    /// Verify that a previously anchored hash exists on-chain.
    /// Checks the transaction referenced in the receipt.
    async fn verify(&self, receipt: &AnchorReceipt) -> Result<bool>;
}

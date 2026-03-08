/// Batch anchoring orchestrator.
///
/// Takes a Super Merkle Root and anchors it to multiple blockchains
/// independently. Each chain gets the same 32-byte hash.
///
/// ```text
/// Super Merkle Root ──┬──▶ Bitcoin OP_RETURN
///                     └──▶ Ethereum calldata
/// ```
///
/// This is NOT cross-chain. Each anchor is independent.
/// If one chain fails, the others still provide integrity proof.
use tracing::{error, info};

use super::{AnchorReceipt, BlockchainAnchor};

/// Result of a batch anchoring operation.
#[derive(Debug)]
pub struct BatchAnchorResult {
    /// The hash that was anchored.
    pub anchored_hash: [u8; 32],
    /// Successful anchor receipts.
    pub receipts: Vec<AnchorReceipt>,
    /// Chains that failed with error messages.
    pub failures: Vec<(String, String)>,
}

/// Anchor a hash to multiple blockchains.
///
/// Attempts all chains. Partial success is acceptable — even one
/// successful anchor provides integrity proof. Failures are logged
/// and returned for retry.
pub async fn anchor_to_all(
    hash: &[u8; 32],
    anchors: &[&dyn BlockchainAnchor],
) -> BatchAnchorResult {
    let mut receipts = Vec::new();
    let mut failures = Vec::new();

    for anchor in anchors {
        let chain = anchor.chain_name().to_string();
        info!(chain = %chain, "Anchoring to blockchain");

        match anchor.anchor(hash).await {
            Ok(receipt) => {
                info!(
                    chain = %chain,
                    tx_id = %receipt.tx_id,
                    "Anchor successful"
                );
                receipts.push(receipt);
            }
            Err(e) => {
                error!(
                    chain = %chain,
                    error = %e,
                    "Anchor failed"
                );
                failures.push((chain, e.to_string()));
            }
        }
    }

    BatchAnchorResult {
        anchored_hash: *hash,
        receipts,
        failures,
    }
}

/// Verify all anchor receipts.
///
/// Returns a list of (chain_name, is_verified) pairs.
pub async fn verify_all(
    receipts: &[AnchorReceipt],
    anchors: &[&dyn BlockchainAnchor],
) -> Vec<(String, bool)> {
    let mut results = Vec::new();

    for receipt in receipts {
        // Find the matching anchor by chain name
        let anchor = anchors
            .iter()
            .find(|a| a.chain_name().to_lowercase() == receipt.chain);

        match anchor {
            Some(a) => match a.verify(receipt).await {
                Ok(verified) => {
                    results.push((receipt.chain.clone(), verified));
                }
                Err(e) => {
                    error!(
                        chain = %receipt.chain,
                        error = %e,
                        "Verification failed"
                    );
                    results.push((receipt.chain.clone(), false));
                }
            },
            None => {
                results.push((receipt.chain.clone(), false));
            }
        }
    }

    results
}

//! Transaction mempool: buffers pending transactions before block inclusion.
//!
//! The mempool receives transactions from RPC clients, validates them against
//! the current chain state, deduplicates by tx hash, and provides ordered
//! batches to the block builder when consensus requests a new proposal.

use std::collections::BTreeMap;

use tracing::debug;

use crate::state::ChainState;
use crate::types::{Block, BlockHeader, Height, Transaction};

// ── Errors ──

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("Transaction already in mempool: {0}")]
    Duplicate(String),

    #[error("Mempool is full ({max} transactions)")]
    Full { max: usize },

    #[error("Pre-validation failed: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, MempoolError>;

// ── Mempool ──

/// Configuration for the mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of pending transactions.
    pub max_txs: usize,
    /// Maximum number of transactions per block.
    pub max_txs_per_block: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_txs: 4096,
            max_txs_per_block: 256,
        }
    }
}

/// A transaction mempool that buffers validated, pending transactions.
///
/// Transactions are keyed by their BLAKE3 hash for O(log n) deduplication.
/// Ordering is deterministic (BTreeMap over tx hash) so all validators
/// produce identical block proposals from the same mempool state.
#[derive(Debug)]
pub struct Mempool {
    /// Pending transactions: tx_hash → Transaction.
    pending: BTreeMap<[u8; 32], Transaction>,
    /// Configuration.
    config: MempoolConfig,
}

impl Mempool {
    /// Create a new empty mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            pending: BTreeMap::new(),
            config,
        }
    }

    /// Number of pending transactions.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Submit a transaction to the mempool.
    ///
    /// The transaction is pre-validated against the current chain state
    /// (signature check, duplicate file check, etc.) before being accepted.
    pub fn submit(&mut self, tx: Transaction, state: &ChainState) -> Result<[u8; 32]> {
        // Check capacity
        if self.pending.len() >= self.config.max_txs {
            return Err(MempoolError::Full {
                max: self.config.max_txs,
            });
        }

        let tx_hash = tx.hash();

        // Check for duplicate in mempool
        if self.pending.contains_key(&tx_hash) {
            return Err(MempoolError::Duplicate(hex::encode(&tx_hash[..8])));
        }

        // Pre-validate against current state
        pre_validate(&tx, state)?;

        debug!(tx_hash = hex::encode(&tx_hash[..8]), "tx accepted");
        self.pending.insert(tx_hash, tx);
        Ok(tx_hash)
    }

    /// Reap transactions for a new block, up to `max_txs_per_block`.
    ///
    /// Returns transactions in deterministic order (sorted by tx hash).
    /// Does NOT remove them — call `purge` after the block is committed.
    pub fn reap(&self) -> Vec<Transaction> {
        self.pending
            .values()
            .take(self.config.max_txs_per_block)
            .cloned()
            .collect()
    }

    /// Remove committed transactions from the mempool.
    ///
    /// Called after a block is applied to the state. Removes all transactions
    /// that were included in the block.
    pub fn purge(&mut self, block: &Block) {
        let before = self.pending.len();
        for tx in &block.transactions {
            self.pending.remove(&tx.hash());
        }
        let removed = before - self.pending.len();
        if removed > 0 {
            debug!(
                removed,
                remaining = self.pending.len(),
                height = block.header.height.0,
                "purged committed txs"
            );
        }
    }

    /// Remove all transactions that are no longer valid against the new state.
    ///
    /// Called after a block is applied. Some pending txs may have become
    /// invalid (e.g., a RegisterFile for a merkle root that was just registered).
    pub fn revalidate(&mut self, state: &ChainState) {
        let before = self.pending.len();
        self.pending.retain(|_, tx| pre_validate(tx, state).is_ok());
        let evicted = before - self.pending.len();
        if evicted > 0 {
            debug!(evicted, "revalidated mempool, evicted stale txs");
        }
    }

    /// Check if a transaction is already in the mempool.
    pub fn contains(&self, tx_hash: &[u8; 32]) -> bool {
        self.pending.contains_key(tx_hash)
    }
}

// ── Pre-validation ──

/// Lightweight pre-validation of a transaction against the current state.
///
/// This catches obvious failures before buffering. Full validation still
/// happens in `ChainState::apply_tx` during block execution.
fn pre_validate(tx: &Transaction, state: &ChainState) -> Result<()> {
    match tx {
        Transaction::RegisterFile {
            merkle_root,
            owner_pk,
            signature,
            ..
        } => {
            // Reject if already registered on-chain
            if state.file_registry.contains_key(merkle_root) {
                return Err(MempoolError::Invalid(format!(
                    "merkle root {} already registered",
                    hex::encode(&merkle_root[..8])
                )));
            }
            // Verify signature
            verify_ed25519_quick(owner_pk, merkle_root, signature)?;
        }

        Transaction::VerifyIntegrity {
            merkle_root,
            verifier_pk,
            signature,
        } => {
            // File must exist on-chain
            if !state.file_registry.contains_key(merkle_root) {
                return Err(MempoolError::Invalid(format!(
                    "file {} not found",
                    hex::encode(&merkle_root[..8])
                )));
            }
            // Verify signature
            verify_ed25519_quick(verifier_pk, merkle_root, signature)?;
        }

        Transaction::UpdateValidatorSet { signature, .. } => {
            // Basic length check
            if signature.len() < 96 {
                return Err(MempoolError::Invalid(
                    "UpdateValidatorSet signature too short".to_string(),
                ));
            }
        }

        Transaction::RegisterGuardian {
            owner_pk,
            guardian_pk,
            threshold,
            total_guardians,
            signature,
            ..
        } => {
            if signature.is_empty() {
                return Err(MempoolError::Invalid("empty signature".to_string()));
            }
            // Verify signature over BLAKE3(domain || guardian_pk || threshold || total_guardians)
            let mut msg = Vec::new();
            msg.extend_from_slice(b"zk-vault:register-guardian:");
            msg.extend_from_slice(guardian_pk);
            msg.push(*threshold);
            msg.push(*total_guardians);
            let msg_hash = blake3::hash(&msg);
            verify_ed25519_quick(owner_pk, msg_hash.as_bytes(), signature)?;
        }

        Transaction::RequestRecovery {
            owner_pk,
            new_pk,
            signature,
        } => {
            if signature.is_empty() {
                return Err(MempoolError::Invalid("empty signature".to_string()));
            }
            // Verify signature with new_pk over owner_pk
            verify_ed25519_quick(new_pk, owner_pk, signature)?;
            // Check guardian set exists
            if !state.guardian_registry.contains_key(owner_pk) {
                return Err(MempoolError::Invalid(format!(
                    "no guardian set for {}",
                    hex::encode(&owner_pk[..8])
                )));
            }
        }

        Transaction::ApproveRecovery {
            owner_pk,
            guardian_pk,
            share_data,
            signature,
        } => {
            if signature.is_empty() {
                return Err(MempoolError::Invalid("empty signature".to_string()));
            }
            // Verify guardian signature over BLAKE3(domain || owner_pk || share_data)
            let mut msg = Vec::new();
            msg.extend_from_slice(b"zk-vault:approve-recovery:");
            msg.extend_from_slice(owner_pk);
            msg.extend_from_slice(share_data.as_bytes());
            let msg_hash = blake3::hash(&msg);
            verify_ed25519_quick(guardian_pk, msg_hash.as_bytes(), signature)?;
        }

        Transaction::RevokeKeys {
            owner_pk,
            new_ed25519_pk,
            signature,
        } => {
            if signature.is_empty() {
                return Err(MempoolError::Invalid("empty signature".to_string()));
            }
            // Verify signature with owner_pk over BLAKE3(domain || new_ed25519_pk)
            let mut msg = Vec::new();
            msg.extend_from_slice(b"zk-vault:revoke-keys:");
            msg.extend_from_slice(new_ed25519_pk);
            let msg_hash = blake3::hash(&msg);
            verify_ed25519_quick(owner_pk, msg_hash.as_bytes(), signature)?;
        }

        Transaction::UpdateStorageStatus {
            validator_pk,
            blob_key,
            holds_blob,
            signature,
        } => {
            if signature.is_empty() {
                return Err(MempoolError::Invalid("empty signature".to_string()));
            }
            // Verify signature over domain-separated message
            let mut msg = Vec::new();
            msg.extend_from_slice(b"zk-vault:storage-status:");
            msg.extend_from_slice(blob_key.as_bytes());
            msg.push(if *holds_blob { 1 } else { 0 });
            let msg_hash = blake3::hash(&msg);
            verify_ed25519_quick(validator_pk, msg_hash.as_bytes(), signature)?;
        }

        Transaction::AnchorMerkleRoot { signature, .. } => {
            if signature.len() != 64 {
                return Err(MempoolError::Invalid(
                    "AnchorMerkleRoot signature must be 64 bytes".into(),
                ));
            }
        }

        Transaction::RenewDeal { signature, .. } => {
            if signature.len() != 64 {
                return Err(MempoolError::Invalid(
                    "RenewDeal signature must be 64 bytes".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Quick Ed25519 signature check for mempool pre-validation.
fn verify_ed25519_quick(pk_bytes: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let vk = VerifyingKey::from_bytes(pk_bytes)
        .map_err(|e| MempoolError::Invalid(format!("bad public key: {e}")))?;

    let sig = Signature::from_slice(signature)
        .map_err(|e| MempoolError::Invalid(format!("bad signature: {e}")))?;

    vk.verify(message, &sig)
        .map_err(|e| MempoolError::Invalid(format!("signature verification failed: {e}")))
}

// ── Block Builder ──

/// Builds a block from mempool transactions and the current chain state.
pub struct BlockBuilder;

impl BlockBuilder {
    /// Build a new block proposal from the current mempool and state.
    ///
    /// The block is ready for consensus proposal. The state_root is computed
    /// by trial-applying transactions to a clone of the state.
    pub fn build(mempool: &Mempool, state: &ChainState) -> Block {
        let txs = mempool.reap();
        let height = Height(state.height.0 + 1);
        let proposer = state.validator_set.validators[0].address;

        // Trial-apply each tx individually to filter out invalid ones
        let mut trial_state = state.clone();
        let mut valid_txs = Vec::with_capacity(txs.len());
        for tx in txs {
            let mut attempt = trial_state.clone();
            if attempt.apply_tx(&tx, height).is_ok() {
                valid_txs.push(tx);
                trial_state = attempt;
            }
        }

        // Compute tx_root
        let tx_root = if valid_txs.is_empty() {
            [0u8; 32]
        } else {
            let mut combined = Vec::new();
            for tx in &valid_txs {
                combined.extend_from_slice(&tx.hash());
            }
            *blake3::hash(&combined).as_bytes()
        };

        let header = BlockHeader {
            height,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            prev_block_id: state.last_block_id,
            state_root: trial_state.state_root(),
            tx_root,
            proposer,
            tx_count: valid_txs.len() as u32,
        };

        Block {
            header,
            transactions: valid_txs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        let sk = SigningKey::from_bytes(&secret);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn test_validator_set() -> (ValidatorSet, Vec<(SigningKey, [u8; 32])>) {
        let keys: Vec<_> = (1..=3).map(make_keypair).collect();
        let validators: Vec<Validator> = keys
            .iter()
            .map(|(_, pk)| Validator::new(*pk, 100))
            .collect();
        (ValidatorSet::new(validators), keys)
    }

    fn make_register_tx(sk: &SigningKey, pk: &[u8; 32], merkle_root: [u8; 32]) -> Transaction {
        let sig = sk.sign(&merkle_root);
        Transaction::RegisterFile {
            merkle_root,
            file_count: 1,
            encrypted_size: 1024,
            owner_pk: *pk,
            signature: sig.to_bytes().to_vec(),
        }
    }

    fn make_block_and_apply(state: &mut ChainState, txs: Vec<Transaction>) {
        let header = BlockHeader {
            height: Height(state.height.0 + 1),
            timestamp: 1000,
            prev_block_id: state.last_block_id,
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            proposer: state.validator_set.validators[0].address,
            tx_count: txs.len() as u32,
        };
        let block = Block {
            header,
            transactions: txs,
        };
        state.apply_block(&block).unwrap();
    }

    #[test]
    fn submit_and_reap() {
        let (vs, keys) = test_validator_set();
        let state = ChainState::genesis(vs);
        let mut pool = Mempool::new(MempoolConfig::default());

        let (sk, pk) = &keys[0];
        let tx = make_register_tx(sk, pk, [0xAA; 32]);

        let hash = pool.submit(tx, &state).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&hash));

        let reaped = pool.reap();
        assert_eq!(reaped.len(), 1);
        // Reap doesn't remove
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn duplicate_tx_rejected() {
        let (vs, keys) = test_validator_set();
        let state = ChainState::genesis(vs);
        let mut pool = Mempool::new(MempoolConfig::default());

        let (sk, pk) = &keys[0];
        let tx = make_register_tx(sk, pk, [0xBB; 32]);

        pool.submit(tx.clone(), &state).unwrap();
        let result = pool.submit(tx, &state);
        assert!(result.is_err());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn full_mempool_rejected() {
        let (vs, keys) = test_validator_set();
        let state = ChainState::genesis(vs);
        let config = MempoolConfig {
            max_txs: 2,
            max_txs_per_block: 2,
        };
        let mut pool = Mempool::new(config);

        let (sk, pk) = &keys[0];
        pool.submit(make_register_tx(sk, pk, [1; 32]), &state)
            .unwrap();
        pool.submit(make_register_tx(sk, pk, [2; 32]), &state)
            .unwrap();

        let result = pool.submit(make_register_tx(sk, pk, [3; 32]), &state);
        assert!(matches!(result, Err(MempoolError::Full { max: 2 })));
    }

    #[test]
    fn invalid_signature_rejected() {
        let (vs, _) = test_validator_set();
        let state = ChainState::genesis(vs);
        let mut pool = Mempool::new(MempoolConfig::default());

        let tx = Transaction::RegisterFile {
            merkle_root: [0xCC; 32],
            file_count: 1,
            encrypted_size: 100,
            owner_pk: [1u8; 32],
            signature: vec![0u8; 64], // garbage
        };

        let result = pool.submit(tx, &state);
        assert!(matches!(result, Err(MempoolError::Invalid(_))));
    }

    #[test]
    fn already_registered_rejected() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);
        let mut pool = Mempool::new(MempoolConfig::default());

        let (sk, pk) = &keys[0];
        let merkle_root = [0xDD; 32];

        // Register on-chain first
        let tx = make_register_tx(sk, pk, merkle_root);
        make_block_and_apply(&mut state, vec![tx]);

        // Try to submit same merkle_root to mempool
        let tx2 = make_register_tx(sk, pk, merkle_root);
        let result = pool.submit(tx2, &state);
        assert!(matches!(result, Err(MempoolError::Invalid(_))));
    }

    #[test]
    fn verify_nonexistent_file_rejected() {
        let (vs, keys) = test_validator_set();
        let state = ChainState::genesis(vs);
        let mut pool = Mempool::new(MempoolConfig::default());

        let (sk, pk) = &keys[0];
        let merkle_root = [0xEE; 32];
        let sig = sk.sign(&merkle_root);

        let tx = Transaction::VerifyIntegrity {
            merkle_root,
            verifier_pk: *pk,
            signature: sig.to_bytes().to_vec(),
        };
        let result = pool.submit(tx, &state);
        assert!(matches!(result, Err(MempoolError::Invalid(_))));
    }

    #[test]
    fn purge_removes_committed() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);
        let mut pool = Mempool::new(MempoolConfig::default());

        let (sk, pk) = &keys[0];
        let tx1 = make_register_tx(sk, pk, [1; 32]);
        let tx2 = make_register_tx(sk, pk, [2; 32]);
        let tx3 = make_register_tx(sk, pk, [3; 32]);

        pool.submit(tx1.clone(), &state).unwrap();
        pool.submit(tx2.clone(), &state).unwrap();
        pool.submit(tx3, &state).unwrap();
        assert_eq!(pool.len(), 3);

        // Commit tx1 and tx2 in a block
        let header = BlockHeader {
            height: Height(1),
            timestamp: 1000,
            prev_block_id: state.last_block_id,
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            proposer: state.validator_set.validators[0].address,
            tx_count: 2,
        };
        let block = Block {
            header,
            transactions: vec![tx1, tx2],
        };
        state.apply_block(&block).unwrap();

        pool.purge(&block);
        assert_eq!(pool.len(), 1); // only tx3 remains
    }

    #[test]
    fn revalidate_evicts_stale() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);
        let mut pool = Mempool::new(MempoolConfig::default());

        let (sk, pk) = &keys[0];
        let merkle_root = [0xAA; 32];

        // Submit RegisterFile to mempool
        let tx = make_register_tx(sk, pk, merkle_root);
        pool.submit(tx.clone(), &state).unwrap();
        assert_eq!(pool.len(), 1);

        // Someone else registers the same merkle_root on-chain
        make_block_and_apply(&mut state, vec![tx]);

        // Revalidate — the pending tx is now stale
        pool.revalidate(&state);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn reap_respects_max_per_block() {
        let (vs, keys) = test_validator_set();
        let state = ChainState::genesis(vs);
        let config = MempoolConfig {
            max_txs: 100,
            max_txs_per_block: 3,
        };
        let mut pool = Mempool::new(config);

        let (sk, pk) = &keys[0];
        for i in 0..10u8 {
            let mut root = [0u8; 32];
            root[0] = i;
            pool.submit(make_register_tx(sk, pk, root), &state).unwrap();
        }
        assert_eq!(pool.len(), 10);

        let reaped = pool.reap();
        assert_eq!(reaped.len(), 3);
    }

    #[test]
    fn block_builder_produces_valid_block() {
        let (vs, keys) = test_validator_set();
        let state = ChainState::genesis(vs);
        let mut pool = Mempool::new(MempoolConfig::default());

        let (sk, pk) = &keys[0];
        pool.submit(make_register_tx(sk, pk, [0x10; 32]), &state)
            .unwrap();
        pool.submit(make_register_tx(sk, pk, [0x20; 32]), &state)
            .unwrap();

        let block = BlockBuilder::build(&pool, &state);
        assert_eq!(block.header.height, Height(1));
        assert_eq!(block.transactions.len(), 2);
        assert_eq!(block.header.tx_count, 2);
        assert_ne!(block.header.state_root, [0u8; 32]);

        // Block should be applicable to state
        let mut new_state = state.clone();
        new_state.apply_block(&block).unwrap();
        assert_eq!(new_state.height, Height(1));
        assert_eq!(new_state.file_count(), 2);
    }

    #[test]
    fn block_builder_skips_invalid_txs() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);
        let mut pool = Mempool::new(MempoolConfig::default());

        let (sk, pk) = &keys[0];

        // Submit two valid txs
        pool.submit(make_register_tx(sk, pk, [0x10; 32]), &state)
            .unwrap();
        pool.submit(make_register_tx(sk, pk, [0x20; 32]), &state)
            .unwrap();

        // Register [0x10] on-chain, making it stale in the mempool
        make_block_and_apply(&mut state, vec![make_register_tx(sk, pk, [0x10; 32])]);

        // Builder should skip the stale tx
        let block = BlockBuilder::build(&pool, &state);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.header.height, Height(2));
    }

    #[test]
    fn block_builder_empty_mempool() {
        let (vs, _) = test_validator_set();
        let state = ChainState::genesis(vs);
        let pool = Mempool::new(MempoolConfig::default());

        let block = BlockBuilder::build(&pool, &state);
        assert_eq!(block.header.height, Height(1));
        assert!(block.transactions.is_empty());
        assert_eq!(block.header.tx_count, 0);
    }
}

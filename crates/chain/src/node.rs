//! Node actor: the consensus driver that ties together ChainState, Mempool,
//! and the Malachite BFT engine.
//!
//! The Node receives events from the consensus layer (propose, decide) and
//! from external clients (submit_tx, query), coordinating state transitions
//! and mempool management.

use tracing::info;

use crate::mempool::{BlockBuilder, Mempool, MempoolConfig, MempoolError};
use crate::state::ChainState;
use crate::types::{Address, Block, BlockId, Height, Transaction, ValidatorSet};

// ── Errors ──

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("State error: {0}")]
    State(#[from] crate::state::StateError),

    #[error("Mempool error: {0}")]
    Mempool(#[from] MempoolError),

    #[error("Not the proposer for height {height} round {round}")]
    NotProposer { height: u64, round: u32 },

    #[error("Block height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },
}

pub type Result<T> = std::result::Result<T, NodeError>;

// ── Node Configuration ──

/// Configuration for the chain node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// This node's validator address.
    pub validator_address: Address,
    /// This node's Ed25519 public key.
    pub validator_pk: [u8; 32],
    /// Mempool configuration.
    pub mempool_config: MempoolConfig,
}

// ── Node ──

/// The chain node: coordinates consensus events with state and mempool.
#[derive(Debug)]
pub struct Node {
    /// Current chain state.
    state: ChainState,
    /// Transaction mempool.
    mempool: Mempool,
    /// Node configuration.
    config: NodeConfig,
    /// Number of blocks committed since genesis.
    blocks_committed: u64,
}

impl Node {
    /// Create a new node from a genesis validator set.
    pub fn new(validator_set: ValidatorSet, config: NodeConfig) -> Self {
        let state = ChainState::genesis(validator_set);
        let mempool = Mempool::new(config.mempool_config.clone());
        Self {
            state,
            mempool,
            config,
            blocks_committed: 0,
        }
    }

    /// Create a node from an existing state (e.g., loaded from disk).
    pub fn from_state(state: ChainState, config: NodeConfig) -> Self {
        let mempool = Mempool::new(config.mempool_config.clone());
        let blocks_committed = state.height.0;
        Self {
            state,
            mempool,
            config,
            blocks_committed,
        }
    }

    // ── Accessors ──

    /// Current chain state (read-only).
    pub fn state(&self) -> &ChainState {
        &self.state
    }

    /// Current block height.
    pub fn height(&self) -> Height {
        self.state.height
    }

    /// Last committed block ID.
    pub fn last_block_id(&self) -> BlockId {
        self.state.last_block_id
    }

    /// Number of pending transactions in the mempool.
    pub fn pending_tx_count(&self) -> usize {
        self.mempool.len()
    }

    /// Number of blocks committed since this node started.
    pub fn blocks_committed(&self) -> u64 {
        self.blocks_committed
    }

    /// This node's validator address.
    pub fn address(&self) -> &Address {
        &self.config.validator_address
    }

    // ── Client-facing operations ──

    /// Submit a transaction from an RPC client.
    ///
    /// The transaction is pre-validated and added to the mempool.
    /// Returns the transaction hash on success.
    pub fn submit_tx(&mut self, tx: Transaction) -> Result<[u8; 32]> {
        let hash = self.mempool.submit(tx, &self.state)?;
        Ok(hash)
    }

    // ── Consensus event handlers ──

    /// Called by consensus when this node is selected as the block proposer.
    ///
    /// Builds a block from the current mempool and state.
    /// The `round` parameter is used for logging; proposer selection is
    /// handled by the consensus engine.
    pub fn on_propose(&self, round: u32) -> Block {
        let block = BlockBuilder::build(&self.mempool, &self.state);
        info!(
            height = block.header.height.0,
            round,
            tx_count = block.transactions.len(),
            "proposed block"
        );
        block
    }

    /// Called by consensus when a block has been decided (committed).
    ///
    /// Applies the block to the state, purges committed transactions
    /// from the mempool, and revalidates remaining transactions.
    pub fn on_decided(&mut self, block: Block) -> Result<()> {
        let expected = Height(self.state.height.0 + 1);
        if block.header.height != expected {
            return Err(NodeError::HeightMismatch {
                expected: expected.0,
                got: block.header.height.0,
            });
        }

        let tx_count = block.transactions.len();
        let height = block.header.height;

        // Apply block to state
        self.state.apply_block(&block)?;

        // Clean up mempool
        self.mempool.purge(&block);
        self.mempool.revalidate(&self.state);

        self.blocks_committed += 1;

        info!(
            height = height.0,
            tx_count,
            file_count = self.state.file_count(),
            pending = self.mempool.len(),
            "block committed"
        );

        Ok(())
    }

    /// Called when receiving a block from another validator (not our proposal).
    ///
    /// Validates and applies the block, same as `on_decided`.
    pub fn on_received_block(&mut self, block: Block) -> Result<()> {
        self.on_decided(block)
    }

    // ── Query operations ──

    /// Look up a file entry by merkle root.
    pub fn get_file(&self, merkle_root: &[u8; 32]) -> Option<&crate::state::FileEntry> {
        self.state.get_file(merkle_root)
    }

    /// Get the current validator set.
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.state.validator_set
    }

    /// Compute the current state root.
    pub fn state_root(&self) -> [u8; 32] {
        self.state.state_root()
    }

    /// Get node status summary.
    pub fn status(&self) -> NodeStatus {
        NodeStatus {
            height: self.state.height,
            last_block_id: self.state.last_block_id,
            state_root: self.state.state_root(),
            file_count: self.state.file_count(),
            validator_count: self.state.validator_set.validators.len(),
            pending_txs: self.mempool.len(),
            blocks_committed: self.blocks_committed,
        }
    }
}

/// Summary of the node's current status.
#[derive(Debug, Clone)]
pub struct NodeStatus {
    pub height: Height,
    pub last_block_id: BlockId,
    pub state_root: [u8; 32],
    pub file_count: usize,
    pub validator_count: usize,
    pub pending_txs: usize,
    pub blocks_committed: u64,
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

    fn test_setup() -> (Node, Vec<(SigningKey, [u8; 32])>) {
        let keys: Vec<_> = (1..=3).map(make_keypair).collect();
        let validators: Vec<Validator> = keys
            .iter()
            .map(|(_, pk)| Validator::new(*pk, 100))
            .collect();
        let vs = ValidatorSet::new(validators);

        let config = NodeConfig {
            validator_address: Address::from_public_key(&keys[0].1),
            validator_pk: keys[0].1,
            mempool_config: MempoolConfig::default(),
        };

        (Node::new(vs, config), keys)
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

    #[test]
    fn new_node_at_genesis() {
        let (node, _) = test_setup();
        assert_eq!(node.height(), Height::GENESIS);
        assert_eq!(node.pending_tx_count(), 0);
        assert_eq!(node.blocks_committed(), 0);

        let status = node.status();
        assert_eq!(status.file_count, 0);
        assert_eq!(status.validator_count, 3);
    }

    #[test]
    fn submit_tx_adds_to_mempool() {
        let (mut node, keys) = test_setup();
        let (sk, pk) = &keys[0];
        let tx = make_register_tx(sk, pk, [0xAA; 32]);

        let hash = node.submit_tx(tx).unwrap();
        assert_eq!(node.pending_tx_count(), 1);
        assert!(node.mempool.contains(&hash));
    }

    #[test]
    fn propose_builds_block() {
        let (mut node, keys) = test_setup();
        let (sk, pk) = &keys[0];

        node.submit_tx(make_register_tx(sk, pk, [0x10; 32]))
            .unwrap();
        node.submit_tx(make_register_tx(sk, pk, [0x20; 32]))
            .unwrap();

        let block = node.on_propose(0);
        assert_eq!(block.header.height, Height(1));
        assert_eq!(block.transactions.len(), 2);
    }

    #[test]
    fn decide_applies_block() {
        let (mut node, keys) = test_setup();
        let (sk, pk) = &keys[0];

        node.submit_tx(make_register_tx(sk, pk, [0x10; 32]))
            .unwrap();
        node.submit_tx(make_register_tx(sk, pk, [0x20; 32]))
            .unwrap();
        assert_eq!(node.pending_tx_count(), 2);

        let block = node.on_propose(0);
        node.on_decided(block).unwrap();

        assert_eq!(node.height(), Height(1));
        assert_eq!(node.state().file_count(), 2);
        assert_eq!(node.pending_tx_count(), 0); // purged
        assert_eq!(node.blocks_committed(), 1);
    }

    #[test]
    fn decide_wrong_height_fails() {
        let (mut node, keys) = test_setup();
        let (sk, pk) = &keys[0];

        // Submit and commit one block first
        node.submit_tx(make_register_tx(sk, pk, [0x10; 32]))
            .unwrap();
        let block1 = node.on_propose(0);
        node.on_decided(block1).unwrap();

        // Try to commit another block at height 1 (should be 2)
        node.submit_tx(make_register_tx(sk, pk, [0x20; 32]))
            .unwrap();
        let block2 = node.on_propose(0);

        // Manually create a block with wrong height
        let bad_block = Block {
            header: BlockHeader {
                height: Height(5),
                ..block2.header
            },
            transactions: block2.transactions,
        };
        let result = node.on_decided(bad_block);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_blocks_lifecycle() {
        let (mut node, keys) = test_setup();
        let (sk, pk) = &keys[0];

        for i in 0..5u8 {
            let mut root = [0u8; 32];
            root[0] = i;
            node.submit_tx(make_register_tx(sk, pk, root)).unwrap();
            let block = node.on_propose(0);
            node.on_decided(block).unwrap();
        }

        assert_eq!(node.height(), Height(5));
        assert_eq!(node.state().file_count(), 5);
        assert_eq!(node.blocks_committed(), 5);
        assert_eq!(node.pending_tx_count(), 0);
    }

    #[test]
    fn query_file_after_commit() {
        let (mut node, keys) = test_setup();
        let (sk, pk) = &keys[0];
        let merkle_root = [0xAB; 32];

        node.submit_tx(make_register_tx(sk, pk, merkle_root))
            .unwrap();
        let block = node.on_propose(0);
        node.on_decided(block).unwrap();

        let entry = node.get_file(&merkle_root).unwrap();
        assert_eq!(entry.owner_pk, *pk);
        assert_eq!(entry.registered_at, Height(1));
    }

    #[test]
    fn mempool_purged_after_decide() {
        let (mut node, keys) = test_setup();
        let (sk, pk) = &keys[0];

        // Submit 3 txs
        node.submit_tx(make_register_tx(sk, pk, [1; 32])).unwrap();
        node.submit_tx(make_register_tx(sk, pk, [2; 32])).unwrap();
        node.submit_tx(make_register_tx(sk, pk, [3; 32])).unwrap();
        assert_eq!(node.pending_tx_count(), 3);

        // Propose and decide — all 3 should be included
        let block = node.on_propose(0);
        assert_eq!(block.transactions.len(), 3);
        node.on_decided(block).unwrap();

        assert_eq!(node.pending_tx_count(), 0);
    }

    #[test]
    fn stale_tx_evicted_after_decide() {
        let (mut node, keys) = test_setup();
        let (sk, pk) = &keys[0];
        let merkle_root = [0xDD; 32];

        // Submit a RegisterFile tx
        node.submit_tx(make_register_tx(sk, pk, merkle_root))
            .unwrap();

        // Simulate: someone else's block registers the same merkle_root
        // We manually build and apply a block containing the same tx
        let external_block = Block {
            header: BlockHeader {
                height: Height(1),
                timestamp: 1000,
                prev_block_id: node.last_block_id(),
                state_root: [0u8; 32],
                tx_root: [0u8; 32],
                proposer: node.state().validator_set.validators[0].address,
                tx_count: 1,
            },
            transactions: vec![make_register_tx(sk, pk, merkle_root)],
        };
        node.on_decided(external_block).unwrap();

        // The mempool tx was purged (same tx) and any remaining would be revalidated
        assert_eq!(node.pending_tx_count(), 0);
    }

    #[test]
    fn from_state_restores() {
        let (mut node, keys) = test_setup();
        let (sk, pk) = &keys[0];

        // Commit some blocks
        for i in 0..3u8 {
            let mut root = [0u8; 32];
            root[0] = i;
            node.submit_tx(make_register_tx(sk, pk, root)).unwrap();
            let block = node.on_propose(0);
            node.on_decided(block).unwrap();
        }

        // "Restart" from saved state
        let saved_state = node.state().clone();
        let config = NodeConfig {
            validator_address: Address::from_public_key(pk),
            validator_pk: *pk,
            mempool_config: MempoolConfig::default(),
        };
        let restored = Node::from_state(saved_state, config);

        assert_eq!(restored.height(), Height(3));
        assert_eq!(restored.state().file_count(), 3);
        assert_eq!(restored.blocks_committed(), 3);
        assert_eq!(restored.pending_tx_count(), 0);
    }

    #[test]
    fn status_reflects_state() {
        let (mut node, keys) = test_setup();
        let (sk, pk) = &keys[0];

        let status_before = node.status();
        assert_eq!(status_before.height, Height::GENESIS);
        assert_eq!(status_before.file_count, 0);

        node.submit_tx(make_register_tx(sk, pk, [0xAA; 32]))
            .unwrap();
        let block = node.on_propose(0);
        node.on_decided(block).unwrap();

        let status_after = node.status();
        assert_eq!(status_after.height, Height(1));
        assert_eq!(status_after.file_count, 1);
        assert_eq!(status_after.blocks_committed, 1);
        assert_eq!(status_after.pending_txs, 0);
        assert_ne!(status_before.state_root, status_after.state_root);
    }
}

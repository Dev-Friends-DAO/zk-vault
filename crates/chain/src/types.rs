//! Core blockchain types for the zk-vault chain.
//!
//! These types are used by the consensus engine and state machine.

use serde::{Deserialize, Serialize};

// ── Height ──

/// Block height (monotonically increasing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Height(pub u64);

impl Height {
    pub const GENESIS: Self = Self(0);

    pub fn increment(self) -> Self {
        Self(self.0 + 1)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for Height {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Round ──

/// Consensus round within a height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Round(pub u32);

impl Round {
    pub const ZERO: Self = Self(0);

    pub fn increment(self) -> Self {
        Self(self.0 + 1)
    }
}

impl std::fmt::Display for Round {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Address ──

/// Validator address: BLAKE3 hash of the Ed25519 public key (first 20 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address([u8; 20]);

impl Address {
    pub fn from_public_key(pk: &[u8; 32]) -> Self {
        let hash = blake3::hash(pk);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash.as_bytes()[..20]);
        Self(addr)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Address({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ── Validator ──

/// A validator in the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    /// Validator address (derived from public key).
    pub address: Address,
    /// Ed25519 public key (32 bytes).
    pub public_key: [u8; 32],
    /// Voting power.
    pub voting_power: u64,
}

impl Validator {
    pub fn new(public_key: [u8; 32], voting_power: u64) -> Self {
        Self {
            address: Address::from_public_key(&public_key),
            public_key,
            voting_power,
        }
    }
}

// ── ValidatorSet ──

/// The set of validators for a given height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    total_power: u64,
}

impl ValidatorSet {
    pub fn new(validators: Vec<Validator>) -> Self {
        let total_power = validators.iter().map(|v| v.voting_power).sum();
        Self {
            validators,
            total_power,
        }
    }

    pub fn total_voting_power(&self) -> u64 {
        self.total_power
    }

    /// Get validator by address.
    pub fn get_by_address(&self, addr: &Address) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.address == addr)
    }

    /// Select proposer for a given height and round (round-robin).
    pub fn proposer(&self, height: Height, round: Round) -> &Validator {
        let index = (height.0 as usize + round.0 as usize) % self.validators.len();
        &self.validators[index]
    }

    /// Check if a set of voting power exceeds 2/3 of total.
    pub fn has_quorum(&self, power: u64) -> bool {
        power * 3 > self.total_power * 2
    }
}

// ── Transaction ──

/// Chain transactions for the zk-vault FileRegistry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Transaction {
    /// Register a new backup on-chain.
    RegisterFile {
        /// Backup manifest Merkle root.
        merkle_root: [u8; 32],
        /// Number of files in the backup.
        file_count: u32,
        /// Total encrypted size in bytes.
        encrypted_size: u64,
        /// Owner's Ed25519 public key.
        owner_pk: [u8; 32],
        /// Ed25519 signature over the merkle_root.
        signature: Vec<u8>,
    },

    /// Verify integrity of an existing backup (on-chain attestation).
    VerifyIntegrity {
        /// Merkle root of the backup to verify.
        merkle_root: [u8; 32],
        /// Verifier's Ed25519 public key.
        verifier_pk: [u8; 32],
        /// Signature attesting the verification.
        signature: Vec<u8>,
    },

    /// Update the validator set (governance).
    UpdateValidatorSet {
        /// New validator set.
        validators: Vec<(/* pk */ [u8; 32], /* power */ u64)>,
        /// Proposer signature.
        signature: Vec<u8>,
    },

    /// Register a guardian for key recovery.
    RegisterGuardian {
        /// Owner's Ed25519 public key.
        owner_pk: [u8; 32],
        /// Guardian's Ed25519 public key (for chain identity).
        guardian_pk: [u8; 32],
        /// Encrypted Shamir share data (hex-encoded JSON of EncryptedGuardianShare).
        encrypted_share: String,
        /// Recovery threshold (K of N).
        threshold: u8,
        /// Total number of guardians (N).
        total_guardians: u8,
        /// Owner's Ed25519 signature over BLAKE3(guardian_pk || threshold || total_guardians).
        signature: Vec<u8>,
    },

    /// Request key recovery (initiates the recovery process).
    RequestRecovery {
        /// Owner's Ed25519 public key (whose keys to recover).
        owner_pk: [u8; 32],
        /// New Ed25519 public key of the requester (for re-encrypted shares).
        new_pk: [u8; 32],
        /// Signature with owner's original key, OR if lost, signature with new_pk over owner_pk.
        signature: Vec<u8>,
    },

    /// Guardian approves a recovery request by providing their decrypted share.
    ApproveRecovery {
        /// Owner whose keys are being recovered.
        owner_pk: [u8; 32],
        /// Guardian's Ed25519 public key.
        guardian_pk: [u8; 32],
        /// The share data (re-encrypted for the requester's new key).
        share_data: String,
        /// Guardian's Ed25519 signature over BLAKE3(owner_pk || share_data).
        signature: Vec<u8>,
    },

    /// Revoke current keys and register new ones.
    RevokeKeys {
        /// Current Ed25519 public key (proves ownership).
        owner_pk: [u8; 32],
        /// New Ed25519 public key.
        new_ed25519_pk: [u8; 32],
        /// Signature with current Ed25519 key over BLAKE3(new_ed25519_pk).
        signature: Vec<u8>,
    },

    /// Validator attests that it stores a blob.
    UpdateStorageStatus {
        /// Blob key.
        blob_key: String,
        /// Validator's Ed25519 public key.
        validator_pk: [u8; 32],
        /// Whether the validator holds the blob.
        holds_blob: bool,
        /// Ed25519 signature over BLAKE3("zk-vault:storage-status:" || blob_key || holds_blob_byte).
        signature: Vec<u8>,
    },

    /// Record a BTC/ETH anchor of the Super Merkle Root.
    AnchorMerkleRoot {
        /// The Super Merkle Root that was anchored.
        super_root: [u8; 32],
        /// Epoch number (height / epoch_length).
        epoch: u64,
        /// Bitcoin anchor receipt (None if BTC anchor was not attempted or failed).
        btc_tx_id: Option<String>,
        /// Ethereum anchor receipt (None if ETH anchor was not attempted or failed).
        eth_tx_id: Option<String>,
        /// Number of files included in the Super Merkle Tree.
        file_count: u32,
        /// Validator who performed the anchor.
        anchor_validator_pk: [u8; 32],
        /// Ed25519 signature over BLAKE3("zk-vault:anchor:" || super_root || epoch_bytes).
        signature: Vec<u8>,
    },

    /// Record a Filecoin deal creation or renewal.
    RenewDeal {
        /// CID of the stored data.
        data_cid: String,
        /// Filecoin deal ID.
        deal_id: u64,
        /// Storage provider address (e.g., "f01234").
        provider: String,
        /// Deal end epoch on Filecoin chain.
        end_epoch: u64,
        /// Whether this is a new deal or renewal of existing.
        is_renewal: bool,
        /// Original merkle root this data belongs to.
        merkle_root: [u8; 32],
        /// Validator who created/monitored the deal.
        validator_pk: [u8; 32],
        /// Ed25519 signature over BLAKE3("zk-vault:deal:" || data_cid || deal_id bytes).
        signature: Vec<u8>,
    },
}

impl Transaction {
    /// Compute the BLAKE3 hash of the serialized transaction.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).expect("Transaction serialization cannot fail");
        *blake3::hash(&bytes).as_bytes()
    }
}

// ── BlockId ──

/// Compact block identifier: BLAKE3 hash of the block header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockId([u8; 32]);

impl BlockId {
    pub fn new(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

// ── Block ──

/// Block header.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height.
    pub height: Height,
    /// Timestamp (Unix millis).
    pub timestamp: u64,
    /// Hash of the previous block header.
    pub prev_block_id: BlockId,
    /// Merkle root of the state after applying transactions.
    pub state_root: [u8; 32],
    /// Merkle root of the transactions in this block.
    pub tx_root: [u8; 32],
    /// Address of the block proposer.
    pub proposer: Address,
    /// Number of transactions.
    pub tx_count: u32,
}

impl BlockHeader {
    /// Compute the block ID (BLAKE3 hash of the serialized header).
    pub fn block_id(&self) -> BlockId {
        let bytes = serde_json::to_vec(self).expect("Header serialization cannot fail");
        BlockId::new(*blake3::hash(&bytes).as_bytes())
    }
}

/// A complete block: header + transactions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Compute the block ID from the header.
    pub fn id(&self) -> BlockId {
        self.header.block_id()
    }

    /// Compute the transaction root (Merkle root of tx hashes).
    pub fn compute_tx_root(&self) -> [u8; 32] {
        if self.transactions.is_empty() {
            return [0u8; 32];
        }
        let tx_hashes: Vec<[u8; 32]> = self.transactions.iter().map(|tx| tx.hash()).collect();
        // Simple hash chain for now; can upgrade to Merkle tree later
        let mut combined = Vec::new();
        for h in &tx_hashes {
            combined.extend_from_slice(h);
        }
        *blake3::hash(&combined).as_bytes()
    }

    /// Genesis block.
    pub fn genesis(validator_set: &ValidatorSet) -> Self {
        let proposer = validator_set.validators[0].address;
        let header = BlockHeader {
            height: Height::GENESIS,
            timestamp: 0,
            prev_block_id: BlockId::new([0u8; 32]),
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            proposer,
            tx_count: 0,
        };
        Self {
            header,
            transactions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validator(seed: u8) -> Validator {
        let mut pk = [0u8; 32];
        pk[0] = seed;
        Validator::new(pk, 100)
    }

    #[test]
    fn address_from_public_key() {
        let pk = [42u8; 32];
        let addr = Address::from_public_key(&pk);
        assert_eq!(addr.as_bytes().len(), 20);

        // Deterministic
        let addr2 = Address::from_public_key(&pk);
        assert_eq!(addr, addr2);

        // Different key → different address
        let pk2 = [43u8; 32];
        let addr3 = Address::from_public_key(&pk2);
        assert_ne!(addr, addr3);
    }

    #[test]
    fn validator_set_proposer_round_robin() {
        let vs = ValidatorSet::new(vec![
            test_validator(1),
            test_validator(2),
            test_validator(3),
        ]);

        let p0 = vs.proposer(Height(0), Round::ZERO);
        let p1 = vs.proposer(Height(1), Round::ZERO);
        let p2 = vs.proposer(Height(2), Round::ZERO);
        let p3 = vs.proposer(Height(3), Round::ZERO); // wraps

        assert_ne!(p0.address, p1.address);
        assert_ne!(p1.address, p2.address);
        assert_eq!(p0.address, p3.address);
    }

    #[test]
    fn validator_set_quorum() {
        let vs = ValidatorSet::new(vec![
            test_validator(1), // 100
            test_validator(2), // 100
            test_validator(3), // 100
        ]);
        assert_eq!(vs.total_voting_power(), 300);
        assert!(!vs.has_quorum(200)); // 200/300 = 66.7%, not > 2/3
        assert!(vs.has_quorum(201)); // 201/300 = 67%, > 2/3
    }

    #[test]
    fn block_id_deterministic() {
        let vs = ValidatorSet::new(vec![test_validator(1)]);
        let block = Block::genesis(&vs);
        let id1 = block.id();
        let id2 = block.id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn transaction_hash() {
        let tx = Transaction::RegisterFile {
            merkle_root: [0xAB; 32],
            file_count: 5,
            encrypted_size: 1024,
            owner_pk: [1u8; 32],
            signature: vec![0u8; 64],
        };
        let h1 = tx.hash();
        let h2 = tx.hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn genesis_block() {
        let vs = ValidatorSet::new(vec![test_validator(1), test_validator(2)]);
        let genesis = Block::genesis(&vs);
        assert_eq!(genesis.header.height, Height::GENESIS);
        assert!(genesis.transactions.is_empty());
        assert_eq!(genesis.header.tx_count, 0);
        assert_eq!(genesis.header.proposer, vs.validators[0].address);
    }
}

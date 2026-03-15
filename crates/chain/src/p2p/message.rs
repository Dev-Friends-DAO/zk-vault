//! P2P network message types for inter-node communication.
//!
//! Messages are organized by gossipsub topic:
//! - Consensus messages (Proposal, Prevote, Precommit) on `/zkvault/consensus/1`
//! - Transaction gossip on `/zkvault/tx/1`
//! - Committed block announcements on `/zkvault/block/1`
//!
//! Block sync uses request-response protocol `/zkvault/sync/1`.

use serde::{Deserialize, Serialize};

use crate::types::{Address, Block, BlockId, Height, Round, Transaction};

// ── Gossipsub Topics ──

/// Topic identifiers for gossipsub.
pub const TOPIC_CONSENSUS: &str = "/zkvault/consensus/1";
pub const TOPIC_TX: &str = "/zkvault/tx/1";
pub const TOPIC_BLOCK: &str = "/zkvault/block/1";

/// Request-response protocol for block sync.
pub const SYNC_PROTOCOL: &str = "/zkvault/sync/1";

// ── Consensus Messages ──

/// A consensus message broadcast via gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// Block proposal from the round's proposer.
    Proposal(Proposal),
    /// Prevote for a block (or nil).
    Prevote(Vote),
    /// Precommit for a block (or nil).
    Precommit(Vote),
}

/// A block proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Block height.
    pub height: Height,
    /// Consensus round.
    pub round: Round,
    /// The proposed block.
    pub block: Block,
    /// Proof-of-lock round (Round(u32::MAX) = nil/no lock).
    pub pol_round: Option<Round>,
    /// Proposer's validator address.
    pub proposer: Address,
    /// Ed25519 signature over BLAKE3(height || round || block_id).
    pub signature: Vec<u8>,
}

/// A prevote or precommit vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Block height.
    pub height: Height,
    /// Consensus round.
    pub round: Round,
    /// Block ID being voted for (None = nil vote).
    pub block_id: Option<BlockId>,
    /// Voter's validator address.
    pub voter: Address,
    /// Ed25519 signature over BLAKE3(vote_type || height || round || block_id_or_nil).
    pub signature: Vec<u8>,
}

impl Vote {
    /// Compute the message bytes that should be signed.
    pub fn sign_bytes(
        vote_type: &str,
        height: Height,
        round: Round,
        block_id: Option<&BlockId>,
    ) -> [u8; 32] {
        let mut msg = Vec::new();
        msg.extend_from_slice(vote_type.as_bytes());
        msg.extend_from_slice(&height.0.to_le_bytes());
        msg.extend_from_slice(&round.0.to_le_bytes());
        match block_id {
            Some(id) => msg.extend_from_slice(id.as_bytes()),
            None => msg.extend_from_slice(&[0u8; 32]),
        }
        *blake3::hash(&msg).as_bytes()
    }
}

impl Proposal {
    /// Compute the message bytes that should be signed.
    pub fn sign_bytes(height: Height, round: Round, block_id: &BlockId) -> [u8; 32] {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"proposal");
        msg.extend_from_slice(&height.0.to_le_bytes());
        msg.extend_from_slice(&round.0.to_le_bytes());
        msg.extend_from_slice(block_id.as_bytes());
        *blake3::hash(&msg).as_bytes()
    }
}

// ── Transaction Gossip ──

/// A transaction broadcast via gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxGossip {
    /// The transaction.
    pub tx: Transaction,
    /// BLAKE3 hash of the transaction (for deduplication).
    pub tx_hash: [u8; 32],
}

// ── Block Announcement ──

/// Announcement of a committed block via gossipsub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAnnounce {
    /// The committed block.
    pub block: Block,
    /// Block ID.
    pub block_id: BlockId,
    /// Height of the committed block.
    pub height: Height,
}

// ── Block Sync (Request-Response) ──

/// Request for block sync (catch-up).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Request a single block by height.
    GetBlock { height: Height },
    /// Request a range of blocks.
    GetBlocks {
        from_height: Height,
        to_height: Height,
    },
    /// Request the peer's current status.
    Status,
}

/// Response for block sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    /// A single block.
    Block(Block),
    /// Multiple blocks.
    Blocks(Vec<Block>),
    /// Peer's current status.
    Status {
        height: Height,
        last_block_id: BlockId,
    },
    /// Block not found.
    NotFound { height: Height },
    /// Error.
    Error(String),
}

// ── Wire Envelope ──

/// Top-level message envelope for all P2P communication.
/// Used for serialization/deserialization on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    Consensus(ConsensusMessage),
    TxGossip(TxGossip),
    BlockAnnounce(BlockAnnounce),
}

impl NetworkMessage {
    /// Serialize to bytes for network transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

impl SyncRequest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

impl SyncResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, Validator, ValidatorSet};

    fn test_vs() -> ValidatorSet {
        ValidatorSet::new(vec![Validator::new([1u8; 32], 100)])
    }

    #[test]
    fn consensus_message_roundtrip() {
        let vs = test_vs();
        let block = Block::genesis(&vs);
        let proposal = ConsensusMessage::Proposal(Proposal {
            height: Height(1),
            round: Round(0),
            block: block.clone(),
            pol_round: None,
            proposer: vs.validators[0].address,
            signature: vec![0u8; 64],
        });

        let msg = NetworkMessage::Consensus(proposal);
        let bytes = msg.to_bytes().unwrap();
        let decoded = NetworkMessage::from_bytes(&bytes).unwrap();
        assert!(matches!(
            decoded,
            NetworkMessage::Consensus(ConsensusMessage::Proposal(_))
        ));
    }

    #[test]
    fn vote_sign_bytes_deterministic() {
        let h = Height(5);
        let r = Round(2);
        let bid = BlockId::new([0xAB; 32]);
        let b1 = Vote::sign_bytes("prevote", h, r, Some(&bid));
        let b2 = Vote::sign_bytes("prevote", h, r, Some(&bid));
        assert_eq!(b1, b2);

        // Different vote type → different bytes
        let b3 = Vote::sign_bytes("precommit", h, r, Some(&bid));
        assert_ne!(b1, b3);

        // Nil vote → different bytes
        let b4 = Vote::sign_bytes("prevote", h, r, None);
        assert_ne!(b1, b4);
    }

    #[test]
    fn tx_gossip_roundtrip() {
        let tx = Transaction::RegisterFile {
            merkle_root: [0xAA; 32],
            file_count: 1,
            encrypted_size: 100,
            owner_pk: [1u8; 32],
            signature: vec![0u8; 64],
        };
        let tx_hash = tx.hash();
        let gossip = TxGossip { tx, tx_hash };
        let msg = NetworkMessage::TxGossip(gossip);
        let bytes = msg.to_bytes().unwrap();
        let decoded = NetworkMessage::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, NetworkMessage::TxGossip(_)));
    }

    #[test]
    fn sync_request_response_roundtrip() {
        let req = SyncRequest::GetBlocks {
            from_height: Height(1),
            to_height: Height(10),
        };
        let bytes = req.to_bytes().unwrap();
        let decoded = SyncRequest::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, SyncRequest::GetBlocks { .. }));

        let resp = SyncResponse::Status {
            height: Height(42),
            last_block_id: BlockId::new([0xFF; 32]),
        };
        let bytes = resp.to_bytes().unwrap();
        let decoded = SyncResponse::from_bytes(&bytes).unwrap();
        assert!(matches!(decoded, SyncResponse::Status { .. }));
    }

    #[test]
    fn proposal_sign_bytes_deterministic() {
        let bid = BlockId::new([0xCD; 32]);
        let b1 = Proposal::sign_bytes(Height(1), Round(0), &bid);
        let b2 = Proposal::sign_bytes(Height(1), Round(0), &bid);
        assert_eq!(b1, b2);

        let b3 = Proposal::sign_bytes(Height(2), Round(0), &bid);
        assert_ne!(b1, b3);
    }
}

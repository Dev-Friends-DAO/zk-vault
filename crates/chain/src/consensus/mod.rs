//! Malachite BFT Context implementation for the zk-vault chain.
//!
//! Maps our domain types to Malachite's trait system.
//!
//! Sub-modules:
//! - [`engine`]: Consensus engine abstraction (PoA / DPoS)
//! - [`vote_collector`]: Vote aggregation and quorum detection
//! - [`driver`]: Async consensus driver event loop

pub mod driver;
pub mod engine;
pub mod vote_collector;

use informalsystems_malachitebft_core_types as malachite;

use crate::types;

// ── ZkVaultContext ──

/// The Malachite context for the zk-vault chain.
#[derive(Clone, Debug)]
pub struct ZkVaultContext;

impl malachite::Context for ZkVaultContext {
    type Address = types::Address;
    type Height = types::Height;
    type ProposalPart = ConsensusProposalPart;
    type Proposal = ConsensusProposal;
    type Validator = types::Validator;
    type ValidatorSet = types::ValidatorSet;
    type Value = types::Block;
    type Vote = ConsensusVote;
    type Extension = VoteExtension;
    type SigningScheme = Ed25519Scheme;

    fn select_proposer<'a>(
        &self,
        validator_set: &'a types::ValidatorSet,
        height: types::Height,
        round: malachite::Round,
    ) -> &'a types::Validator {
        let round_idx = round.as_u32().unwrap_or(0);
        let index =
            (height.as_u64() as usize + round_idx as usize) % validator_set.validators.len();
        &validator_set.validators[index]
    }

    fn new_proposal(
        &self,
        height: types::Height,
        round: malachite::Round,
        value: types::Block,
        pol_round: malachite::Round,
        address: types::Address,
    ) -> ConsensusProposal {
        ConsensusProposal {
            height,
            round,
            value,
            pol_round,
            address,
        }
    }

    fn new_prevote(
        &self,
        height: types::Height,
        round: malachite::Round,
        value_id: malachite::NilOrVal<types::BlockId>,
        address: types::Address,
    ) -> ConsensusVote {
        ConsensusVote {
            vote_type: malachite::VoteType::Prevote,
            height,
            round,
            value_id,
            address,
            extension: None,
        }
    }

    fn new_precommit(
        &self,
        height: types::Height,
        round: malachite::Round,
        value_id: malachite::NilOrVal<types::BlockId>,
        address: types::Address,
    ) -> ConsensusVote {
        ConsensusVote {
            vote_type: malachite::VoteType::Precommit,
            height,
            round,
            value_id,
            address,
            extension: None,
        }
    }
}

// ── Height impl ──

impl Default for types::Height {
    fn default() -> Self {
        Self::GENESIS
    }
}

impl malachite::Height for types::Height {
    const ZERO: Self = types::Height(0);
    const INITIAL: Self = types::Height(1);

    fn increment_by(&self, n: u64) -> Self {
        types::Height(self.0 + n)
    }

    fn decrement_by(&self, n: u64) -> Option<Self> {
        self.0.checked_sub(n).map(types::Height)
    }

    fn as_u64(&self) -> u64 {
        self.0
    }
}

// ── Address impl ──

impl malachite::Address for types::Address {}

// ── Value (Block) impl ──

impl malachite::Value for types::Block {
    type Id = types::BlockId;

    fn id(&self) -> types::BlockId {
        self.id()
    }
}

// ── Validator impl ──

impl malachite::Validator<ZkVaultContext> for types::Validator {
    fn address(&self) -> &types::Address {
        &self.address
    }

    fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    fn voting_power(&self) -> malachite::VotingPower {
        self.voting_power
    }
}

// ── ValidatorSet impl ──

impl malachite::ValidatorSet<ZkVaultContext> for types::ValidatorSet {
    fn count(&self) -> usize {
        self.validators.len()
    }

    fn total_voting_power(&self) -> malachite::VotingPower {
        self.total_voting_power()
    }

    fn get_by_address(&self, address: &types::Address) -> Option<&types::Validator> {
        self.get_by_address(address)
    }

    fn get_by_index(&self, index: usize) -> Option<&types::Validator> {
        self.validators.get(index)
    }
}

// ── SigningScheme: Ed25519 ──

/// Ed25519 public key (32 bytes).
pub type Ed25519PublicKey = [u8; 32];

/// Ed25519 signature (64 bytes).
pub type Ed25519Signature = [u8; 64];

/// Ed25519 private key (32 bytes).
pub type Ed25519PrivateKey = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519Scheme;

impl malachite::SigningScheme for Ed25519Scheme {
    type DecodingError = Ed25519DecodeError;
    type Signature = Ed25519Signature;
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;

    fn decode_signature(bytes: &[u8]) -> Result<Self::Signature, Self::DecodingError> {
        bytes
            .try_into()
            .map_err(|_| Ed25519DecodeError(bytes.len()))
    }

    fn encode_signature(signature: &Self::Signature) -> Vec<u8> {
        signature.to_vec()
    }
}

#[derive(Debug)]
pub struct Ed25519DecodeError(usize);

impl core::fmt::Display for Ed25519DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "expected 64 bytes for Ed25519 signature, got {}", self.0)
    }
}

// ── Vote Extension ──

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VoteExtension {
    pub data: Vec<u8>,
}

impl malachite::Extension for VoteExtension {
    fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

// ── Proposal ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusProposal {
    pub height: types::Height,
    pub round: malachite::Round,
    pub value: types::Block,
    pub pol_round: malachite::Round,
    pub address: types::Address,
}

impl malachite::Proposal<ZkVaultContext> for ConsensusProposal {
    fn height(&self) -> types::Height {
        self.height
    }

    fn round(&self) -> malachite::Round {
        self.round
    }

    fn value(&self) -> &types::Block {
        &self.value
    }

    fn take_value(self) -> types::Block {
        self.value
    }

    fn pol_round(&self) -> malachite::Round {
        self.pol_round
    }

    fn validator_address(&self) -> &types::Address {
        &self.address
    }
}

// ── ProposalPart ──

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusProposalPart {
    pub is_first: bool,
    pub is_last: bool,
}

impl malachite::ProposalPart<ZkVaultContext> for ConsensusProposalPart {
    fn is_first(&self) -> bool {
        self.is_first
    }

    fn is_last(&self) -> bool {
        self.is_last
    }
}

// ── Vote ──

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConsensusVote {
    pub vote_type: malachite::VoteType,
    pub height: types::Height,
    pub round: malachite::Round,
    pub value_id: malachite::NilOrVal<types::BlockId>,
    pub address: types::Address,
    pub extension: Option<malachite::SignedExtension<ZkVaultContext>>,
}

impl malachite::Vote<ZkVaultContext> for ConsensusVote {
    fn height(&self) -> types::Height {
        self.height
    }

    fn round(&self) -> malachite::Round {
        self.round
    }

    fn value(&self) -> &malachite::NilOrVal<types::BlockId> {
        &self.value_id
    }

    fn take_value(self) -> malachite::NilOrVal<types::BlockId> {
        self.value_id
    }

    fn vote_type(&self) -> malachite::VoteType {
        self.vote_type
    }

    fn validator_address(&self) -> &types::Address {
        &self.address
    }

    fn extension(&self) -> Option<&malachite::SignedExtension<ZkVaultContext>> {
        self.extension.as_ref()
    }

    fn take_extension(&mut self) -> Option<malachite::SignedExtension<ZkVaultContext>> {
        self.extension.take()
    }

    fn extend(mut self, extension: malachite::SignedExtension<ZkVaultContext>) -> Self {
        self.extension = Some(extension);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use malachite::{Context as _, SigningScheme as _};

    fn test_validator(seed: u8) -> Validator {
        let mut pk = [0u8; 32];
        pk[0] = seed;
        Validator::new(pk, 100)
    }

    #[test]
    fn context_select_proposer() {
        let ctx = ZkVaultContext;
        let vs = ValidatorSet::new(vec![
            test_validator(1),
            test_validator(2),
            test_validator(3),
        ]);

        let p0 = malachite::Context::select_proposer(&ctx, &vs, Height(0), malachite::Round::ZERO);
        let p1 = malachite::Context::select_proposer(&ctx, &vs, Height(1), malachite::Round::ZERO);
        assert_ne!(p0.address, p1.address);
    }

    #[test]
    fn context_new_vote() {
        let ctx = ZkVaultContext;
        let addr = Address::from_public_key(&[1u8; 32]);

        let prevote = ctx.new_prevote(
            Height(1),
            malachite::Round::ZERO,
            malachite::NilOrVal::Nil,
            addr,
        );
        assert_eq!(
            malachite::Vote::vote_type(&prevote),
            malachite::VoteType::Prevote
        );
        assert_eq!(malachite::Vote::height(&prevote), Height(1));

        let precommit = ctx.new_precommit(
            Height(1),
            malachite::Round::ZERO,
            malachite::NilOrVal::Nil,
            addr,
        );
        assert_eq!(
            malachite::Vote::vote_type(&precommit),
            malachite::VoteType::Precommit
        );
    }

    #[test]
    fn context_new_proposal() {
        let ctx = ZkVaultContext;
        let vs = ValidatorSet::new(vec![test_validator(1)]);
        let block = Block::genesis(&vs);
        let addr = vs.validators[0].address;

        let proposal = ctx.new_proposal(
            Height(1),
            malachite::Round::ZERO,
            block.clone(),
            malachite::Round::Nil,
            addr,
        );
        assert_eq!(malachite::Proposal::height(&proposal), Height(1));
        assert_eq!(malachite::Proposal::value(&proposal), &block);
    }

    #[test]
    fn height_malachite_trait() {
        use malachite::Height as _;
        assert_eq!(Height::ZERO, Height(0));
        assert_eq!(Height::INITIAL, Height(1));
        assert_eq!(Height(5).increment_by(3), Height(8));
        assert_eq!(Height(5).decrement_by(2), Some(Height(3)));
        assert_eq!(Height(2).decrement_by(5), None);
    }

    #[test]
    fn signing_scheme_roundtrip() {
        let sig = [42u8; 64];
        let encoded = Ed25519Scheme::encode_signature(&sig);
        let decoded = Ed25519Scheme::decode_signature(&encoded).unwrap();
        assert_eq!(sig, decoded);
    }
}

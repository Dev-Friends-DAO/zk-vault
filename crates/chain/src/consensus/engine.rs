//! Consensus engine abstraction for PoA/DPoS validator selection.
//!
//! The [`ValidatorSelector`] trait abstracts over how validators are
//! chosen and how proposers are elected. This enables the same consensus
//! driver to work with both PoA (static validator set) and DPoS
//! (stake-weighted dynamic validator set).

use crate::types::{Address, Height, Round, Validator, ValidatorSet};

// ── Trait ──

/// Abstraction over validator selection strategy.
///
/// Implementations determine how the validator set is managed and how
/// proposers are selected. This is the primary extension point for
/// transitioning from PoA to DPoS.
pub trait ValidatorSelector: Send + Sync {
    /// Get the current validator set.
    fn validator_set(&self) -> &ValidatorSet;

    /// Select the proposer for a given height and round.
    fn proposer(&self, height: Height, round: Round) -> &Validator;

    /// Check if an address is a current validator.
    fn is_validator(&self, address: &Address) -> bool;

    /// Update the validator set (e.g., from an UpdateValidatorSet tx).
    fn update_validator_set(&mut self, new_set: ValidatorSet);

    /// Check if a given amount of voting power constitutes a quorum (>2/3).
    fn has_quorum(&self, power: u64) -> bool;

    /// Get the voting power for a specific validator address.
    fn voting_power(&self, address: &Address) -> u64;

    /// Get the total voting power across all validators.
    fn total_voting_power(&self) -> u64;
}

// ── PoA Engine ──

/// Proof of Authority engine: static, known validator set.
///
/// Validators are configured at genesis and can only be changed via
/// governance transactions (UpdateValidatorSet). Proposer selection
/// is round-robin based on (height + round) % validator_count.
#[derive(Debug, Clone)]
pub struct PoaEngine {
    validator_set: ValidatorSet,
}

impl PoaEngine {
    pub fn new(validator_set: ValidatorSet) -> Self {
        Self { validator_set }
    }
}

impl ValidatorSelector for PoaEngine {
    fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    fn proposer(&self, height: Height, round: Round) -> &Validator {
        self.validator_set.proposer(height, round)
    }

    fn is_validator(&self, address: &Address) -> bool {
        self.validator_set.get_by_address(address).is_some()
    }

    fn update_validator_set(&mut self, new_set: ValidatorSet) {
        self.validator_set = new_set;
    }

    fn has_quorum(&self, power: u64) -> bool {
        self.validator_set.has_quorum(power)
    }

    fn voting_power(&self, address: &Address) -> u64 {
        self.validator_set
            .get_by_address(address)
            .map(|v| v.voting_power)
            .unwrap_or(0)
    }

    fn total_voting_power(&self) -> u64 {
        self.validator_set.total_voting_power()
    }
}

// ── Future: DPoS Engine (stub) ──
//
// When DPoS is implemented, it will:
// - Read staking state from ChainState
// - Select top N validators by delegated stake
// - Rotate validator set at epoch boundaries
// - Implement slashing for Byzantine behaviour
//
// The ConsensusDriver and PeerManager will work identically because
// they depend only on the ValidatorSelector trait.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Validator, ValidatorSet};

    fn make_validator(seed: u8, power: u64) -> Validator {
        let mut pk = [0u8; 32];
        pk[0] = seed;
        Validator::new(pk, power)
    }

    fn test_engine() -> PoaEngine {
        let vs = ValidatorSet::new(vec![
            make_validator(1, 100),
            make_validator(2, 100),
            make_validator(3, 100),
        ]);
        PoaEngine::new(vs)
    }

    #[test]
    fn proposer_round_robin() {
        let engine = test_engine();
        let p0 = engine.proposer(Height(0), Round::ZERO).address;
        let p1 = engine.proposer(Height(1), Round::ZERO).address;
        let p2 = engine.proposer(Height(2), Round::ZERO).address;
        let p3 = engine.proposer(Height(3), Round::ZERO).address;

        assert_ne!(p0, p1);
        assert_ne!(p1, p2);
        assert_eq!(p0, p3); // wraps around
    }

    #[test]
    fn is_validator_checks() {
        let engine = test_engine();
        let valid_addr = engine.validator_set().validators[0].address;
        let invalid_addr = Address::from_public_key(&[99u8; 32]);

        assert!(engine.is_validator(&valid_addr));
        assert!(!engine.is_validator(&invalid_addr));
    }

    #[test]
    fn quorum_threshold() {
        let engine = test_engine();
        assert_eq!(engine.total_voting_power(), 300);
        assert!(!engine.has_quorum(200)); // 66.7% not > 2/3
        assert!(engine.has_quorum(201)); // 67% > 2/3
    }

    #[test]
    fn voting_power_lookup() {
        let engine = test_engine();
        let addr = engine.validator_set().validators[0].address;
        assert_eq!(engine.voting_power(&addr), 100);

        let unknown = Address::from_public_key(&[99u8; 32]);
        assert_eq!(engine.voting_power(&unknown), 0);
    }

    #[test]
    fn update_validator_set() {
        let mut engine = test_engine();
        assert_eq!(engine.validator_set().validators.len(), 3);

        let new_vs = ValidatorSet::new(vec![make_validator(10, 200), make_validator(11, 200)]);
        engine.update_validator_set(new_vs);

        assert_eq!(engine.validator_set().validators.len(), 2);
        assert_eq!(engine.total_voting_power(), 400);
    }
}

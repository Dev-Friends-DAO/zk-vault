//! Vote collection and quorum detection for BFT consensus.
//!
//! Tracks prevotes and precommits, aggregates voting power, and
//! detects when a quorum (>2/3 voting power) has been reached.

use std::collections::HashMap;

use crate::types::{Address, BlockId, Height, Round};

/// Tracks votes for BFT consensus rounds.
///
/// Separate instances are used for prevotes and precommits.
#[derive(Debug)]
pub struct VoteCollector {
    /// Votes: (height, round) → voter_address → voted block_id (None = nil vote).
    votes: HashMap<(u64, u32), HashMap<Address, Option<BlockId>>>,
    /// Voting power per address (cached from validator set).
    power: HashMap<Address, u64>,
}

impl Default for VoteCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl VoteCollector {
    pub fn new() -> Self {
        Self {
            votes: HashMap::new(),
            power: HashMap::new(),
        }
    }

    /// Set the voting power for a validator. Call this when the validator
    /// set changes.
    pub fn set_power(&mut self, address: Address, power: u64) {
        self.power.insert(address, power);
    }

    /// Clear and reset power for a new validator set.
    pub fn reset_power(&mut self, validators: &[(Address, u64)]) {
        self.power.clear();
        for (addr, power) in validators {
            self.power.insert(*addr, *power);
        }
    }

    /// Record a vote. Returns `true` if this is a new vote (not a duplicate).
    pub fn add_vote(
        &mut self,
        height: Height,
        round: Round,
        voter: Address,
        block_id: Option<BlockId>,
    ) -> bool {
        let key = (height.0, round.0);
        let round_votes = self.votes.entry(key).or_default();

        // Reject duplicate votes from the same voter
        if round_votes.contains_key(&voter) {
            return false;
        }

        round_votes.insert(voter, block_id);
        true
    }

    /// Get total voting power for votes matching a specific block_id
    /// at (height, round).
    pub fn power_for(&self, height: Height, round: Round, block_id: &Option<BlockId>) -> u64 {
        let key = (height.0, round.0);
        let Some(round_votes) = self.votes.get(&key) else {
            return 0;
        };

        round_votes
            .iter()
            .filter(|(_, bid)| *bid == block_id)
            .map(|(addr, _)| self.power.get(addr).copied().unwrap_or(0))
            .sum()
    }

    /// Get total voting power across all votes at (height, round),
    /// regardless of what they voted for.
    pub fn total_power_at(&self, height: Height, round: Round) -> u64 {
        let key = (height.0, round.0);
        let Some(round_votes) = self.votes.get(&key) else {
            return 0;
        };

        round_votes
            .keys()
            .map(|addr| self.power.get(addr).copied().unwrap_or(0))
            .sum()
    }

    /// Check if there's a quorum for a specific block_id.
    pub fn has_quorum_for(
        &self,
        height: Height,
        round: Round,
        block_id: &Option<BlockId>,
        total_power: u64,
    ) -> bool {
        let power = self.power_for(height, round, block_id);
        power * 3 > total_power * 2
    }

    /// Find the block_id that has quorum (if any).
    pub fn quorum_value(
        &self,
        height: Height,
        round: Round,
        total_power: u64,
    ) -> Option<Option<BlockId>> {
        let key = (height.0, round.0);
        let round_votes = self.votes.get(&key)?;

        // Tally power per block_id
        let mut tally: HashMap<Option<BlockId>, u64> = HashMap::new();
        for (addr, bid) in round_votes {
            let power = self.power.get(addr).copied().unwrap_or(0);
            *tally.entry(*bid).or_default() += power;
        }

        // Check if any value has quorum
        for (bid, power) in tally {
            if power * 3 > total_power * 2 {
                return Some(bid);
            }
        }

        None
    }

    /// Get the number of votes at (height, round).
    pub fn vote_count(&self, height: Height, round: Round) -> usize {
        let key = (height.0, round.0);
        self.votes.get(&key).map(|v| v.len()).unwrap_or(0)
    }

    /// Clear votes for heights below the given threshold (garbage collection).
    pub fn gc(&mut self, below_height: Height) {
        self.votes.retain(|(h, _), _| *h >= below_height.0);
    }

    /// Clear all votes (used when advancing to a new height).
    pub fn clear(&mut self) {
        self.votes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(seed: u8) -> Address {
        Address::from_public_key(&{
            let mut pk = [0u8; 32];
            pk[0] = seed;
            pk
        })
    }

    fn setup() -> VoteCollector {
        let mut vc = VoteCollector::new();
        vc.set_power(addr(1), 100);
        vc.set_power(addr(2), 100);
        vc.set_power(addr(3), 100);
        vc
    }

    #[test]
    fn add_vote_deduplicates() {
        let mut vc = setup();
        let bid = Some(BlockId::new([0xAA; 32]));

        assert!(vc.add_vote(Height(1), Round(0), addr(1), bid));
        assert!(!vc.add_vote(Height(1), Round(0), addr(1), bid)); // duplicate
        assert_eq!(vc.vote_count(Height(1), Round(0)), 1);
    }

    #[test]
    fn power_for_specific_block() {
        let mut vc = setup();
        let bid = Some(BlockId::new([0xAA; 32]));

        vc.add_vote(Height(1), Round(0), addr(1), bid);
        vc.add_vote(Height(1), Round(0), addr(2), bid);
        vc.add_vote(Height(1), Round(0), addr(3), None); // nil vote

        assert_eq!(vc.power_for(Height(1), Round(0), &bid), 200);
        assert_eq!(vc.power_for(Height(1), Round(0), &None), 100);
    }

    #[test]
    fn quorum_detection() {
        let mut vc = setup();
        let bid = Some(BlockId::new([0xBB; 32]));

        // 1 vote: 100/300, no quorum
        vc.add_vote(Height(1), Round(0), addr(1), bid);
        assert!(!vc.has_quorum_for(Height(1), Round(0), &bid, 300));

        // 2 votes: 200/300, no quorum (need > 2/3)
        vc.add_vote(Height(1), Round(0), addr(2), bid);
        assert!(!vc.has_quorum_for(Height(1), Round(0), &bid, 300));

        // 3 votes: 300/300, quorum
        vc.add_vote(Height(1), Round(0), addr(3), bid);
        assert!(vc.has_quorum_for(Height(1), Round(0), &bid, 300));
    }

    #[test]
    fn quorum_value_finds_winner() {
        let mut vc = setup();
        let bid = Some(BlockId::new([0xCC; 32]));

        vc.add_vote(Height(1), Round(0), addr(1), bid);
        vc.add_vote(Height(1), Round(0), addr(2), bid);
        vc.add_vote(Height(1), Round(0), addr(3), bid);

        let winner = vc.quorum_value(Height(1), Round(0), 300);
        assert_eq!(winner, Some(bid));
    }

    #[test]
    fn nil_quorum() {
        let mut vc = setup();

        vc.add_vote(Height(1), Round(0), addr(1), None);
        vc.add_vote(Height(1), Round(0), addr(2), None);
        vc.add_vote(Height(1), Round(0), addr(3), None);

        assert!(vc.has_quorum_for(Height(1), Round(0), &None, 300));
        let winner = vc.quorum_value(Height(1), Round(0), 300);
        assert_eq!(winner, Some(None)); // quorum for nil
    }

    #[test]
    fn gc_removes_old_heights() {
        let mut vc = setup();
        let bid = Some(BlockId::new([0xDD; 32]));

        vc.add_vote(Height(1), Round(0), addr(1), bid);
        vc.add_vote(Height(2), Round(0), addr(1), bid);
        vc.add_vote(Height(3), Round(0), addr(1), bid);

        vc.gc(Height(3));
        assert_eq!(vc.vote_count(Height(1), Round(0)), 0);
        assert_eq!(vc.vote_count(Height(2), Round(0)), 0);
        assert_eq!(vc.vote_count(Height(3), Round(0)), 1);
    }

    #[test]
    fn total_power_at_height_round() {
        let mut vc = setup();
        let bid = Some(BlockId::new([0xEE; 32]));

        vc.add_vote(Height(1), Round(0), addr(1), bid);
        vc.add_vote(Height(1), Round(0), addr(2), None);

        assert_eq!(vc.total_power_at(Height(1), Round(0)), 200);
    }
}

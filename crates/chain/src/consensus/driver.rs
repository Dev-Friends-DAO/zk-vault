//! Async consensus driver: bridges P2P network ↔ Node ↔ BFT rounds.
//!
//! The [`ConsensusDriver`] is the central coordinator that:
//! 1. Receives [`P2pEvent`]s from the network
//! 2. Drives the BFT state machine (Propose → Prevote → Precommit → Commit)
//! 3. Broadcasts votes/proposals via [`P2pHandle`]
//! 4. Calls [`Node::on_propose()`] and [`Node::on_decided()`]
//! 5. Handles block sync for catching-up nodes

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::consensus::engine::ValidatorSelector;
use crate::consensus::vote_collector::VoteCollector;
use crate::node::Node;
use crate::p2p::message::{
    BlockAnnounce, ConsensusMessage, Proposal, SyncRequest, SyncResponse, Vote,
};
use crate::p2p::peer_manager::PeerManager;
use crate::p2p::transport::{P2pEvent, P2pHandle};
use crate::types::{Address, Block, BlockId, Height, Round};

// ── Configuration ──

/// Configuration for the consensus driver.
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Base timeout for the propose phase.
    pub propose_timeout: Duration,
    /// Base timeout for the prevote phase.
    pub prevote_timeout: Duration,
    /// Base timeout for the precommit phase.
    pub precommit_timeout: Duration,
    /// Timeout increase per round (linear backoff).
    pub timeout_delta: Duration,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            propose_timeout: Duration::from_secs(3),
            prevote_timeout: Duration::from_secs(2),
            precommit_timeout: Duration::from_secs(2),
            timeout_delta: Duration::from_millis(500),
        }
    }
}

// ── Phase ──

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for a proposal from the round's proposer.
    Propose,
    /// Proposal received/sent, collecting prevotes.
    Prevote,
    /// Prevote quorum reached, collecting precommits.
    Precommit,
}

// ── ConsensusDriver ──

/// The async consensus driver that coordinates P2P, BFT, and state.
pub struct ConsensusDriver {
    /// Shared node state (also used by RPC).
    node: Arc<RwLock<Node>>,
    /// P2P network handle for broadcasting.
    p2p: P2pHandle,
    /// Validator selection engine (PoA or DPoS).
    engine: Box<dyn ValidatorSelector>,
    /// This node's Ed25519 signing key.
    signing_key: SigningKey,
    /// This node's validator address.
    address: Address,

    // ── BFT round state ──
    height: Height,
    round: Round,
    phase: Phase,

    /// The proposed block for the current round.
    proposed_block: Option<(Block, BlockId)>,

    /// Prevote collector.
    prevotes: VoteCollector,
    /// Precommit collector.
    precommits: VoteCollector,

    /// Peer manager.
    peer_manager: PeerManager,

    /// Timeout configuration.
    config: ConsensusConfig,
}

impl ConsensusDriver {
    /// Create a new consensus driver.
    pub fn new(
        node: Arc<RwLock<Node>>,
        p2p: P2pHandle,
        engine: Box<dyn ValidatorSelector>,
        signing_key: SigningKey,
        config: ConsensusConfig,
    ) -> Self {
        let pk = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&pk);

        let mut prevotes = VoteCollector::new();
        let mut precommits = VoteCollector::new();
        let mut peer_manager = PeerManager::new();

        // Initialize vote collectors and peer manager with validator set
        let validators: Vec<_> = engine
            .validator_set()
            .validators
            .iter()
            .map(|v| (v.address, v.voting_power))
            .collect();
        prevotes.reset_power(&validators);
        precommits.reset_power(&validators);
        peer_manager.set_expected_validators(validators.iter().map(|(a, _)| *a));

        Self {
            node,
            p2p,
            engine,
            signing_key,
            address,
            height: Height(1),
            round: Round::ZERO,
            phase: Phase::Propose,
            proposed_block: None,
            prevotes,
            precommits,
            peer_manager,
            config,
        }
    }

    /// Run the consensus event loop. This method never returns under
    /// normal operation.
    pub async fn run(mut self, mut event_rx: mpsc::Receiver<P2pEvent>) {
        // Initialize height from node state
        {
            let node = self.node.read().await;
            self.height = Height(node.height().0 + 1);
        }

        info!(height = self.height.0, addr = %self.address, "Consensus driver starting");

        // Start the first round (propose if we're the proposer)
        self.enter_new_round().await;

        loop {
            let timeout = self.current_timeout();

            tokio::select! {
                Some(event) = event_rx.recv() => {
                    self.handle_event(event).await;
                }
                _ = tokio::time::sleep(timeout) => {
                    self.handle_timeout().await;
                }
            }

            // Non-recursive state machine: process any pending transitions
            self.drive_state().await;
        }
    }

    // ── Non-recursive state machine ──

    /// Process pending state transitions. Called after every event/timeout.
    /// This is the core state machine that avoids async recursion by
    /// processing transitions in a loop.
    pub async fn drive_state(&mut self) {
        loop {
            let total_power = self.engine.total_voting_power();

            match self.phase {
                Phase::Propose | Phase::Prevote => {
                    // Check for prevote quorum
                    if let Some(quorum_bid) =
                        self.prevotes
                            .quorum_value(self.height, self.round, total_power)
                    {
                        info!(
                            height = self.height.0,
                            round = self.round.0,
                            block_id = ?quorum_bid,
                            "Prevote quorum reached"
                        );
                        self.phase = Phase::Precommit;
                        self.broadcast_precommit(quorum_bid).await;
                        continue; // Check if precommit quorum now
                    }
                    break;
                }
                Phase::Precommit => {
                    if let Some(quorum_bid) =
                        self.precommits
                            .quorum_value(self.height, self.round, total_power)
                    {
                        match quorum_bid {
                            Some(block_id) => {
                                // Quorum for a block → commit
                                self.do_commit(block_id).await;
                                self.enter_new_round().await;
                                // Break after commit; next event/timeout
                                // will trigger further progress.
                                break;
                            }
                            None => {
                                // Quorum for nil → advance round
                                info!(
                                    height = self.height.0,
                                    round = self.round.0,
                                    "Nil quorum, advancing round"
                                );
                                self.round = self.round.increment();
                                self.proposed_block = None;
                                self.enter_new_round().await;
                                break;
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    // ── Round lifecycle ──

    /// Enter a new round: check if we're the proposer, propose if so,
    /// and cast our prevote.
    pub async fn enter_new_round(&mut self) {
        self.phase = Phase::Propose;
        self.proposed_block = None;

        let proposer = self.engine.proposer(self.height, self.round);

        info!(
            height = self.height.0,
            round = self.round.0,
            proposer = %proposer.address,
            is_me = (proposer.address == self.address),
            "Starting round"
        );

        // If we are the proposer, build and broadcast a proposal
        if proposer.address == self.address {
            let block = {
                let node = self.node.read().await;
                node.on_propose(self.round.0)
            };

            let block_id = block.id();
            let signature = self.sign_proposal(self.height, self.round, &block_id);

            let proposal = Proposal {
                height: self.height,
                round: self.round,
                block: block.clone(),
                pol_round: None,
                proposer: self.address,
                signature,
            };

            self.proposed_block = Some((block, block_id));
            self.p2p
                .broadcast_consensus(ConsensusMessage::Proposal(proposal))
                .await;

            // Proposer prevotes for own block
            self.broadcast_prevote(Some(block_id)).await;
        }
    }

    /// Prepare state for the next height after a commit.
    fn advance_height(&mut self) {
        self.height = Height(self.height.0 + 1);
        self.round = Round::ZERO;
        self.prevotes.clear();
        self.precommits.clear();
        self.proposed_block = None;

        // Update vote collectors if validator set changed
        let validators: Vec<_> = self
            .engine
            .validator_set()
            .validators
            .iter()
            .map(|v| (v.address, v.voting_power))
            .collect();
        self.prevotes.reset_power(&validators);
        self.precommits.reset_power(&validators);
    }

    // ── Event handling ──

    pub async fn handle_event(&mut self, event: P2pEvent) {
        match event {
            P2pEvent::ConsensusMsg(msg) => self.handle_consensus_msg(msg).await,
            P2pEvent::TxReceived(tx) => {
                // I5: Tx gossip → mempool integration
                let mut node = self.node.write().await;
                if let Err(e) = node.submit_tx(tx) {
                    debug!(err = %e, "Rejected gossiped tx");
                }
            }
            P2pEvent::BlockAnnounced(announce) => {
                self.handle_block_announce(announce).await;
            }
            P2pEvent::SyncRequest { request, channel } => {
                self.handle_sync_request(request, channel).await;
            }
            P2pEvent::SyncResponse(response) => {
                self.handle_sync_response(response).await;
            }
            P2pEvent::PeerConnected(peer_id) => {
                self.peer_manager.on_peer_connected(peer_id);
                // Request status from new peer
                self.p2p
                    .send_sync_request(peer_id, SyncRequest::Status)
                    .await;
            }
            P2pEvent::PeerDisconnected(peer_id) => {
                self.peer_manager.on_peer_disconnected(&peer_id);
            }
        }
    }

    async fn handle_consensus_msg(&mut self, msg: ConsensusMessage) {
        match msg {
            ConsensusMessage::Proposal(proposal) => self.on_proposal(proposal).await,
            ConsensusMessage::Prevote(vote) => self.on_prevote(vote),
            ConsensusMessage::Precommit(vote) => self.on_precommit(vote),
        }
    }

    // ── Proposal handling ──

    async fn on_proposal(&mut self, proposal: Proposal) {
        // Only process proposals for current height and round
        if proposal.height != self.height || proposal.round != self.round {
            debug!(
                proposal_h = proposal.height.0,
                proposal_r = proposal.round.0,
                our_h = self.height.0,
                our_r = self.round.0,
                "Ignoring proposal for different height/round"
            );
            return;
        }

        if self.phase != Phase::Propose {
            return; // Already past propose phase
        }

        // I6: Verify proposer is correct for this round
        let expected_proposer = self.engine.proposer(self.height, self.round);
        if proposal.proposer != expected_proposer.address {
            warn!(
                expected = %expected_proposer.address,
                got = %proposal.proposer,
                "Proposal from wrong proposer"
            );
            return;
        }

        // I6: Verify signature
        if !self.verify_proposal_signature(&proposal) {
            warn!(proposer = %proposal.proposer, "Invalid proposal signature");
            return;
        }

        let block_id = proposal.block.id();
        self.proposed_block = Some((proposal.block, block_id));

        info!(
            height = self.height.0,
            round = self.round.0,
            block_id = %block_id,
            tx_count = self.proposed_block.as_ref().unwrap().0.transactions.len(),
            "Received valid proposal"
        );

        // Prevote for this block
        self.broadcast_prevote(Some(block_id)).await;
    }

    // ── Prevote handling ──

    fn on_prevote(&mut self, vote: Vote) {
        if vote.height != self.height {
            return;
        }

        // I6: Verify signature
        if !self.verify_vote_signature(&vote, "prevote") {
            warn!(voter = %vote.voter, "Invalid prevote signature");
            return;
        }

        // Must be from a known validator
        if !self.engine.is_validator(&vote.voter) {
            debug!(voter = %vote.voter, "Prevote from non-validator");
            return;
        }

        let new = self
            .prevotes
            .add_vote(vote.height, vote.round, vote.voter, vote.block_id);

        if !new {
            return;
        }

        debug!(
            voter = %vote.voter,
            block_id = ?vote.block_id,
            height = vote.height.0,
            round = vote.round.0,
            "Prevote recorded"
        );
        // Quorum check happens in drive_state()
    }

    // ── Precommit handling ──

    fn on_precommit(&mut self, vote: Vote) {
        if vote.height != self.height {
            return;
        }

        // I6: Verify signature
        if !self.verify_vote_signature(&vote, "precommit") {
            warn!(voter = %vote.voter, "Invalid precommit signature");
            return;
        }

        if !self.engine.is_validator(&vote.voter) {
            debug!(voter = %vote.voter, "Precommit from non-validator");
            return;
        }

        let new = self
            .precommits
            .add_vote(vote.height, vote.round, vote.voter, vote.block_id);

        if !new {
            return;
        }

        debug!(
            voter = %vote.voter,
            block_id = ?vote.block_id,
            height = vote.height.0,
            round = vote.round.0,
            "Precommit recorded"
        );
        // Quorum check happens in drive_state()
    }

    // ── Commit ──

    async fn do_commit(&mut self, block_id: BlockId) {
        let block = match &self.proposed_block {
            Some((block, bid)) if *bid == block_id => block.clone(),
            _ => {
                error!(
                    block_id = %block_id,
                    "Precommit quorum for unknown block"
                );
                return;
            }
        };

        info!(
            height = self.height.0,
            round = self.round.0,
            block_id = %block_id,
            tx_count = block.transactions.len(),
            "Committing block"
        );

        // Apply the block
        {
            let mut node = self.node.write().await;
            if let Err(e) = node.on_decided(block.clone()) {
                error!(err = %e, "Failed to commit block");
                return;
            }
        }

        // Announce the committed block to peers
        let announce = BlockAnnounce {
            block,
            block_id,
            height: self.height,
        };
        self.p2p.announce_block(announce).await;

        // GC old votes and advance height
        self.prevotes.gc(self.height);
        self.precommits.gc(self.height);
        self.advance_height();
    }

    // ── Block announcement (from other nodes) ──

    async fn handle_block_announce(&mut self, announce: BlockAnnounce) {
        let expected_height = {
            let node = self.node.read().await;
            Height(node.height().0 + 1)
        };

        if announce.height == expected_height {
            info!(
                height = announce.height.0,
                block_id = %announce.block_id,
                "Applying announced block"
            );

            let mut node = self.node.write().await;
            if let Err(e) = node.on_decided(announce.block) {
                debug!(err = %e, "Failed to apply announced block");
            } else {
                drop(node);
                self.advance_height();
                self.enter_new_round().await;
            }
        } else if announce.height > expected_height {
            debug!(
                our = expected_height.0,
                announced = announce.height.0,
                "Behind on blocks, need sync"
            );
        }
    }

    // ── Block sync (I7) ──

    async fn handle_sync_request(
        &self,
        request: SyncRequest,
        channel: libp2p::request_response::ResponseChannel<SyncResponse>,
    ) {
        let response = {
            let node = self.node.read().await;
            match request {
                SyncRequest::Status => SyncResponse::Status {
                    height: node.height(),
                    last_block_id: node.last_block_id(),
                },
                SyncRequest::GetBlock { height } => {
                    // TODO: Add block history storage for full sync support.
                    SyncResponse::NotFound { height }
                }
                SyncRequest::GetBlocks {
                    from_height,
                    to_height: _,
                } => SyncResponse::NotFound {
                    height: from_height,
                },
            }
        };

        self.p2p.send_sync_response(channel, response).await;
    }

    async fn handle_sync_response(&mut self, response: SyncResponse) {
        match response {
            SyncResponse::Status {
                height,
                last_block_id: _,
            } => {
                debug!(peer_height = height.0, "Received status response");
                let our_height = {
                    let node = self.node.read().await;
                    node.height()
                };
                if height > our_height {
                    info!(
                        our = our_height.0,
                        peer = height.0,
                        "Peer is ahead, sync needed"
                    );
                }
            }
            SyncResponse::Block(block) => {
                let mut node = self.node.write().await;
                if let Err(e) = node.on_decided(block) {
                    debug!(err = %e, "Failed to apply synced block");
                }
            }
            SyncResponse::Blocks(blocks) => {
                let mut node = self.node.write().await;
                for block in blocks {
                    if let Err(e) = node.on_decided(block) {
                        debug!(err = %e, "Failed to apply synced block");
                        break;
                    }
                }
            }
            SyncResponse::NotFound { height } => {
                debug!(height = height.0, "Sync: block not found");
            }
            SyncResponse::Error(e) => {
                warn!(err = %e, "Sync error from peer");
            }
        }
    }

    // ── Timeouts ──

    fn current_timeout(&self) -> Duration {
        let base = match self.phase {
            Phase::Propose => self.config.propose_timeout,
            Phase::Prevote => self.config.prevote_timeout,
            Phase::Precommit => self.config.precommit_timeout,
        };
        base + self.config.timeout_delta * self.round.0
    }

    async fn handle_timeout(&mut self) {
        match self.phase {
            Phase::Propose => {
                info!(
                    height = self.height.0,
                    round = self.round.0,
                    "Propose timeout, prevoting nil"
                );
                self.broadcast_prevote(None).await;
            }
            Phase::Prevote => {
                info!(
                    height = self.height.0,
                    round = self.round.0,
                    "Prevote timeout, precommitting nil"
                );
                self.phase = Phase::Precommit;
                self.broadcast_precommit(None).await;
            }
            Phase::Precommit => {
                info!(
                    height = self.height.0,
                    round = self.round.0,
                    "Precommit timeout, advancing round"
                );
                self.round = self.round.increment();
                self.proposed_block = None;
                self.enter_new_round().await;
            }
        }
    }

    // ── Voting (broadcast only, no quorum check) ──

    async fn broadcast_prevote(&mut self, block_id: Option<BlockId>) {
        self.phase = Phase::Prevote;

        let signature = self.sign_vote("prevote", self.height, self.round, block_id.as_ref());

        let vote = Vote {
            height: self.height,
            round: self.round,
            block_id,
            voter: self.address,
            signature,
        };

        // Record our own vote
        self.prevotes
            .add_vote(self.height, self.round, self.address, block_id);

        self.p2p
            .broadcast_consensus(ConsensusMessage::Prevote(vote))
            .await;
    }

    async fn broadcast_precommit(&mut self, block_id: Option<BlockId>) {
        let signature = self.sign_vote("precommit", self.height, self.round, block_id.as_ref());

        let vote = Vote {
            height: self.height,
            round: self.round,
            block_id,
            voter: self.address,
            signature,
        };

        // Record our own vote
        self.precommits
            .add_vote(self.height, self.round, self.address, block_id);

        self.p2p
            .broadcast_consensus(ConsensusMessage::Precommit(vote))
            .await;
    }

    // ── I6: Signatures ──

    fn sign_proposal(&self, height: Height, round: Round, block_id: &BlockId) -> Vec<u8> {
        let sign_bytes = Proposal::sign_bytes(height, round, block_id);
        self.signing_key.sign(&sign_bytes).to_bytes().to_vec()
    }

    fn sign_vote(
        &self,
        vote_type: &str,
        height: Height,
        round: Round,
        block_id: Option<&BlockId>,
    ) -> Vec<u8> {
        let sign_bytes = Vote::sign_bytes(vote_type, height, round, block_id);
        self.signing_key.sign(&sign_bytes).to_bytes().to_vec()
    }

    pub(crate) fn verify_proposal_signature(&self, proposal: &Proposal) -> bool {
        let Some(validator) = self
            .engine
            .validator_set()
            .get_by_address(&proposal.proposer)
        else {
            return false;
        };

        let Ok(verifying_key) = VerifyingKey::from_bytes(&validator.public_key) else {
            return false;
        };

        let sign_bytes =
            Proposal::sign_bytes(proposal.height, proposal.round, &proposal.block.id());

        let Ok(signature) = ed25519_dalek::Signature::from_slice(&proposal.signature) else {
            return false;
        };

        verifying_key.verify(&sign_bytes, &signature).is_ok()
    }

    pub(crate) fn verify_vote_signature(&self, vote: &Vote, vote_type: &str) -> bool {
        let Some(validator) = self.engine.validator_set().get_by_address(&vote.voter) else {
            return false;
        };

        let Ok(verifying_key) = VerifyingKey::from_bytes(&validator.public_key) else {
            return false;
        };

        let sign_bytes =
            Vote::sign_bytes(vote_type, vote.height, vote.round, vote.block_id.as_ref());

        let Ok(signature) = ed25519_dalek::Signature::from_slice(&vote.signature) else {
            return false;
        };

        verifying_key.verify(&sign_bytes, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::engine::PoaEngine;
    use crate::mempool::MempoolConfig;
    use crate::node::{Node, NodeConfig};
    use crate::storage::Storage;
    use crate::types::{Validator, ValidatorSet};

    fn make_keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        let sk = SigningKey::from_bytes(&secret);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn sign_and_verify_proposal() {
        let (sk, pk) = make_keypair(1);
        let vs = ValidatorSet::new(vec![Validator::new(pk, 100)]);
        let engine = PoaEngine::new(vs.clone());

        let block = Block::genesis(&vs);
        let block_id = block.id();
        let height = Height(1);
        let round = Round::ZERO;

        let sign_bytes = Proposal::sign_bytes(height, round, &block_id);
        let signature = sk.sign(&sign_bytes).to_bytes().to_vec();

        let proposal = Proposal {
            height,
            round,
            block,
            pol_round: None,
            proposer: Address::from_public_key(&pk),
            signature,
        };

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(dir.path()).unwrap());
        let config = NodeConfig {
            validator_address: Address::from_public_key(&pk),
            validator_pk: pk,
            mempool_config: MempoolConfig::default(),
        };
        let node = Arc::new(RwLock::new(Node::new(vs, config, storage)));
        let (cmd_tx, _) = mpsc::channel(16);
        let p2p = P2pHandle::new(cmd_tx);
        let driver =
            ConsensusDriver::new(node, p2p, Box::new(engine), sk, ConsensusConfig::default());

        assert!(driver.verify_proposal_signature(&proposal));
    }

    #[test]
    fn sign_and_verify_vote() {
        let (sk, pk) = make_keypair(2);
        let vs = ValidatorSet::new(vec![Validator::new(pk, 100)]);
        let engine = PoaEngine::new(vs.clone());

        let height = Height(1);
        let round = Round::ZERO;
        let block_id = Some(BlockId::new([0xAA; 32]));

        let sign_bytes = Vote::sign_bytes("prevote", height, round, block_id.as_ref());
        let signature = sk.sign(&sign_bytes).to_bytes().to_vec();

        let vote = Vote {
            height,
            round,
            block_id,
            voter: Address::from_public_key(&pk),
            signature,
        };

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(dir.path()).unwrap());
        let config = NodeConfig {
            validator_address: Address::from_public_key(&pk),
            validator_pk: pk,
            mempool_config: MempoolConfig::default(),
        };
        let node = Arc::new(RwLock::new(Node::new(vs, config, storage)));
        let (cmd_tx, _) = mpsc::channel(16);
        let p2p = P2pHandle::new(cmd_tx);
        let driver =
            ConsensusDriver::new(node, p2p, Box::new(engine), sk, ConsensusConfig::default());

        assert!(driver.verify_vote_signature(&vote, "prevote"));
        assert!(!driver.verify_vote_signature(&vote, "precommit"));
    }

    #[test]
    fn invalid_signature_rejected() {
        let (sk, pk) = make_keypair(3);
        let vs = ValidatorSet::new(vec![Validator::new(pk, 100)]);
        let engine = PoaEngine::new(vs.clone());

        let vote = Vote {
            height: Height(1),
            round: Round::ZERO,
            block_id: None,
            voter: Address::from_public_key(&pk),
            signature: vec![0u8; 64],
        };

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(dir.path()).unwrap());
        let config = NodeConfig {
            validator_address: Address::from_public_key(&pk),
            validator_pk: pk,
            mempool_config: MempoolConfig::default(),
        };
        let node = Arc::new(RwLock::new(Node::new(vs, config, storage)));
        let (cmd_tx, _) = mpsc::channel(16);
        let p2p = P2pHandle::new(cmd_tx);
        let driver =
            ConsensusDriver::new(node, p2p, Box::new(engine), sk, ConsensusConfig::default());

        assert!(!driver.verify_vote_signature(&vote, "prevote"));
    }

    #[tokio::test]
    async fn single_validator_consensus_round() {
        // With a single validator, the node should propose, prevote, precommit,
        // and commit all by itself via drive_state().
        let (sk, pk) = make_keypair(1);
        let vs = ValidatorSet::new(vec![Validator::new(pk, 100)]);
        let engine = PoaEngine::new(vs.clone());

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(dir.path()).unwrap());
        let config = NodeConfig {
            validator_address: Address::from_public_key(&pk),
            validator_pk: pk,
            mempool_config: MempoolConfig::default(),
        };
        let node = Arc::new(RwLock::new(Node::new(vs, config, storage)));
        let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
        let p2p = P2pHandle::new(cmd_tx);
        let mut driver = ConsensusDriver::new(
            Arc::clone(&node),
            p2p,
            Box::new(engine),
            sk,
            ConsensusConfig::default(),
        );

        // Start round: proposer proposes + prevotes
        driver.enter_new_round().await;
        while cmd_rx.try_recv().is_ok() {}

        // drive_state: prevote quorum → precommit → precommit quorum → commit
        // Then breaks after commit + enters new round at height 2.
        driver.drive_state().await;
        while cmd_rx.try_recv().is_ok() {}

        // Node should have committed exactly one block (height 0→1)
        {
            let node = node.read().await;
            assert_eq!(node.height(), Height(1));
            assert_eq!(node.blocks_committed(), 1);
        }

        // Second drive_state commits another block at height 2
        driver.drive_state().await;
        while cmd_rx.try_recv().is_ok() {}

        {
            let node = node.read().await;
            assert_eq!(node.height(), Height(2));
            assert_eq!(node.blocks_committed(), 2);
        }
    }
}

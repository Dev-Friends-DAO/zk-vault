//! Peer management for the P2P network.
//!
//! Tracks connected peers, maps validator addresses to peer IDs,
//! and provides peer selection for block sync requests.
//!
//! Works with both PoA (static validator list) and DPoS (dynamic
//! validator set from staking state) via the [`ValidatorSelector`] trait.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use libp2p::PeerId;
use tracing::{debug, info};

use crate::types::{Address, Height};

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// libp2p peer ID.
    pub peer_id: PeerId,
    /// When the peer connected.
    pub connected_at: Instant,
    /// Last time we received a message from this peer.
    pub last_seen: Instant,
    /// Peer's self-reported chain height (from status messages).
    pub height: Option<Height>,
    /// Whether this peer is a known validator.
    pub is_validator: bool,
}

/// Manages connected peers and validator-to-peer mapping.
#[derive(Debug)]
pub struct PeerManager {
    /// Connected peers by PeerId.
    peers: HashMap<PeerId, PeerInfo>,
    /// Known mapping of validator address → PeerId.
    /// Populated when we receive signed messages from peers.
    validator_peers: HashMap<Address, PeerId>,
    /// Expected validator addresses (from the consensus engine).
    expected_validators: HashSet<Address>,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            validator_peers: HashMap::new(),
            expected_validators: HashSet::new(),
        }
    }

    /// Set the expected validator addresses.
    /// Called when the validator set changes (PoA update or DPoS epoch).
    pub fn set_expected_validators(&mut self, addresses: impl IntoIterator<Item = Address>) {
        self.expected_validators = addresses.into_iter().collect();
        // Update is_validator flag for existing peers
        for (addr, peer_id) in &self.validator_peers {
            if let Some(info) = self.peers.get_mut(peer_id) {
                info.is_validator = self.expected_validators.contains(addr);
            }
        }
    }

    /// Register a new peer connection.
    pub fn on_peer_connected(&mut self, peer_id: PeerId) {
        let now = Instant::now();
        self.peers.insert(
            peer_id,
            PeerInfo {
                peer_id,
                connected_at: now,
                last_seen: now,
                height: None,
                is_validator: false,
            },
        );
        info!(peer = %peer_id, "Peer registered");
    }

    /// Remove a disconnected peer.
    pub fn on_peer_disconnected(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
        self.validator_peers.retain(|_, pid| pid != peer_id);
        debug!(peer = %peer_id, "Peer removed");
    }

    /// Associate a validator address with a peer ID.
    /// Called when we receive a signed consensus message from a peer.
    pub fn register_validator_peer(&mut self, address: Address, peer_id: PeerId) {
        self.validator_peers.insert(address, peer_id);
        if let Some(info) = self.peers.get_mut(&peer_id) {
            info.is_validator = self.expected_validators.contains(&address);
        }
    }

    /// Update a peer's reported height.
    pub fn update_peer_height(&mut self, peer_id: &PeerId, height: Height) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.height = Some(height);
            info.last_seen = Instant::now();
        }
    }

    /// Mark a peer as recently seen (received any message).
    pub fn touch(&mut self, peer_id: &PeerId) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.last_seen = Instant::now();
        }
    }

    /// Get the PeerId for a validator address.
    pub fn peer_for_validator(&self, address: &Address) -> Option<&PeerId> {
        self.validator_peers.get(address)
    }

    /// Get info about a connected peer.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Number of connected peers.
    pub fn connected_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of connected validator peers.
    pub fn validator_count(&self) -> usize {
        self.peers.values().filter(|p| p.is_validator).count()
    }

    /// Get all connected peer IDs.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peers.keys().copied().collect()
    }

    /// Select the best peer for block sync (highest known height).
    pub fn best_sync_peer(&self) -> Option<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.height.is_some())
            .max_by_key(|p| p.height)
    }

    /// Get all peers that report a height greater than ours.
    pub fn peers_ahead_of(&self, our_height: Height) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.height.map(|h| h > our_height).unwrap_or(false))
            .collect()
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

    #[test]
    fn connect_and_disconnect() {
        let mut pm = PeerManager::new();
        let p1 = PeerId::random();
        let p2 = PeerId::random();

        pm.on_peer_connected(p1);
        pm.on_peer_connected(p2);
        assert_eq!(pm.connected_count(), 2);

        pm.on_peer_disconnected(&p1);
        assert_eq!(pm.connected_count(), 1);
        assert!(pm.peer_info(&p1).is_none());
        assert!(pm.peer_info(&p2).is_some());
    }

    #[test]
    fn validator_peer_mapping() {
        let mut pm = PeerManager::new();
        let p1 = PeerId::random();
        let a1 = addr(1);

        pm.set_expected_validators([a1]);
        pm.on_peer_connected(p1);
        pm.register_validator_peer(a1, p1);

        assert_eq!(pm.peer_for_validator(&a1), Some(&p1));
        assert!(pm.peer_info(&p1).unwrap().is_validator);
        assert_eq!(pm.validator_count(), 1);
    }

    #[test]
    fn best_sync_peer_selects_highest() {
        let mut pm = PeerManager::new();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let p3 = PeerId::random();

        pm.on_peer_connected(p1);
        pm.on_peer_connected(p2);
        pm.on_peer_connected(p3);

        pm.update_peer_height(&p1, Height(5));
        pm.update_peer_height(&p2, Height(10));
        pm.update_peer_height(&p3, Height(3));

        let best = pm.best_sync_peer().unwrap();
        assert_eq!(best.peer_id, p2);
        assert_eq!(best.height, Some(Height(10)));
    }

    #[test]
    fn peers_ahead_of() {
        let mut pm = PeerManager::new();
        let p1 = PeerId::random();
        let p2 = PeerId::random();

        pm.on_peer_connected(p1);
        pm.on_peer_connected(p2);

        pm.update_peer_height(&p1, Height(5));
        pm.update_peer_height(&p2, Height(10));

        let ahead = pm.peers_ahead_of(Height(7));
        assert_eq!(ahead.len(), 1);
        assert_eq!(ahead[0].peer_id, p2);
    }

    #[test]
    fn disconnect_removes_validator_mapping() {
        let mut pm = PeerManager::new();
        let p1 = PeerId::random();
        let a1 = addr(1);

        pm.on_peer_connected(p1);
        pm.register_validator_peer(a1, p1);
        assert!(pm.peer_for_validator(&a1).is_some());

        pm.on_peer_disconnected(&p1);
        assert!(pm.peer_for_validator(&a1).is_none());
    }
}

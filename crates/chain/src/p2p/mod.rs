//! P2P networking layer for multi-node consensus.
//!
//! Built on libp2p with:
//! - gossipsub: consensus messages, tx gossip, block announcements
//! - request-response: block sync (catch-up)
//! - Noise: encrypted transport
//! - mDNS: local peer discovery (development)
//! - Kademlia: DHT-based peer discovery (production)

pub mod message;
pub mod peer_manager;
pub mod transport;

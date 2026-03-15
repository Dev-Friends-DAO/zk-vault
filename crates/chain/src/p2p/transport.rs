//! libp2p transport and swarm configuration.
//!
//! Combines gossipsub, request-response, mDNS, Kademlia, and Noise
//! into a single network behaviour for the zk-vault chain node.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageId};
use libp2p::identity::Keypair;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{mdns, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::message::{
    BlockAnnounce, ConsensusMessage, NetworkMessage, SyncRequest, SyncResponse, TxGossip,
    SYNC_PROTOCOL, TOPIC_BLOCK, TOPIC_CONSENSUS, TOPIC_TX,
};
use crate::types::Transaction;

// ── Configuration ──

/// P2P network configuration.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// Address to listen on (e.g., "/ip4/0.0.0.0/tcp/9030").
    pub listen_addr: Multiaddr,
    /// Bootstrap peer addresses.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Enable mDNS for local peer discovery.
    pub enable_mdns: bool,
    /// Node keypair for identity (derived from validator key).
    pub keypair: Keypair,
}

// ── Combined Behaviour ──

/// The combined network behaviour for zk-vault nodes.
#[derive(NetworkBehaviour)]
pub struct ZkVaultBehaviour {
    /// Gossipsub for consensus messages, tx gossip, block announcements.
    pub gossipsub: gossipsub::Behaviour,
    /// Request-response for block sync.
    pub sync: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
    /// mDNS for local peer discovery.
    pub mdns: mdns::tokio::Behaviour,
    /// Identify protocol for peer metadata exchange.
    pub identify: libp2p::identify::Behaviour,
}

// ── Events emitted to the consensus layer ──

/// Events from the P2P layer to the node/consensus driver.
#[derive(Debug)]
pub enum P2pEvent {
    /// Received a consensus message from a peer.
    ConsensusMsg(ConsensusMessage),
    /// Received a transaction from a peer.
    TxReceived(Transaction),
    /// Received a committed block announcement.
    BlockAnnounced(BlockAnnounce),
    /// Received a sync request from a peer.
    SyncRequest {
        request: SyncRequest,
        channel: request_response::ResponseChannel<SyncResponse>,
    },
    /// Received a sync response.
    SyncResponse(SyncResponse),
    /// A new peer connected.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
}

// ── P2P Network Handle ──

/// Handle for sending messages to the P2P network.
/// Clone-safe; can be shared across tasks.
#[derive(Clone)]
pub struct P2pHandle {
    cmd_tx: mpsc::Sender<P2pCommand>,
}

/// Commands sent to the P2P event loop.
#[derive(Debug)]
pub enum P2pCommand {
    /// Broadcast a consensus message.
    BroadcastConsensus(ConsensusMessage),
    /// Broadcast a transaction.
    BroadcastTx(Transaction),
    /// Announce a committed block.
    AnnounceBlock(BlockAnnounce),
    /// Send a sync request to a specific peer.
    SendSyncRequest { peer: PeerId, request: SyncRequest },
    /// Send a sync response.
    SendSyncResponse {
        channel: request_response::ResponseChannel<SyncResponse>,
        response: SyncResponse,
    },
}

impl P2pHandle {
    /// Create a new P2pHandle from a command sender channel.
    pub fn new(cmd_tx: mpsc::Sender<P2pCommand>) -> Self {
        Self { cmd_tx }
    }

    pub async fn broadcast_consensus(&self, msg: ConsensusMessage) {
        let _ = self.cmd_tx.send(P2pCommand::BroadcastConsensus(msg)).await;
    }

    pub async fn broadcast_tx(&self, tx: Transaction) {
        let _ = self.cmd_tx.send(P2pCommand::BroadcastTx(tx)).await;
    }

    pub async fn announce_block(&self, announce: BlockAnnounce) {
        let _ = self.cmd_tx.send(P2pCommand::AnnounceBlock(announce)).await;
    }

    pub async fn send_sync_request(&self, peer: PeerId, request: SyncRequest) {
        let _ = self
            .cmd_tx
            .send(P2pCommand::SendSyncRequest { peer, request })
            .await;
    }

    pub async fn send_sync_response(
        &self,
        channel: request_response::ResponseChannel<SyncResponse>,
        response: SyncResponse,
    ) {
        let _ = self
            .cmd_tx
            .send(P2pCommand::SendSyncResponse { channel, response })
            .await;
    }
}

// ── Build Swarm ──

/// Build the libp2p swarm with all protocols configured.
pub fn build_swarm(
    config: &P2pConfig,
) -> Result<Swarm<ZkVaultBehaviour>, Box<dyn std::error::Error>> {
    let local_peer_id = PeerId::from(config.keypair.public());

    // Gossipsub configuration
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(|msg: &gossipsub::Message| {
            let mut hasher = DefaultHasher::new();
            msg.data.hash(&mut hasher);
            msg.topic.hash(&mut hasher);
            MessageId::from(hasher.finish().to_string())
        })
        .build()
        .map_err(|e| format!("Gossipsub config error: {e}"))?;

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(config.keypair.clone()),
        gossipsub_config,
    )
    .map_err(|e| format!("Gossipsub behaviour error: {e}"))?;

    // Request-response for sync
    let sync = request_response::cbor::Behaviour::new(
        [(StreamProtocol::new(SYNC_PROTOCOL), ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
    );

    // mDNS for local discovery
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

    // Identify protocol
    let identify = libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
        "/zkvault/1.0.0".to_string(),
        config.keypair.public(),
    ));

    let behaviour = ZkVaultBehaviour {
        gossipsub,
        sync,
        mdns,
        identify,
    };

    let swarm = SwarmBuilder::with_existing_identity(config.keypair.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}

// ── P2P Event Loop ──

/// Run the P2P event loop. This spawns the libp2p swarm and bridges
/// events to/from the consensus layer via channels.
pub async fn run_p2p(
    config: P2pConfig,
    event_tx: mpsc::Sender<P2pEvent>,
) -> Result<P2pHandle, Box<dyn std::error::Error>> {
    let mut swarm = build_swarm(&config)?;

    // Subscribe to gossipsub topics
    let topic_consensus = IdentTopic::new(TOPIC_CONSENSUS);
    let topic_tx = IdentTopic::new(TOPIC_TX);
    let topic_block = IdentTopic::new(TOPIC_BLOCK);

    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic_consensus)?;
    swarm.behaviour_mut().gossipsub.subscribe(&topic_tx)?;
    swarm.behaviour_mut().gossipsub.subscribe(&topic_block)?;

    // Listen
    swarm.listen_on(config.listen_addr.clone())?;
    info!(addr = %config.listen_addr, "P2P listening");

    // Connect to bootstrap peers
    for addr in &config.bootstrap_peers {
        match swarm.dial(addr.clone()) {
            Ok(_) => info!(peer = %addr, "Dialing bootstrap peer"),
            Err(e) => warn!(peer = %addr, err = %e, "Failed to dial bootstrap peer"),
        }
    }

    // Command channel
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<P2pCommand>(256);
    let handle = P2pHandle { cmd_tx };

    // Spawn event loop
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // Handle outgoing commands
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        P2pCommand::BroadcastConsensus(msg) => {
                            let net_msg = NetworkMessage::Consensus(msg);
                            if let Ok(bytes) = net_msg.to_bytes() {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic_consensus.clone(), bytes) {
                                    debug!(err = %e, "Failed to publish consensus message");
                                }
                            }
                        }
                        P2pCommand::BroadcastTx(tx) => {
                            let tx_hash = tx.hash();
                            let gossip = TxGossip { tx, tx_hash };
                            let net_msg = NetworkMessage::TxGossip(gossip);
                            if let Ok(bytes) = net_msg.to_bytes() {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic_tx.clone(), bytes) {
                                    debug!(err = %e, "Failed to publish tx gossip");
                                }
                            }
                        }
                        P2pCommand::AnnounceBlock(announce) => {
                            let net_msg = NetworkMessage::BlockAnnounce(announce);
                            if let Ok(bytes) = net_msg.to_bytes() {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic_block.clone(), bytes) {
                                    debug!(err = %e, "Failed to publish block announcement");
                                }
                            }
                        }
                        P2pCommand::SendSyncRequest { peer, request } => {
                            swarm.behaviour_mut().sync.send_request(&peer, request);
                        }
                        P2pCommand::SendSyncResponse { channel, response } => {
                            if swarm.behaviour_mut().sync.send_response(channel, response).is_err() {
                                debug!("Failed to send sync response");
                            }
                        }
                    }
                }

                // Handle swarm events
                event = swarm.select_next_some() => {
                    match event {
                        libp2p::swarm::SwarmEvent::Behaviour(ZkVaultBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { message, .. }
                        )) => {
                            match NetworkMessage::from_bytes(&message.data) {
                                Ok(NetworkMessage::Consensus(msg)) => {
                                    let _ = event_tx.send(P2pEvent::ConsensusMsg(msg)).await;
                                }
                                Ok(NetworkMessage::TxGossip(gossip)) => {
                                    let _ = event_tx.send(P2pEvent::TxReceived(gossip.tx)).await;
                                }
                                Ok(NetworkMessage::BlockAnnounce(announce)) => {
                                    let _ = event_tx.send(P2pEvent::BlockAnnounced(announce)).await;
                                }
                                Err(e) => {
                                    debug!(err = %e, "Failed to decode gossipsub message");
                                }
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(ZkVaultBehaviourEvent::Sync(
                            request_response::Event::Message { message, .. }
                        )) => {
                            match message {
                                request_response::Message::Request { request, channel, .. } => {
                                    let _ = event_tx.send(P2pEvent::SyncRequest { request, channel }).await;
                                }
                                request_response::Message::Response { response, .. } => {
                                    let _ = event_tx.send(P2pEvent::SyncResponse(response)).await;
                                }
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(ZkVaultBehaviourEvent::Mdns(
                            mdns::Event::Discovered(peers)
                        )) => {
                            for (peer_id, addr) in peers {
                                info!(peer = %peer_id, addr = %addr, "mDNS discovered peer");
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(ZkVaultBehaviourEvent::Mdns(
                            mdns::Event::Expired(peers)
                        )) => {
                            for (peer_id, _) in peers {
                                debug!(peer = %peer_id, "mDNS peer expired");
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            }
                        }
                        libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            info!(peer = %peer_id, "Peer connected");
                            let _ = event_tx.send(P2pEvent::PeerConnected(peer_id)).await;
                        }
                        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            info!(peer = %peer_id, "Peer disconnected");
                            let _ = event_tx.send(P2pEvent::PeerDisconnected(peer_id)).await;
                        }
                        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                            info!(addr = %address, "Listening on");
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    Ok(handle)
}

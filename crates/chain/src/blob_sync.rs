//! Blob synchronization manager for Mode B storage replication.
//!
//! Handles replication of encrypted blobs across validators:
//! - Auto-pushes new blobs to peers after upload
//! - Handles incoming replication requests
//! - Syncs missing blobs on startup

use std::sync::Arc;

use libp2p::PeerId;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::node::Node;
use crate::p2p::message::{BlobReplicationRequest, BlobReplicationResponse};
use crate::p2p::peer_manager::PeerManager;
use crate::p2p::transport::P2pHandle;

/// Manages blob replication across validator nodes.
pub struct BlobSyncManager {
    node: Arc<RwLock<Node>>,
    p2p: P2pHandle,
    peer_manager: Arc<RwLock<PeerManager>>,
    replication_factor: u32,
}

impl BlobSyncManager {
    pub fn new(
        node: Arc<RwLock<Node>>,
        p2p: P2pHandle,
        peer_manager: Arc<RwLock<PeerManager>>,
        replication_factor: u32,
    ) -> Self {
        Self {
            node,
            p2p,
            peer_manager,
            replication_factor,
        }
    }

    /// Replicate a blob to connected peers.
    /// Called after a blob is uploaded locally via RPC.
    pub async fn replicate_blob(&self, key: &str, data: &[u8]) {
        let data_hash = *blake3::hash(data).as_bytes();
        let peers = self.peer_manager.read().await.connected_peers();

        // We count as 1 replica, need replication_factor - 1 more
        let target = if self.replication_factor == 0 {
            peers.len() // 0 = replicate to all
        } else {
            (self.replication_factor as usize)
                .saturating_sub(1)
                .min(peers.len())
        };

        if peers.is_empty() {
            debug!(key, "No peers connected, skipping replication");
            return;
        }

        let request = BlobReplicationRequest::ReplicateBlob {
            key: key.to_string(),
            data: data.to_vec(),
            data_hash,
        };

        let mut replicated = 0;
        for peer in peers.iter().take(target) {
            self.p2p
                .send_blob_repl_request(*peer, request.clone())
                .await;
            replicated += 1;
        }

        info!(
            key,
            replicated,
            total_peers = peers.len(),
            "Blob replication initiated"
        );
    }

    /// Handle an incoming blob replication request from a peer.
    pub async fn handle_request(&self, request: BlobReplicationRequest) -> BlobReplicationResponse {
        match request {
            BlobReplicationRequest::ReplicateBlob {
                key,
                data,
                data_hash,
            } => {
                // Verify data integrity
                let computed_hash = *blake3::hash(&data).as_bytes();
                if computed_hash != data_hash {
                    warn!(key, "Blob data hash mismatch, rejecting");
                    return BlobReplicationResponse::Error("Data hash mismatch".to_string());
                }

                // Store locally
                let size = data.len();
                let mut node = self.node.write().await;
                match node.put_blob(key.clone(), data) {
                    Ok(_) => {
                        info!(key, size, "Blob replicated from peer");
                        BlobReplicationResponse::Ack { key, stored: true }
                    }
                    Err(e) => {
                        warn!(key, err = %e, "Failed to store replicated blob");
                        BlobReplicationResponse::Error(e.to_string())
                    }
                }
            }
            BlobReplicationRequest::GetBlob { key } => {
                let node = self.node.read().await;
                match node.get_blob(&key) {
                    Ok(Some(data)) => BlobReplicationResponse::BlobData { key, data },
                    Ok(None) => BlobReplicationResponse::NotFound { key },
                    Err(e) => BlobReplicationResponse::Error(e.to_string()),
                }
            }
            BlobReplicationRequest::ListBlobs => {
                let node = self.node.read().await;
                match node.list_blobs() {
                    Ok(keys) => BlobReplicationResponse::BlobKeys(keys),
                    Err(e) => BlobReplicationResponse::Error(e.to_string()),
                }
            }
        }
    }

    /// Sync missing blobs from a peer.
    /// Sends ListBlobs to the peer and then fetches any keys we don't have.
    pub async fn request_blob_list(&self, peer: PeerId) {
        self.p2p
            .send_blob_repl_request(peer, BlobReplicationRequest::ListBlobs)
            .await;
    }

    /// Handle a ListBlobs response: fetch any blobs we're missing.
    pub async fn handle_blob_list(&self, peer: PeerId, remote_keys: Vec<String>) {
        let local_keys: std::collections::HashSet<String> = {
            let node = self.node.read().await;
            match node.list_blobs() {
                Ok(keys) => keys.into_iter().collect(),
                Err(e) => {
                    warn!(err = %e, "Failed to list local blobs for sync");
                    return;
                }
            }
        };

        let missing: Vec<_> = remote_keys
            .into_iter()
            .filter(|k| !local_keys.contains(k))
            .collect();

        if missing.is_empty() {
            debug!("No missing blobs to sync");
            return;
        }

        info!(count = missing.len(), "Requesting missing blobs from peer");
        for key in missing {
            self.p2p
                .send_blob_repl_request(peer, BlobReplicationRequest::GetBlob { key })
                .await;
        }
    }

    /// Handle a GetBlob response (BlobData received from peer).
    pub async fn handle_blob_data(&self, key: String, data: Vec<u8>) {
        let mut node = self.node.write().await;
        match node.put_blob(key.clone(), data) {
            Ok(size) => info!(key, size, "Synced missing blob from peer"),
            Err(e) => warn!(key, err = %e, "Failed to store synced blob"),
        }
    }
}

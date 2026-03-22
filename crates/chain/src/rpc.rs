//! JSON-RPC server for the zk-vault chain node.
//!
//! Provides HTTP endpoints for submitting transactions, querying chain state,
//! and checking node status. Uses axum with `Arc<Mutex<Node>>` for shared state.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::blob_sync::BlobSyncManager;
use crate::node::Node;

// ── Shared state ──

/// Thread-safe shared node reference.
pub type SharedNode = Arc<Mutex<Node>>;

// ── Request / Response types ──

/// JSON-RPC submit_tx request.
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitTxRequest {
    /// Hex-encoded serialized transaction JSON.
    pub tx_json: String,
}

/// JSON-RPC submit_tx response.
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitTxResponse {
    pub tx_hash: String,
}

/// JSON-RPC get_status response.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub height: u64,
    pub last_block_id: String,
    pub state_root: String,
    pub file_count: usize,
    pub validator_count: usize,
    pub pending_txs: usize,
    pub blocks_committed: u64,
}

/// JSON-RPC get_file request.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetFileRequest {
    /// Hex-encoded merkle root (64 hex chars = 32 bytes).
    pub merkle_root: String,
}

/// JSON-RPC get_file response.
#[derive(Debug, Serialize, Deserialize)]
pub struct FileResponse {
    pub merkle_root: String,
    pub owner_pk: String,
    pub file_count: u32,
    pub encrypted_size: u64,
    pub registered_at: u64,
    pub verification_count: usize,
}

/// Upload encrypted data blob request.
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadDataRequest {
    /// Storage key (hex-encoded merkle root or user-defined key).
    pub key: String,
    /// Base64-encoded encrypted data.
    pub data_b64: String,
}

/// Upload encrypted data blob response.
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadDataResponse {
    pub key: String,
    pub size: usize,
}

/// Download encrypted data blob request.
#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadDataRequest {
    /// Storage key.
    pub key: String,
}

/// Download encrypted data blob response.
#[derive(Debug, Serialize, Deserialize)]
pub struct DownloadDataResponse {
    pub key: String,
    pub data_b64: String,
    pub size: usize,
}

/// List stored data blobs response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListDataResponse {
    pub keys: Vec<String>,
    pub total_size: u64,
}

/// Anchor status response (Super Merkle Tree batching).
#[derive(Debug, Serialize, Deserialize)]
pub struct AnchorStatusResponse {
    /// Number of registered files included in the Super Merkle Tree.
    pub file_count: usize,
    /// Hex-encoded Super Merkle Root (BLAKE3).
    pub super_root: Option<String>,
    /// User proofs (user_id → hex proof).
    pub user_proofs: Vec<SuperProofEntry>,
}

/// A single user's proof in the Super Merkle Tree.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuperProofEntry {
    pub owner_pk: String,
    pub merkle_root: String,
    pub proof_index: usize,
    pub proof_hashes: Vec<String>,
}

/// Get guardians request.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetGuardiansRequest {
    pub owner_pk: String,
}

/// Get guardians response.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetGuardiansResponse {
    pub owner_pk: String,
    pub threshold: u8,
    pub total_guardians: u8,
    pub guardian_count: usize,
    pub guardians: Vec<GuardianInfo>,
}

/// Guardian info in response.
#[derive(Debug, Serialize, Deserialize)]
pub struct GuardianInfo {
    pub guardian_pk: String,
    pub registered_at: u64,
}

/// Get recovery status request.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetRecoveryStatusRequest {
    pub owner_pk: String,
}

/// Get recovery status response.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetRecoveryStatusResponse {
    pub owner_pk: String,
    pub status: String,
    pub new_pk: String,
    pub requested_at: u64,
    pub approval_count: usize,
    pub threshold: u8,
}

/// Get key status request.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetKeyStatusRequest {
    pub owner_pk: String,
}

/// Get key status response.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetKeyStatusResponse {
    pub owner_pk: String,
    pub current_pk: String,
    pub revoked_count: usize,
    pub last_rotated: u64,
}

/// Get anchor history request.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetAnchorRequest {
    /// Epoch number to query (if omitted, returns latest).
    pub epoch: Option<u64>,
}

/// Get anchor history response.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetAnchorResponse {
    pub epoch: u64,
    pub super_root: String,
    pub btc_tx_id: Option<String>,
    pub eth_tx_id: Option<String>,
    pub file_count: u32,
    pub anchor_validator: String,
    pub recorded_at: u64,
}

/// List all anchors response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ListAnchorsResponse {
    pub anchors: Vec<GetAnchorResponse>,
    pub total: usize,
}

/// Generic error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// RPC state with optional blob sync manager for peer retrieval.
#[derive(Clone)]
pub struct RpcState {
    pub node: SharedNode,
    pub blob_sync: Option<Arc<tokio::sync::RwLock<BlobSyncManager>>>,
}

// ── Router ──

/// Build the axum router with all RPC endpoints.
pub fn router(node: SharedNode) -> Router {
    Router::new()
        .route("/status", get(handle_status))
        .route("/submit_tx", post(handle_submit_tx))
        .route("/get_file", post(handle_get_file))
        .route("/propose", post(handle_propose))
        .route("/upload_data", post(handle_upload_data))
        .route("/download_data", post(handle_download_data))
        .route("/list_data", get(handle_list_data))
        .route("/anchor_status", get(handle_anchor_status))
        .route("/health", get(handle_health))
        .route("/get_guardians", post(handle_get_guardians))
        .route("/get_recovery_status", post(handle_get_recovery_status))
        .route("/get_key_status", post(handle_get_key_status))
        .route("/get_anchor", post(handle_get_anchor))
        .route("/list_anchors", get(handle_list_anchors))
        .with_state(node)
}

/// Start the RPC server on the given address.
pub async fn serve(node: SharedNode, addr: &str) -> std::io::Result<()> {
    let app = router(node);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr, "RPC server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Build the axum router with blob sync support for peer retrieval.
pub fn router_with_sync(state: RpcState) -> Router {
    Router::new()
        .route("/status", get(handle_status_v2))
        .route("/submit_tx", post(handle_submit_tx_v2))
        .route("/get_file", post(handle_get_file_v2))
        .route("/propose", post(handle_propose_v2))
        .route("/upload_data", post(handle_upload_data_v2))
        .route("/download_data", post(handle_download_data_v2))
        .route("/list_data", get(handle_list_data_v2))
        .route("/anchor_status", get(handle_anchor_status_v2))
        .route("/health", get(handle_health))
        .route("/get_guardians", post(handle_get_guardians_v2))
        .route("/get_recovery_status", post(handle_get_recovery_status_v2))
        .route("/get_key_status", post(handle_get_key_status_v2))
        .route("/get_anchor", post(handle_get_anchor_v2))
        .route("/list_anchors", get(handle_list_anchors_v2))
        .with_state(state)
}

/// Start the RPC server with blob sync support.
pub async fn serve_with_sync(state: RpcState, addr: &str) -> std::io::Result<()> {
    let app = router_with_sync(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr, "RPC server listening (with blob sync)");
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Handlers ──

async fn handle_health() -> &'static str {
    "ok"
}

async fn handle_status(State(node): State<SharedNode>) -> Json<StatusResponse> {
    let node = node.lock().unwrap();
    let status = node.status();
    Json(StatusResponse {
        height: status.height.0,
        last_block_id: hex::encode(status.last_block_id.as_bytes()),
        state_root: hex::encode(status.state_root),
        file_count: status.file_count,
        validator_count: status.validator_count,
        pending_txs: status.pending_txs,
        blocks_committed: status.blocks_committed,
    })
}

async fn handle_submit_tx(
    State(node): State<SharedNode>,
    Json(req): Json<SubmitTxRequest>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Parse the transaction from JSON
    let tx: crate::types::Transaction = serde_json::from_str(&req.tx_json).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid transaction JSON: {e}"),
            }),
        )
    })?;

    // Submit to node
    let mut node = node.lock().unwrap();
    let hash = node.submit_tx(tx).map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(SubmitTxResponse {
        tx_hash: hex::encode(hash),
    }))
}

async fn handle_get_file(
    State(node): State<SharedNode>,
    Json(req): Json<GetFileRequest>,
) -> Result<Json<FileResponse>, (StatusCode, Json<ErrorResponse>)> {
    let merkle_root_bytes = hex::decode(&req.merkle_root).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid hex: {e}"),
            }),
        )
    })?;

    if merkle_root_bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "merkle_root must be 32 bytes (64 hex chars), got {}",
                    merkle_root_bytes.len()
                ),
            }),
        ));
    }

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&merkle_root_bytes);

    let node = node.lock().unwrap();
    let entry = node.get_file(&merkle_root).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("File not found: {}", req.merkle_root),
            }),
        )
    })?;

    Ok(Json(FileResponse {
        merkle_root: req.merkle_root,
        owner_pk: hex::encode(entry.owner_pk),
        file_count: entry.file_count,
        encrypted_size: entry.encrypted_size,
        registered_at: entry.registered_at.0,
        verification_count: entry.verifications.len(),
    }))
}

/// Trigger a propose + decide cycle (for testing / single-validator mode).
async fn handle_propose(
    State(node): State<SharedNode>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let mut node = node.lock().unwrap();
    let block = node.on_propose(0);
    let height = block.header.height.0;
    let tx_count = block.transactions.len();

    node.on_decided(block).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(serde_json::json!({
        "height": height,
        "tx_count": tx_count,
    })))
}

// ── Blob store handlers (Mode B) ──

async fn handle_upload_data(
    State(node): State<SharedNode>,
    Json(req): Json<UploadDataRequest>,
) -> Result<Json<UploadDataResponse>, (StatusCode, Json<ErrorResponse>)> {
    use base64::Engine;
    let data = base64::engine::general_purpose::STANDARD
        .decode(&req.data_b64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid base64: {e}"),
                }),
            )
        })?;

    let mut node = node.lock().unwrap();
    let size = node.put_blob(req.key.clone(), data).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    info!(key = %req.key, size, "blob uploaded");

    Ok(Json(UploadDataResponse { key: req.key, size }))
}

async fn handle_download_data(
    State(node): State<SharedNode>,
    Json(req): Json<DownloadDataRequest>,
) -> Result<Json<DownloadDataResponse>, (StatusCode, Json<ErrorResponse>)> {
    use base64::Engine;
    let node = node.lock().unwrap();
    let data = node
        .get_blob(&req.key)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Blob not found: {}", req.key),
                }),
            )
        })?;

    let size = data.len();
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);

    Ok(Json(DownloadDataResponse {
        key: req.key,
        data_b64,
        size,
    }))
}

async fn handle_anchor_status(State(node): State<SharedNode>) -> Json<AnchorStatusResponse> {
    let node = node.lock().unwrap();
    let state = node.state();

    if state.file_registry.is_empty() {
        return Json(AnchorStatusResponse {
            file_count: 0,
            super_root: None,
            user_proofs: vec![],
        });
    }

    // Build Super Merkle Tree from all registered file roots
    let leaf_hashes: Vec<[u8; 32]> = state.file_registry.keys().copied().collect();
    let entries: Vec<_> = state
        .file_registry
        .iter()
        .map(|(root, entry)| (*root, entry.owner_pk))
        .collect();

    let tree = zk_vault_core::merkle::tree::MerkleTree::from_leaf_hashes(leaf_hashes);
    let super_root = tree.root();

    let user_proofs: Vec<SuperProofEntry> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, (root, owner_pk))| {
            let proof = tree.prove(i)?;
            Some(SuperProofEntry {
                owner_pk: hex::encode(owner_pk),
                merkle_root: hex::encode(root),
                proof_index: proof.leaf_index,
                proof_hashes: proof.siblings.iter().map(|(_, h)| hex::encode(h)).collect(),
            })
        })
        .collect();

    Json(AnchorStatusResponse {
        file_count: state.file_registry.len(),
        super_root: super_root.map(hex::encode),
        user_proofs,
    })
}

async fn handle_get_anchor(
    State(node): State<SharedNode>,
    Json(req): Json<GetAnchorRequest>,
) -> Result<Json<GetAnchorResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = node.lock().unwrap();
    let state = node.state();

    let entry = if let Some(epoch) = req.epoch {
        state.anchor_history.get(&epoch)
    } else {
        // Return latest anchor
        state.anchor_history.values().last()
    };

    let entry = entry.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "No anchor found".to_string(),
            }),
        )
    })?;

    Ok(Json(GetAnchorResponse {
        epoch: entry.epoch,
        super_root: hex::encode(entry.super_root),
        btc_tx_id: entry.btc_tx_id.clone(),
        eth_tx_id: entry.eth_tx_id.clone(),
        file_count: entry.file_count,
        anchor_validator: hex::encode(entry.anchor_validator_pk),
        recorded_at: entry.recorded_at.0,
    }))
}

async fn handle_list_anchors(State(node): State<SharedNode>) -> Json<ListAnchorsResponse> {
    let node = node.lock().unwrap();
    let state = node.state();

    let anchors: Vec<GetAnchorResponse> = state
        .anchor_history
        .values()
        .map(|entry| GetAnchorResponse {
            epoch: entry.epoch,
            super_root: hex::encode(entry.super_root),
            btc_tx_id: entry.btc_tx_id.clone(),
            eth_tx_id: entry.eth_tx_id.clone(),
            file_count: entry.file_count,
            anchor_validator: hex::encode(entry.anchor_validator_pk),
            recorded_at: entry.recorded_at.0,
        })
        .collect();

    let total = anchors.len();
    Json(ListAnchorsResponse { anchors, total })
}

/// Parse a hex-encoded 32-byte public key from a request string.
fn parse_pk(hex_str: &str) -> Result<[u8; 32], (StatusCode, Json<ErrorResponse>)> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid hex: {e}"),
            }),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "Public key must be 32 bytes (64 hex chars), got {}",
                    bytes.len()
                ),
            }),
        ));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes);
    Ok(pk)
}

async fn handle_get_guardians(
    State(node): State<SharedNode>,
    Json(req): Json<GetGuardiansRequest>,
) -> Result<Json<GetGuardiansResponse>, (StatusCode, Json<ErrorResponse>)> {
    let owner_pk = parse_pk(&req.owner_pk)?;

    let node = node.lock().unwrap();
    let gs = node.get_guardians(&owner_pk).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("No guardian set found for {}", req.owner_pk),
            }),
        )
    })?;

    let guardians: Vec<GuardianInfo> = gs
        .guardians
        .iter()
        .map(|g| GuardianInfo {
            guardian_pk: hex::encode(g.guardian_pk),
            registered_at: g.registered_at.0,
        })
        .collect();

    Ok(Json(GetGuardiansResponse {
        owner_pk: req.owner_pk,
        threshold: gs.threshold,
        total_guardians: gs.total_guardians,
        guardian_count: gs.guardians.len(),
        guardians,
    }))
}

async fn handle_get_recovery_status(
    State(node): State<SharedNode>,
    Json(req): Json<GetRecoveryStatusRequest>,
) -> Result<Json<GetRecoveryStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let owner_pk = parse_pk(&req.owner_pk)?;

    let node = node.lock().unwrap();
    let rr = node.get_recovery_status(&owner_pk).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("No recovery request found for {}", req.owner_pk),
            }),
        )
    })?;

    let status_str = match &rr.status {
        crate::state::RecoveryStatus::Pending => "Pending",
        crate::state::RecoveryStatus::Completed => "Completed",
        crate::state::RecoveryStatus::Cancelled => "Cancelled",
    };

    // Look up threshold from guardian registry
    let threshold = node
        .get_guardians(&owner_pk)
        .map(|gs| gs.threshold)
        .unwrap_or(0);

    Ok(Json(GetRecoveryStatusResponse {
        owner_pk: req.owner_pk,
        status: status_str.to_string(),
        new_pk: hex::encode(rr.new_pk),
        requested_at: rr.requested_at.0,
        approval_count: rr.approvals.len(),
        threshold,
    }))
}

async fn handle_get_key_status(
    State(node): State<SharedNode>,
    Json(req): Json<GetKeyStatusRequest>,
) -> Result<Json<GetKeyStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let owner_pk = parse_pk(&req.owner_pk)?;

    let node = node.lock().unwrap();
    let ke = node.get_key_status(&owner_pk).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("No key entry found for {}", req.owner_pk),
            }),
        )
    })?;

    Ok(Json(GetKeyStatusResponse {
        owner_pk: req.owner_pk,
        current_pk: hex::encode(ke.current_pk),
        revoked_count: ke.revoked_pks.len(),
        last_rotated: ke.last_rotated.0,
    }))
}

async fn handle_list_data(
    State(node): State<SharedNode>,
) -> Result<Json<ListDataResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = node.lock().unwrap();
    let keys = node.list_blobs().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let total_size = node.blob_store_size().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(Json(ListDataResponse { keys, total_size }))
}

// ── V2 handlers (extract node from RpcState) ──

async fn handle_status_v2(State(state): State<RpcState>) -> Json<StatusResponse> {
    handle_status(State(state.node)).await
}

async fn handle_submit_tx_v2(
    State(state): State<RpcState>,
    body: Json<SubmitTxRequest>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, Json<ErrorResponse>)> {
    handle_submit_tx(State(state.node), body).await
}

async fn handle_get_file_v2(
    State(state): State<RpcState>,
    body: Json<GetFileRequest>,
) -> Result<Json<FileResponse>, (StatusCode, Json<ErrorResponse>)> {
    handle_get_file(State(state.node), body).await
}

async fn handle_propose_v2(
    State(state): State<RpcState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    handle_propose(State(state.node)).await
}

async fn handle_upload_data_v2(
    State(state): State<RpcState>,
    Json(req): Json<UploadDataRequest>,
) -> Result<Json<UploadDataResponse>, (StatusCode, Json<ErrorResponse>)> {
    use base64::Engine;
    let data = base64::engine::general_purpose::STANDARD
        .decode(&req.data_b64)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid base64: {e}"),
                }),
            )
        })?;

    let size = {
        let mut node = state.node.lock().unwrap();
        node.put_blob(req.key.clone(), data.clone()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?
    };
    info!(key = %req.key, size, "blob uploaded");

    // Trigger replication to peers
    if let Some(blob_sync) = &state.blob_sync {
        let sync = blob_sync.read().await;
        sync.replicate_blob(&req.key, &data).await;
    }

    Ok(Json(UploadDataResponse { key: req.key, size }))
}

async fn handle_download_data_v2(
    State(state): State<RpcState>,
    Json(req): Json<DownloadDataRequest>,
) -> Result<Json<DownloadDataResponse>, (StatusCode, Json<ErrorResponse>)> {
    use base64::Engine;

    // Try local first
    let local_data = {
        let node = state.node.lock().unwrap();
        node.get_blob(&req.key).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?
    };

    let data = match local_data {
        Some(data) => data,
        None => {
            // Blob not found locally — in a full P2P implementation,
            // we would query peers via BlobSyncManager here.
            // For now, return 404 (peer retrieval requires async P2P
            // round-trip which is handled by ConsensusDriver events).
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Blob not found: {}", req.key),
                }),
            ));
        }
    };

    let size = data.len();
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);

    Ok(Json(DownloadDataResponse {
        key: req.key,
        data_b64,
        size,
    }))
}

async fn handle_list_data_v2(
    State(state): State<RpcState>,
) -> Result<Json<ListDataResponse>, (StatusCode, Json<ErrorResponse>)> {
    handle_list_data(State(state.node)).await
}

async fn handle_anchor_status_v2(State(state): State<RpcState>) -> Json<AnchorStatusResponse> {
    handle_anchor_status(State(state.node)).await
}

async fn handle_get_guardians_v2(
    State(state): State<RpcState>,
    body: Json<GetGuardiansRequest>,
) -> Result<Json<GetGuardiansResponse>, (StatusCode, Json<ErrorResponse>)> {
    handle_get_guardians(State(state.node), body).await
}

async fn handle_get_recovery_status_v2(
    State(state): State<RpcState>,
    body: Json<GetRecoveryStatusRequest>,
) -> Result<Json<GetRecoveryStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    handle_get_recovery_status(State(state.node), body).await
}

async fn handle_get_key_status_v2(
    State(state): State<RpcState>,
    body: Json<GetKeyStatusRequest>,
) -> Result<Json<GetKeyStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    handle_get_key_status(State(state.node), body).await
}

async fn handle_get_anchor_v2(
    State(state): State<RpcState>,
    body: Json<GetAnchorRequest>,
) -> Result<Json<GetAnchorResponse>, (StatusCode, Json<ErrorResponse>)> {
    handle_get_anchor(State(state.node), body).await
}

async fn handle_list_anchors_v2(State(state): State<RpcState>) -> Json<ListAnchorsResponse> {
    handle_list_anchors(State(state.node)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::MempoolConfig;
    use crate::node::NodeConfig;
    use crate::types::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        let sk = SigningKey::from_bytes(&secret);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn test_node() -> (SharedNode, Vec<(SigningKey, [u8; 32])>, tempfile::TempDir) {
        let keys: Vec<_> = (1..=3).map(make_keypair).collect();
        let validators: Vec<Validator> = keys
            .iter()
            .map(|(_, pk)| Validator::new(*pk, 100))
            .collect();
        let vs = ValidatorSet::new(validators);

        let config = NodeConfig {
            validator_address: Address::from_public_key(&keys[0].1),
            validator_pk: keys[0].1,
            mempool_config: MempoolConfig::default(),
            replication_factor: 3,
        };

        let dir = tempfile::tempdir().unwrap();
        let storage = std::sync::Arc::new(crate::storage::Storage::open(dir.path()).unwrap());
        let node = Arc::new(Mutex::new(Node::new(vs, config, storage)));
        (node, keys, dir)
    }

    fn make_register_tx(sk: &SigningKey, pk: &[u8; 32], merkle_root: [u8; 32]) -> Transaction {
        let sig = sk.sign(&merkle_root);
        Transaction::RegisterFile {
            merkle_root,
            file_count: 1,
            encrypted_size: 1024,
            owner_pk: *pk,
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// Spawn a test server and return its base URL.
    /// The TempDir must be kept alive for the lifetime of the test.
    async fn spawn_test_server() -> (
        String,
        SharedNode,
        Vec<(SigningKey, [u8; 32])>,
        tempfile::TempDir,
    ) {
        let (node, keys, dir) = test_node();
        let app = router(node.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), node, keys, dir)
    }

    #[tokio::test]
    async fn health_check() {
        let (base, _, _, _dir) = spawn_test_server().await;
        let resp = reqwest::get(format!("{base}/health")).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn status_at_genesis() {
        let (base, _, _, _dir) = spawn_test_server().await;
        let resp = reqwest::get(format!("{base}/status")).await.unwrap();
        assert_eq!(resp.status(), 200);

        let status: StatusResponse = resp.json().await.unwrap();
        assert_eq!(status.height, 0);
        assert_eq!(status.file_count, 0);
        assert_eq!(status.validator_count, 3);
        assert_eq!(status.pending_txs, 0);
    }

    #[tokio::test]
    async fn submit_tx_and_propose() {
        let (base, _, keys, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();

        // Submit a tx
        let (sk, pk) = &keys[0];
        let tx = make_register_tx(sk, pk, [0xAA; 32]);
        let tx_json = serde_json::to_string(&tx).unwrap();

        let resp = client
            .post(format!("{base}/submit_tx"))
            .json(&SubmitTxRequest { tx_json })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let submit_resp: SubmitTxResponse = resp.json().await.unwrap();
        assert!(!submit_resp.tx_hash.is_empty());

        // Check status — 1 pending tx
        let status: StatusResponse = client
            .get(format!("{base}/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status.pending_txs, 1);

        // Propose + decide
        let resp = client.post(format!("{base}/propose")).send().await.unwrap();
        assert_eq!(resp.status(), 200);

        // Check status — height 1, 0 pending, 1 file
        let status: StatusResponse = client
            .get(format!("{base}/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status.height, 1);
        assert_eq!(status.file_count, 1);
        assert_eq!(status.pending_txs, 0);
    }

    #[tokio::test]
    async fn get_file_after_commit() {
        let (base, _, keys, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();

        let (sk, pk) = &keys[0];
        let merkle_root = [0xBB; 32];
        let tx = make_register_tx(sk, pk, merkle_root);
        let tx_json = serde_json::to_string(&tx).unwrap();

        // Submit + propose
        client
            .post(format!("{base}/submit_tx"))
            .json(&SubmitTxRequest { tx_json })
            .send()
            .await
            .unwrap();
        client.post(format!("{base}/propose")).send().await.unwrap();

        // Query file
        let resp = client
            .post(format!("{base}/get_file"))
            .json(&GetFileRequest {
                merkle_root: hex::encode(merkle_root),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let file: FileResponse = resp.json().await.unwrap();
        assert_eq!(file.owner_pk, hex::encode(pk));
        assert_eq!(file.file_count, 1);
        assert_eq!(file.registered_at, 1);
    }

    #[tokio::test]
    async fn get_file_not_found() {
        let (base, _, _, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();

        let resp = client
            .post(format!("{base}/get_file"))
            .json(&GetFileRequest {
                merkle_root: hex::encode([0xFF; 32]),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn submit_invalid_tx_rejected() {
        let (base, _, _, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();

        // Bad JSON
        let resp = client
            .post(format!("{base}/submit_tx"))
            .json(&SubmitTxRequest {
                tx_json: "not valid json".to_string(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn submit_bad_signature_rejected() {
        let (base, _, _, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();

        let tx = Transaction::RegisterFile {
            merkle_root: [0xCC; 32],
            file_count: 1,
            encrypted_size: 100,
            owner_pk: [1u8; 32],
            signature: vec![0u8; 64],
        };
        let tx_json = serde_json::to_string(&tx).unwrap();

        let resp = client
            .post(format!("{base}/submit_tx"))
            .json(&SubmitTxRequest { tx_json })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
    }

    #[tokio::test]
    async fn full_lifecycle() {
        let (base, _, keys, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();
        let (sk, pk) = &keys[0];

        // Submit 3 different files
        for i in 0..3u8 {
            let mut root = [0u8; 32];
            root[0] = i;
            let tx = make_register_tx(sk, pk, root);
            let tx_json = serde_json::to_string(&tx).unwrap();
            client
                .post(format!("{base}/submit_tx"))
                .json(&SubmitTxRequest { tx_json })
                .send()
                .await
                .unwrap();
        }

        // Propose once — all 3 should be in one block
        let resp = client.post(format!("{base}/propose")).send().await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["height"], 1);
        assert_eq!(body["tx_count"], 3);

        // Final status
        let status: StatusResponse = client
            .get(format!("{base}/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status.height, 1);
        assert_eq!(status.file_count, 3);
        assert_eq!(status.pending_txs, 0);
        assert_eq!(status.blocks_committed, 1);
    }

    // ── Blob store (Mode B) tests ──

    #[tokio::test]
    async fn upload_and_download_blob() {
        use base64::Engine;
        let (base, _, _, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();

        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);

        // Upload
        let resp = client
            .post(format!("{base}/upload_data"))
            .json(&UploadDataRequest {
                key: "test-blob-1".to_string(),
                data_b64: data_b64.clone(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let upload: UploadDataResponse = resp.json().await.unwrap();
        assert_eq!(upload.key, "test-blob-1");
        assert_eq!(upload.size, 7);

        // Download
        let resp = client
            .post(format!("{base}/download_data"))
            .json(&DownloadDataRequest {
                key: "test-blob-1".to_string(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let download: DownloadDataResponse = resp.json().await.unwrap();
        assert_eq!(download.key, "test-blob-1");
        assert_eq!(download.size, 7);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&download.data_b64)
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn download_blob_not_found() {
        let (base, _, _, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();

        let resp = client
            .post(format!("{base}/download_data"))
            .json(&DownloadDataRequest {
                key: "nonexistent".to_string(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn list_data_empty_then_populated() {
        use base64::Engine;
        let (base, _, _, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();

        // Empty
        let resp: ListDataResponse = client
            .get(format!("{base}/list_data"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(resp.keys.is_empty());
        assert_eq!(resp.total_size, 0);

        // Upload two blobs
        for key in ["blob-a", "blob-b"] {
            let data_b64 = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 100]);
            client
                .post(format!("{base}/upload_data"))
                .json(&UploadDataRequest {
                    key: key.to_string(),
                    data_b64,
                })
                .send()
                .await
                .unwrap();
        }

        // List
        let resp: ListDataResponse = client
            .get(format!("{base}/list_data"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp.keys.len(), 2);
        assert_eq!(resp.total_size, 200);
    }

    #[tokio::test]
    async fn upload_invalid_base64_rejected() {
        let (base, _, _, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();

        let resp = client
            .post(format!("{base}/upload_data"))
            .json(&UploadDataRequest {
                key: "bad".to_string(),
                data_b64: "not-valid-base64!!!".to_string(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
    }

    // ── Anchor status tests ──

    #[tokio::test]
    async fn anchor_status_empty() {
        let (base, _, _, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();

        let resp: AnchorStatusResponse = client
            .get(format!("{base}/anchor_status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp.file_count, 0);
        assert!(resp.super_root.is_none());
        assert!(resp.user_proofs.is_empty());
    }

    #[tokio::test]
    async fn anchor_status_with_files() {
        let (base, _, keys, _dir) = spawn_test_server().await;
        let client = reqwest::Client::new();
        let (sk, pk) = &keys[0];

        // Register 3 files
        for i in 0..3u8 {
            let mut root = [0u8; 32];
            root[0] = i;
            let tx = make_register_tx(sk, pk, root);
            let tx_json = serde_json::to_string(&tx).unwrap();
            client
                .post(format!("{base}/submit_tx"))
                .json(&SubmitTxRequest { tx_json })
                .send()
                .await
                .unwrap();
        }

        // Propose
        client.post(format!("{base}/propose")).send().await.unwrap();

        // Check anchor status
        let resp: AnchorStatusResponse = client
            .get(format!("{base}/anchor_status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp.file_count, 3);
        assert!(resp.super_root.is_some());
        assert_eq!(resp.user_proofs.len(), 3);

        // Each proof should have the correct owner
        for proof in &resp.user_proofs {
            assert_eq!(proof.owner_pk, hex::encode(pk));
            assert!(!proof.proof_hashes.is_empty());
        }
    }
}

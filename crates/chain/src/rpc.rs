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

/// Generic error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ── Router ──

/// Build the axum router with all RPC endpoints.
pub fn router(node: SharedNode) -> Router {
    Router::new()
        .route("/status", get(handle_status))
        .route("/submit_tx", post(handle_submit_tx))
        .route("/get_file", post(handle_get_file))
        .route("/propose", post(handle_propose))
        .route("/health", get(handle_health))
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

    fn test_node() -> (SharedNode, Vec<(SigningKey, [u8; 32])>) {
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
        };

        let node = Arc::new(Mutex::new(Node::new(vs, config)));
        (node, keys)
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
    async fn spawn_test_server() -> (String, SharedNode, Vec<(SigningKey, [u8; 32])>) {
        let (node, keys) = test_node();
        let app = router(node.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), node, keys)
    }

    #[tokio::test]
    async fn health_check() {
        let (base, _, _) = spawn_test_server().await;
        let resp = reqwest::get(format!("{base}/health")).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn status_at_genesis() {
        let (base, _, _) = spawn_test_server().await;
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
        let (base, _, keys) = spawn_test_server().await;
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
        let (base, _, keys) = spawn_test_server().await;
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
        let (base, _, _) = spawn_test_server().await;
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
        let (base, _, _) = spawn_test_server().await;
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
        let (base, _, _) = spawn_test_server().await;
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
        let (base, _, keys) = spawn_test_server().await;
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
}

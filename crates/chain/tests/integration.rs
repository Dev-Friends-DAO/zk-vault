//! Integration tests: 3-node local network simulation.
//!
//! Each node has its own RPC server. Blocks are broadcast manually
//! between nodes (simulating what Malachite consensus would do).

use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use zk_vault_chain::mempool::MempoolConfig;
use zk_vault_chain::node::{Node, NodeConfig};
use zk_vault_chain::rpc::{self, SharedNode, StatusResponse, SubmitTxRequest, SubmitTxResponse};
use zk_vault_chain::types::{Address, Transaction, Validator, ValidatorSet};

// ── Helpers ──

fn make_keypair(seed: u8) -> (SigningKey, [u8; 32]) {
    let mut secret = [0u8; 32];
    secret[0] = seed;
    let sk = SigningKey::from_bytes(&secret);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
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

struct TestNetwork {
    nodes: Vec<SharedNode>,
    urls: Vec<String>,
    keys: Vec<(SigningKey, [u8; 32])>,
}

impl TestNetwork {
    async fn spawn(n: usize) -> Self {
        let keys: Vec<_> = (1..=n as u8).map(make_keypair).collect();
        let validators: Vec<Validator> = keys
            .iter()
            .map(|(_, pk)| Validator::new(*pk, 100))
            .collect();
        let vs = ValidatorSet::new(validators);

        let mut nodes = Vec::new();
        let mut urls = Vec::new();

        for (_, pk) in &keys {
            let config = NodeConfig {
                validator_address: Address::from_public_key(pk),
                validator_pk: *pk,
                mempool_config: MempoolConfig::default(),
            };
            let node = Arc::new(Mutex::new(Node::new(vs.clone(), config)));
            let app = rpc::router(node.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            nodes.push(node);
            urls.push(format!("http://{addr}"));
        }

        Self { nodes, urls, keys }
    }

    /// Propose on the first node and broadcast the decided block to all nodes.
    fn propose_and_broadcast(&self) {
        let block = self.nodes[0].lock().unwrap().on_propose(0);
        for node in &self.nodes {
            node.lock().unwrap().on_decided(block.clone()).unwrap();
        }
    }
}

// ── Tests ──

#[tokio::test]
async fn three_nodes_genesis_status() {
    let net = TestNetwork::spawn(3).await;
    let client = reqwest::Client::new();

    for url in &net.urls {
        let status: StatusResponse = client
            .get(format!("{url}/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status.height, 0);
        assert_eq!(status.file_count, 0);
        assert_eq!(status.validator_count, 3);
    }
}

#[tokio::test]
async fn submit_propose_broadcast_all_agree() {
    let net = TestNetwork::spawn(3).await;
    let client = reqwest::Client::new();

    // Submit tx to node 0 via RPC
    let (sk, pk) = &net.keys[0];
    let tx = make_register_tx(sk, pk, [0xAA; 32]);
    let tx_json = serde_json::to_string(&tx).unwrap();

    let resp: SubmitTxResponse = client
        .post(format!("{}/submit_tx", net.urls[0]))
        .json(&SubmitTxRequest { tx_json })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!resp.tx_hash.is_empty());

    // Propose and broadcast
    net.propose_and_broadcast();

    // All nodes should agree
    let mut state_roots = Vec::new();
    for url in &net.urls {
        let status: StatusResponse = client
            .get(format!("{url}/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status.height, 1);
        assert_eq!(status.file_count, 1);
        assert_eq!(status.pending_txs, 0);
        state_roots.push(status.state_root.clone());
    }

    // All state roots must be identical
    assert_eq!(state_roots[0], state_roots[1]);
    assert_eq!(state_roots[1], state_roots[2]);
}

#[tokio::test]
async fn five_blocks_all_nodes_consistent() {
    let net = TestNetwork::spawn(3).await;
    let (sk, pk) = &net.keys[0];

    for i in 0..5u8 {
        let mut root = [0u8; 32];
        root[0] = i;
        let tx = make_register_tx(sk, pk, root);
        net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
        net.propose_and_broadcast();
    }

    // Verify consistency across all nodes
    for node in &net.nodes {
        let n = node.lock().unwrap();
        assert_eq!(n.height().0, 5);
        assert_eq!(n.state().file_count(), 5);
    }

    // State roots match
    let roots: Vec<_> = net
        .nodes
        .iter()
        .map(|n| n.lock().unwrap().state_root())
        .collect();
    assert_eq!(roots[0], roots[1]);
    assert_eq!(roots[1], roots[2]);
}

#[tokio::test]
async fn query_file_from_any_node() {
    let net = TestNetwork::spawn(3).await;
    let client = reqwest::Client::new();
    let (sk, pk) = &net.keys[0];
    let merkle_root = [0xBB; 32];

    // Submit to node 0, propose, broadcast to all
    let tx = make_register_tx(sk, pk, merkle_root);
    net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
    net.propose_and_broadcast();

    // Query from node 2 (not the one that received the tx)
    let resp = client
        .post(format!("{}/get_file", net.urls[2]))
        .json(&rpc::GetFileRequest {
            merkle_root: hex::encode(merkle_root),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let file: rpc::FileResponse = resp.json().await.unwrap();
    assert_eq!(file.owner_pk, hex::encode(pk));
    assert_eq!(file.file_count, 1);
    assert_eq!(file.registered_at, 1);
}

#[tokio::test]
async fn submit_to_different_nodes() {
    let net = TestNetwork::spawn(3).await;

    // Each validator submits a tx to their own node
    for (i, (sk, pk)) in net.keys.iter().enumerate() {
        let mut root = [0u8; 32];
        root[0] = i as u8 + 10;
        let tx = make_register_tx(sk, pk, root);
        net.nodes[i].lock().unwrap().submit_tx(tx).unwrap();
    }

    // Only node 0 has mempool entries (we submit to each node's own mempool)
    // For the propose to include all txs, we need to gather them on node 0
    // In a real network, gossip would handle this.
    // For this test, we just verify each node can propose its own tx.

    // Propose from node 0 (only has 1 tx)
    let block = net.nodes[0].lock().unwrap().on_propose(0);
    assert_eq!(block.transactions.len(), 1);

    // Apply to all
    for node in &net.nodes {
        node.lock().unwrap().on_decided(block.clone()).unwrap();
    }

    // All at height 1 with 1 file
    for node in &net.nodes {
        let n = node.lock().unwrap();
        assert_eq!(n.height().0, 1);
        assert_eq!(n.state().file_count(), 1);
    }
}

/// E2E: simulates CLI backup → RegisterFile → propose → get_file → VerifyIntegrity
#[tokio::test]
async fn e2e_cli_backup_verify_flow() {
    let net = TestNetwork::spawn(3).await;
    let client = reqwest::Client::new();
    let (sk, pk) = &net.keys[0];
    let base = &net.urls[0];

    // 1. Simulate CLI backup: create RegisterFile tx
    let merkle_root = [0xDE; 32];
    let file_count = 3u32;
    let encrypted_size = 10240u64;
    let sig = sk.sign(&merkle_root);
    let tx = serde_json::json!({
        "RegisterFile": {
            "merkle_root": merkle_root,
            "file_count": file_count,
            "encrypted_size": encrypted_size,
            "owner_pk": *pk,
            "signature": sig.to_bytes().to_vec(),
        }
    });
    let tx_json = tx.to_string();

    // 2. Submit via RPC (like CLI --chain does)
    let resp = client
        .post(format!("{base}/submit_tx"))
        .json(&rpc::SubmitTxRequest { tx_json })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let submit: SubmitTxResponse = resp.json().await.unwrap();
    assert!(!submit.tx_hash.is_empty());

    // 3. Verify pending
    let status: StatusResponse = client
        .get(format!("{base}/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status.pending_txs, 1);

    // 4. Propose + broadcast
    net.propose_and_broadcast();

    // 5. Verify committed
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

    // 6. Query file (like CLI status --chain does)
    let file_resp = client
        .post(format!("{base}/get_file"))
        .json(&rpc::GetFileRequest {
            merkle_root: hex::encode(merkle_root),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(file_resp.status(), 200);
    let file: rpc::FileResponse = file_resp.json().await.unwrap();
    assert_eq!(file.file_count, file_count);
    assert_eq!(file.encrypted_size, encrypted_size);
    assert_eq!(file.owner_pk, hex::encode(pk));
    assert_eq!(file.registered_at, 1);
    assert_eq!(file.verification_count, 0);

    // 7. Simulate CLI verify --chain: submit VerifyIntegrity tx
    let verify_sig = sk.sign(&merkle_root);
    let verify_tx = serde_json::json!({
        "VerifyIntegrity": {
            "merkle_root": merkle_root,
            "verifier_pk": *pk,
            "signature": verify_sig.to_bytes().to_vec(),
        }
    });
    let verify_tx_json = verify_tx.to_string();

    let resp = client
        .post(format!("{base}/submit_tx"))
        .json(&rpc::SubmitTxRequest {
            tx_json: verify_tx_json,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 8. Propose + broadcast again
    net.propose_and_broadcast();

    // 9. Verify verification_count increased
    let file_resp = client
        .post(format!("{base}/get_file"))
        .json(&rpc::GetFileRequest {
            merkle_root: hex::encode(merkle_root),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(file_resp.status(), 200);
    let file: rpc::FileResponse = file_resp.json().await.unwrap();
    assert_eq!(file.verification_count, 1);

    // 10. Final status: height 2, 1 file, 0 pending
    let status: StatusResponse = client
        .get(format!("{base}/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status.height, 2);
    assert_eq!(status.file_count, 1);
    assert_eq!(status.pending_txs, 0);
    assert_eq!(status.blocks_committed, 2);
}

#[tokio::test]
async fn rejected_block_does_not_corrupt_state() {
    let net = TestNetwork::spawn(3).await;
    let (sk, pk) = &net.keys[0];

    // Commit one block normally
    let tx = make_register_tx(sk, pk, [0x01; 32]);
    net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
    net.propose_and_broadcast();

    // Try to apply a block with wrong height to node 1
    let bad_tx = make_register_tx(sk, pk, [0x02; 32]);
    net.nodes[0].lock().unwrap().submit_tx(bad_tx).unwrap();
    let block = net.nodes[0].lock().unwrap().on_propose(0);

    // Tamper with height
    let mut bad_block = block;
    bad_block.header = zk_vault_chain::types::BlockHeader {
        height: zk_vault_chain::types::Height(99),
        ..bad_block.header
    };

    let result = net.nodes[1].lock().unwrap().on_decided(bad_block);
    assert!(result.is_err());

    // Node 1 state should still be at height 1
    let n1 = net.nodes[1].lock().unwrap();
    assert_eq!(n1.height().0, 1);
    assert_eq!(n1.state().file_count(), 1);
}

/// E2E Mode B: RegisterFile + upload_data → propose → download_data → verify round-trip
#[tokio::test]
async fn e2e_mode_b_upload_download() {
    use base64::Engine;

    let net = TestNetwork::spawn(3).await;
    let client = reqwest::Client::new();
    let (sk, pk) = &net.keys[0];
    let base = &net.urls[0];

    // 1. Register file on chain
    let merkle_root = [0xF0; 32];
    let file_count = 2u32;
    let encrypted_size = 2048u64;
    let sig = sk.sign(&merkle_root);
    let tx = serde_json::json!({
        "RegisterFile": {
            "merkle_root": merkle_root,
            "file_count": file_count,
            "encrypted_size": encrypted_size,
            "owner_pk": *pk,
            "signature": sig.to_bytes().to_vec(),
        }
    });
    let submit_resp = client
        .post(format!("{base}/submit_tx"))
        .json(&rpc::SubmitTxRequest {
            tx_json: tx.to_string(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(submit_resp.status(), 200);

    // 2. Upload encrypted data blobs (simulating CLI backup --chain)
    let blob1_data: Vec<u8> = [0xDE, 0xAD, 0xBE, 0xEF]
        .iter()
        .copied()
        .cycle()
        .take(256)
        .collect();
    let blob2_data: Vec<u8> = [0xCA, 0xFE, 0xBA, 0xBE]
        .iter()
        .copied()
        .cycle()
        .take(512)
        .collect();
    let blob1_b64 = base64::engine::general_purpose::STANDARD.encode(&blob1_data);
    let blob2_b64 = base64::engine::general_purpose::STANDARD.encode(&blob2_data);

    let resp = client
        .post(format!("{base}/upload_data"))
        .json(&rpc::UploadDataRequest {
            key: "user1/file-a".to_string(),
            data_b64: blob1_b64,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let upload: rpc::UploadDataResponse = resp.json().await.unwrap();
    assert_eq!(upload.size, 256);

    let resp = client
        .post(format!("{base}/upload_data"))
        .json(&rpc::UploadDataRequest {
            key: "user1/file-b".to_string(),
            data_b64: blob2_b64,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 3. Propose and broadcast
    net.propose_and_broadcast();

    // 4. Verify file registered on chain
    let file_resp = client
        .post(format!("{base}/get_file"))
        .json(&rpc::GetFileRequest {
            merkle_root: hex::encode(merkle_root),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(file_resp.status(), 200);
    let file: rpc::FileResponse = file_resp.json().await.unwrap();
    assert_eq!(file.file_count, file_count);
    assert_eq!(file.encrypted_size, encrypted_size);

    // 5. Download blobs from a DIFFERENT node (simulating CLI restore --chain)
    let node2_base = &net.urls[0]; // same node since blobs aren't replicated yet

    let resp = client
        .post(format!("{node2_base}/download_data"))
        .json(&rpc::DownloadDataRequest {
            key: "user1/file-a".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let download: rpc::DownloadDataResponse = resp.json().await.unwrap();
    assert_eq!(download.size, 256);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&download.data_b64)
        .unwrap();
    assert_eq!(decoded, blob1_data);

    let resp = client
        .post(format!("{node2_base}/download_data"))
        .json(&rpc::DownloadDataRequest {
            key: "user1/file-b".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let download: rpc::DownloadDataResponse = resp.json().await.unwrap();
    assert_eq!(download.size, 512);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&download.data_b64)
        .unwrap();
    assert_eq!(decoded, blob2_data);

    // 6. List blobs
    let resp: rpc::ListDataResponse = client
        .get(format!("{node2_base}/list_data"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.keys.len(), 2);
    assert_eq!(resp.total_size, 768); // 256 + 512

    // 7. Final status
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
}

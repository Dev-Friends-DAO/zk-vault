//! Integration tests: 3-node local network simulation.
//!
//! Each node has its own RPC server. Blocks are broadcast manually
//! between nodes (simulating what Malachite consensus would do).
//! Also includes consensus driver tests for BFT round simulation.

use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use zk_vault_chain::mempool::MempoolConfig;
use zk_vault_chain::node::{Node, NodeConfig};
use zk_vault_chain::rpc::{self, SharedNode, StatusResponse, SubmitTxRequest, SubmitTxResponse};
use zk_vault_chain::storage::Storage;
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
    /// Keep temp directories alive for the lifetime of the network.
    _dirs: Vec<tempfile::TempDir>,
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
        let mut dirs = Vec::new();

        for (_, pk) in &keys {
            let config = NodeConfig {
                validator_address: Address::from_public_key(pk),
                validator_pk: *pk,
                mempool_config: MempoolConfig::default(),
            };
            let dir = tempfile::tempdir().unwrap();
            let storage = Arc::new(Storage::open(dir.path()).unwrap());
            let node = Arc::new(Mutex::new(Node::new(vs.clone(), config, storage)));
            let app = rpc::router(node.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            nodes.push(node);
            urls.push(format!("http://{addr}"));
            dirs.push(dir);
        }

        Self {
            nodes,
            urls,
            keys,
            _dirs: dirs,
        }
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

/// Super Merkle Tree batching: multiple users → single super root for anchoring
#[tokio::test]
async fn anchor_status_super_merkle_tree() {
    let net = TestNetwork::spawn(3).await;
    let client = reqwest::Client::new();
    let base = &net.urls[0];

    // Each validator registers a file
    for (i, (sk, pk)) in net.keys.iter().enumerate() {
        let mut root = [0u8; 32];
        root[0] = (i + 1) as u8;
        let tx = make_register_tx(sk, pk, root);
        // Submit all to node 0
        net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
    }
    net.propose_and_broadcast();

    // All nodes should have 3 files
    for node in &net.nodes {
        assert_eq!(node.lock().unwrap().state().file_count(), 3);
    }

    // Query anchor_status from any node
    let resp: rpc::AnchorStatusResponse = client
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

    // All nodes should produce the same super root
    let mut super_roots = Vec::new();
    for url in &net.urls {
        let resp: rpc::AnchorStatusResponse = client
            .get(format!("{url}/anchor_status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        super_roots.push(resp.super_root.unwrap());
    }
    assert_eq!(super_roots[0], super_roots[1]);
    assert_eq!(super_roots[1], super_roots[2]);

    // Super root is what would be anchored to BTC/ETH
    let super_root_hex = &super_roots[0];
    assert_eq!(super_root_hex.len(), 64); // 32 bytes = 64 hex chars
}

// ── I9: Consensus Driver Integration Tests ──

/// Simulates 3-node BFT consensus using channels (no actual P2P).
/// Validates: proposal broadcast, prevote/precommit signature verification,
/// quorum detection, and state consistency across all nodes.
#[tokio::test]
async fn consensus_driver_three_node_bft_round() {
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};
    use zk_vault_chain::consensus::driver::{ConsensusConfig, ConsensusDriver};
    use zk_vault_chain::consensus::engine::PoaEngine;
    use zk_vault_chain::p2p::message::ConsensusMessage;
    use zk_vault_chain::p2p::transport::{P2pCommand, P2pEvent, P2pHandle};
    use zk_vault_chain::types::{Address, Height};

    let keys: Vec<_> = (1..=3u8).map(make_keypair).collect();
    let validators: Vec<_> = keys
        .iter()
        .map(|(_, pk)| zk_vault_chain::types::Validator::new(*pk, 100))
        .collect();
    let vs = ValidatorSet::new(validators);

    // Create 3 nodes with shared validator set
    struct TestNode {
        driver: Option<ConsensusDriver>,
        node: Arc<RwLock<zk_vault_chain::node::Node>>,
        _event_tx: mpsc::Sender<P2pEvent>,
        cmd_rx: mpsc::Receiver<P2pCommand>,
        _dir: tempfile::TempDir,
    }

    let mut test_nodes: Vec<TestNode> = Vec::new();

    for (sk, pk) in &keys {
        let config = zk_vault_chain::node::NodeConfig {
            validator_address: Address::from_public_key(pk),
            validator_pk: *pk,
            mempool_config: zk_vault_chain::mempool::MempoolConfig::default(),
        };
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(dir.path()).unwrap());
        let node = Arc::new(RwLock::new(zk_vault_chain::node::Node::new(
            vs.clone(),
            config,
            storage,
        )));
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (event_tx, _event_rx) = mpsc::channel(256);
        let p2p = P2pHandle::new(cmd_tx);
        let engine = PoaEngine::new(vs.clone());

        let driver = ConsensusDriver::new(
            Arc::clone(&node),
            p2p,
            Box::new(engine),
            sk.clone(),
            ConsensusConfig {
                propose_timeout: std::time::Duration::from_secs(30),
                prevote_timeout: std::time::Duration::from_secs(30),
                precommit_timeout: std::time::Duration::from_secs(30),
                timeout_delta: std::time::Duration::from_millis(0),
            },
        );

        // We'll drive manually, not via run()
        test_nodes.push(TestNode {
            driver: Some(driver),
            node,
            _event_tx: event_tx,
            cmd_rx,
            _dir: dir,
        });
    }

    // Determine who is proposer at height 1, round 0
    // Formula: (height.0 + round.0) % validator_count
    let proposer_idx = 1usize;

    // Submit a tx to the proposer's mempool
    {
        let (sk, pk) = &keys[0];
        let tx = make_register_tx(sk, pk, [0xAA; 32]);
        let mut node = test_nodes[proposer_idx].node.write().await;
        node.submit_tx(tx).unwrap();
    }
    // The proposer enters new round and proposes
    let proposer = test_nodes[proposer_idx].driver.as_mut().unwrap();
    proposer.enter_new_round().await;

    // Drain the proposer's command channel to get the broadcast messages
    let mut proposal_msg = None;
    let mut proposer_prevote = None;
    while let Ok(cmd) = test_nodes[proposer_idx].cmd_rx.try_recv() {
        match cmd {
            P2pCommand::BroadcastConsensus(ConsensusMessage::Proposal(p)) => {
                proposal_msg = Some(ConsensusMessage::Proposal(p));
            }
            P2pCommand::BroadcastConsensus(ConsensusMessage::Prevote(v)) => {
                proposer_prevote = Some(ConsensusMessage::Prevote(v));
            }
            _ => {}
        }
    }
    assert!(
        proposal_msg.is_some(),
        "Proposer should broadcast a proposal"
    );
    assert!(
        proposer_prevote.is_some(),
        "Proposer should broadcast a prevote"
    );

    // Step 2: Deliver the proposal to other nodes
    for (i, tn) in test_nodes.iter_mut().enumerate() {
        if i == proposer_idx {
            continue;
        }
        let driver = tn.driver.as_mut().unwrap();
        driver
            .handle_event(P2pEvent::ConsensusMsg(proposal_msg.clone().unwrap()))
            .await;
        driver.drive_state().await;
    }

    // Collect prevotes from all non-proposer nodes
    let mut all_prevotes = vec![proposer_prevote.unwrap()];
    for (i, tn) in test_nodes.iter_mut().enumerate() {
        if i == proposer_idx {
            continue;
        }
        while let Ok(cmd) = tn.cmd_rx.try_recv() {
            if let P2pCommand::BroadcastConsensus(msg @ ConsensusMessage::Prevote(_)) = cmd {
                all_prevotes.push(msg);
            }
        }
    }
    assert_eq!(all_prevotes.len(), 3, "All 3 nodes should prevote");

    // Step 3: Deliver all prevotes to all nodes
    for tn in &mut test_nodes {
        let driver = tn.driver.as_mut().unwrap();
        for prevote in &all_prevotes {
            driver
                .handle_event(P2pEvent::ConsensusMsg(prevote.clone()))
                .await;
        }
        driver.drive_state().await;
    }

    // Collect precommits
    let mut all_precommits = Vec::new();
    for tn in &mut test_nodes {
        while let Ok(cmd) = tn.cmd_rx.try_recv() {
            if let P2pCommand::BroadcastConsensus(msg @ ConsensusMessage::Precommit(_)) = cmd {
                all_precommits.push(msg);
            }
        }
    }
    assert_eq!(all_precommits.len(), 3, "All 3 nodes should precommit");

    // Step 4: Deliver all precommits to all nodes
    for tn in &mut test_nodes {
        let driver = tn.driver.as_mut().unwrap();
        for precommit in &all_precommits {
            driver
                .handle_event(P2pEvent::ConsensusMsg(precommit.clone()))
                .await;
        }
        driver.drive_state().await;
        // Drain remaining commands (block announce, etc.)
        while tn.cmd_rx.try_recv().is_ok() {}
    }

    // Step 5: Verify all nodes committed the same block
    let mut heights = Vec::new();
    let mut state_roots = Vec::new();
    let mut file_counts = Vec::new();

    for tn in &test_nodes {
        let node = tn.node.read().await;
        heights.push(node.height());
        state_roots.push(node.state_root());
        file_counts.push(node.state().file_count());
    }

    // All nodes at height 1
    for h in &heights {
        assert_eq!(*h, Height(1), "All nodes should be at height 1");
    }

    // Only the proposer's node had the tx in mempool, so it should have
    // been included in the block. All nodes apply the same block.
    for fc in &file_counts {
        assert_eq!(
            *fc, 1,
            "All nodes should have 1 file after committing the block"
        );
    }

    // State roots identical
    assert_eq!(state_roots[0], state_roots[1]);
    assert_eq!(state_roots[1], state_roots[2]);
}

/// Test that ConsensusDriver rejects proposals with invalid signatures.
#[tokio::test]
async fn consensus_driver_rejects_invalid_proposal_signature() {
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};
    use zk_vault_chain::consensus::driver::{ConsensusConfig, ConsensusDriver};
    use zk_vault_chain::consensus::engine::PoaEngine;
    use zk_vault_chain::p2p::message::{ConsensusMessage, Proposal};
    use zk_vault_chain::p2p::transport::{P2pEvent, P2pHandle};
    use zk_vault_chain::types::{Address, Block, Height, Round};

    let keys: Vec<_> = (1..=3u8).map(make_keypair).collect();
    let validators: Vec<_> = keys
        .iter()
        .map(|(_, pk)| zk_vault_chain::types::Validator::new(*pk, 100))
        .collect();
    let vs = ValidatorSet::new(validators);

    let (sk, pk) = &keys[0];
    let config = zk_vault_chain::node::NodeConfig {
        validator_address: Address::from_public_key(pk),
        validator_pk: *pk,
        mempool_config: zk_vault_chain::mempool::MempoolConfig::default(),
    };
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(Storage::open(dir.path()).unwrap());
    let node = Arc::new(RwLock::new(zk_vault_chain::node::Node::new(
        vs.clone(),
        config,
        storage,
    )));
    let (cmd_tx, mut cmd_rx) = mpsc::channel(256);
    let p2p = P2pHandle::new(cmd_tx);
    let engine = PoaEngine::new(vs.clone());

    let mut driver = ConsensusDriver::new(
        Arc::clone(&node),
        p2p,
        Box::new(engine),
        sk.clone(),
        ConsensusConfig::default(),
    );

    // Create a proposal with invalid signature from the correct proposer
    let proposer_idx = 1usize;
    let proposer_addr = Address::from_public_key(&keys[proposer_idx].1);

    let fake_proposal = Proposal {
        height: Height(1),
        round: Round::ZERO,
        block: Block::genesis(&vs),
        pol_round: None,
        proposer: proposer_addr,
        signature: vec![0u8; 64], // invalid signature
    };

    // Deliver the fake proposal
    driver
        .handle_event(P2pEvent::ConsensusMsg(ConsensusMessage::Proposal(
            fake_proposal,
        )))
        .await;
    driver.drive_state().await;

    // The driver should NOT have prevoted (no commands emitted)
    assert!(
        cmd_rx.try_recv().is_err(),
        "Should not prevote for invalid proposal"
    );
}

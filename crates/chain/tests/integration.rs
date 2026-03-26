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
                replication_factor: 3,
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
            replication_factor: 3,
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
        replication_factor: 3,
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

/// J7: Blob replication and retrieval after node failure.
///
/// Tests the full Mode B replication flow:
/// 1. Upload blob to node 0
/// 2. Simulate replication to nodes 1 and 2 (direct blob copy)
/// 3. Verify all nodes have the blob
/// 4. "Stop" node 0 (don't query it)
/// 5. Successfully retrieve from nodes 1 and 2
#[tokio::test]
async fn blob_replication_and_retrieval_after_node_failure() {
    use base64::Engine;

    let net = TestNetwork::spawn(3).await;
    let client = reqwest::Client::new();

    // 1. Upload blob to node 0
    let blob_data: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&blob_data);

    let resp = client
        .post(format!("{}/upload_data", net.urls[0]))
        .json(&rpc::UploadDataRequest {
            key: "repl-test-blob".to_string(),
            data_b64: data_b64.clone(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let upload: rpc::UploadDataResponse = resp.json().await.unwrap();
    assert_eq!(upload.size, 256);

    // 2. Simulate replication: copy blob from node 0 to nodes 1 and 2
    {
        let data = net.nodes[0]
            .lock()
            .unwrap()
            .get_blob("repl-test-blob")
            .unwrap()
            .unwrap();
        net.nodes[1]
            .lock()
            .unwrap()
            .put_blob("repl-test-blob".to_string(), data.clone())
            .unwrap();
        net.nodes[2]
            .lock()
            .unwrap()
            .put_blob("repl-test-blob".to_string(), data)
            .unwrap();
    }

    // 3. Verify all nodes have the blob via RPC
    for url in &net.urls {
        let resp = client
            .post(format!("{url}/download_data"))
            .json(&rpc::DownloadDataRequest {
                key: "repl-test-blob".to_string(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let download: rpc::DownloadDataResponse = resp.json().await.unwrap();
        assert_eq!(download.size, 256);
    }

    // 4. "Stop" node 0 — simulate failure by only querying nodes 1 and 2

    // 5. Retrieve from node 1
    let resp = client
        .post(format!("{}/download_data", net.urls[1]))
        .json(&rpc::DownloadDataRequest {
            key: "repl-test-blob".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let download: rpc::DownloadDataResponse = resp.json().await.unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&download.data_b64)
        .unwrap();
    assert_eq!(decoded, blob_data, "Node 1 should return identical data");

    // 6. Retrieve from node 2
    let resp = client
        .post(format!("{}/download_data", net.urls[2]))
        .json(&rpc::DownloadDataRequest {
            key: "repl-test-blob".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let download: rpc::DownloadDataResponse = resp.json().await.unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&download.data_b64)
        .unwrap();
    assert_eq!(decoded, blob_data, "Node 2 should return identical data");

    // 7. Verify blob is NOT on a non-existent key
    let resp = client
        .post(format!("{}/download_data", net.urls[1]))
        .json(&rpc::DownloadDataRequest {
            key: "nonexistent-blob".to_string(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// J7: Storage attestation transaction round-trip.
///
/// Tests that UpdateStorageStatus transactions are properly processed:
/// 1. Validator submits UpdateStorageStatus tx
/// 2. After block commit, blob_replicas state is updated
#[tokio::test]
async fn storage_attestation_tx_roundtrip() {
    let net = TestNetwork::spawn(3).await;
    let (sk, pk) = &net.keys[0];

    // Submit UpdateStorageStatus tx
    let blob_key = "user1/backup-001";
    let mut msg = Vec::new();
    msg.extend_from_slice(b"zk-vault:storage-status:");
    msg.extend_from_slice(blob_key.as_bytes());
    msg.push(1u8); // holds_blob = true
    let msg_hash = blake3::hash(&msg);
    let sig = sk.sign(msg_hash.as_bytes());

    let tx = Transaction::UpdateStorageStatus {
        blob_key: blob_key.to_string(),
        validator_pk: *pk,
        holds_blob: true,
        signature: sig.to_bytes().to_vec(),
    };

    net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
    net.propose_and_broadcast();

    // Verify blob_replicas state on all nodes
    for node in &net.nodes {
        let n = node.lock().unwrap();
        let state = n.state();
        let replicas = state.blob_replicas.get("user1/backup-001");
        assert!(replicas.is_some(), "blob_replicas should have the entry");
        assert!(
            replicas.unwrap().contains(pk),
            "validator pk should be in replicas"
        );
    }

    // Verify state roots match across all nodes
    let roots: Vec<_> = net
        .nodes
        .iter()
        .map(|n| n.lock().unwrap().state_root())
        .collect();
    assert_eq!(roots[0], roots[1]);
    assert_eq!(roots[1], roots[2]);
}

/// J5: Block history store round-trip.
///
/// Tests that committed blocks are persisted and retrievable.
#[tokio::test]
async fn block_history_store_roundtrip() {
    let net = TestNetwork::spawn(3).await;
    let (sk, pk) = &net.keys[0];

    // Commit 3 blocks
    for i in 0..3u8 {
        let mut root = [0u8; 32];
        root[0] = i + 100;
        let tx = make_register_tx(sk, pk, root);
        net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
        net.propose_and_broadcast();
    }

    // Verify all nodes are at height 3
    for node in &net.nodes {
        assert_eq!(node.lock().unwrap().height().0, 3);
    }

    // Retrieve blocks from history on node 0
    let n = net.nodes[0].lock().unwrap();
    for h in 1..=3u64 {
        let block = n.get_block(zk_vault_chain::types::Height(h)).unwrap();
        assert!(block.is_some(), "Block at height {h} should exist");
        let block = block.unwrap();
        assert_eq!(block.header.height.0, h);
        assert_eq!(block.transactions.len(), 1);
    }

    // Block at height 0 (genesis) was not stored via on_decided
    let genesis = n.get_block(zk_vault_chain::types::Height(0)).unwrap();
    assert!(
        genesis.is_none(),
        "Genesis block is not stored via on_decided"
    );

    // Block at height 99 doesn't exist
    let missing = n.get_block(zk_vault_chain::types::Height(99)).unwrap();
    assert!(missing.is_none());
}

/// K1/K5: AnchorMerkleRoot transaction round-trip.
///
/// Tests that AnchorMerkleRoot transactions are properly processed
/// and anchor history is updated in ChainState.
#[tokio::test]
async fn anchor_merkle_root_tx_roundtrip() {
    let net = TestNetwork::spawn(3).await;
    let (sk, pk) = &net.keys[0];

    // First register some files to have a non-empty registry
    for i in 0..3u8 {
        let mut root = [0u8; 32];
        root[0] = i + 200;
        let tx = make_register_tx(sk, pk, root);
        net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
    }
    net.propose_and_broadcast();

    // Compute Super Merkle Root (same logic as anchor_status RPC)
    let super_root = {
        let n = net.nodes[0].lock().unwrap();
        let state = n.state();
        let leaf_hashes: Vec<[u8; 32]> = state.file_registry.keys().copied().collect();
        let tree = zk_vault_core::merkle::tree::MerkleTree::from_leaf_hashes(leaf_hashes);
        tree.root().unwrap()
    };

    // Submit AnchorMerkleRoot tx
    let epoch = 1u64;
    let mut msg = Vec::new();
    msg.extend_from_slice(b"zk-vault:anchor:");
    msg.extend_from_slice(&super_root);
    msg.extend_from_slice(&epoch.to_le_bytes());
    let msg_hash = blake3::hash(&msg);
    let sig = sk.sign(msg_hash.as_bytes());

    let tx = Transaction::AnchorMerkleRoot {
        super_root,
        epoch,
        btc_tx_id: Some("btc_test_txid_abc123".to_string()),
        eth_tx_id: Some("0xeth_test_txid_def456".to_string()),
        file_count: 3,
        anchor_validator_pk: *pk,
        signature: sig.to_bytes().to_vec(),
    };

    net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
    net.propose_and_broadcast();

    // Verify anchor history on all nodes
    for node in &net.nodes {
        let n = node.lock().unwrap();
        let state = n.state();
        let entry = state.anchor_history.get(&1u64);
        assert!(entry.is_some(), "Anchor entry should exist for epoch 1");

        let entry = entry.unwrap();
        assert_eq!(entry.super_root, super_root);
        assert_eq!(entry.epoch, 1);
        assert_eq!(entry.btc_tx_id.as_deref(), Some("btc_test_txid_abc123"));
        assert_eq!(entry.eth_tx_id.as_deref(), Some("0xeth_test_txid_def456"));
        assert_eq!(entry.file_count, 3);
        assert_eq!(entry.anchor_validator_pk, *pk);
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

/// K: Anchor service epoch boundary detection and round-robin.
#[tokio::test]
async fn anchor_service_epoch_scheduling() {
    use zk_vault_chain::anchor_service::{AnchorConfig, AnchorService};

    let keys: Vec<_> = (1..=3u8).map(make_keypair).collect();
    let validators: Vec<Validator> = keys
        .iter()
        .map(|(_, pk)| Validator::new(*pk, 100))
        .collect();
    let vs = ValidatorSet::new(validators);

    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(Storage::open(dir.path()).unwrap());
    let config = zk_vault_chain::node::NodeConfig {
        validator_address: Address::from_public_key(&keys[0].1),
        validator_pk: keys[0].1,
        mempool_config: zk_vault_chain::mempool::MempoolConfig::default(),
        replication_factor: 3,
    };
    let node = Arc::new(tokio::sync::RwLock::new(zk_vault_chain::node::Node::new(
        vs, config, storage,
    )));

    let anchor_config = AnchorConfig {
        epoch_length: 5,
        btc_config: None,
        eth_config: Some(zk_vault_core::anchor::ethereum::EthereumConfig {
            rpc_url: "http://localhost:1".to_string(),
            network: "test".to_string(),
            private_key_hex: "01".repeat(32),
            chain_id: 1,
        }),
    };

    let svc0 = AnchorService::new(Arc::clone(&node), keys[0].0.clone(), anchor_config.clone());
    let svc1 = AnchorService::new(Arc::clone(&node), keys[1].0.clone(), anchor_config.clone());
    let svc2 = AnchorService::new(Arc::clone(&node), keys[2].0.clone(), anchor_config);

    // Epoch 1 (height 5): 1 % 3 = 1 → validator 1
    assert!(!svc0.is_anchor_validator(zk_vault_chain::types::Height(5)));
    assert!(svc1.is_anchor_validator(zk_vault_chain::types::Height(5)));
    assert!(!svc2.is_anchor_validator(zk_vault_chain::types::Height(5)));

    // Epoch 2 (height 10): 2 % 3 = 2 → validator 2
    assert!(!svc0.is_anchor_validator(zk_vault_chain::types::Height(10)));
    assert!(!svc1.is_anchor_validator(zk_vault_chain::types::Height(10)));
    assert!(svc2.is_anchor_validator(zk_vault_chain::types::Height(10)));

    // Epoch 3 (height 15): 3 % 3 = 0 → validator 0
    assert!(svc0.is_anchor_validator(zk_vault_chain::types::Height(15)));

    // Non-epoch heights should never be anchor validators
    assert!(!svc0.is_anchor_validator(zk_vault_chain::types::Height(7)));
    assert!(!svc1.is_anchor_validator(zk_vault_chain::types::Height(3)));
}

/// K: Anchor list RPC endpoint.
#[tokio::test]
async fn anchor_list_rpc() {
    let net = TestNetwork::spawn(3).await;
    let client = reqwest::Client::new();
    let (sk, pk) = &net.keys[0];
    let base = &net.urls[0];

    // Register a file and propose
    let tx = make_register_tx(sk, pk, [0xAA; 32]);
    net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
    net.propose_and_broadcast();

    // Submit an anchor tx
    let super_root = {
        let n = net.nodes[0].lock().unwrap();
        let state = n.state();
        let leaf_hashes: Vec<[u8; 32]> = state.file_registry.keys().copied().collect();
        let tree = zk_vault_core::merkle::tree::MerkleTree::from_leaf_hashes(leaf_hashes);
        tree.root().unwrap()
    };

    let epoch = 1u64;
    let mut msg = Vec::new();
    msg.extend_from_slice(b"zk-vault:anchor:");
    msg.extend_from_slice(&super_root);
    msg.extend_from_slice(&epoch.to_le_bytes());
    let msg_hash = blake3::hash(&msg);
    let sig = sk.sign(msg_hash.as_bytes());

    let anchor_tx = Transaction::AnchorMerkleRoot {
        super_root,
        epoch,
        btc_tx_id: Some("test_btc_tx".to_string()),
        eth_tx_id: None,
        file_count: 1,
        anchor_validator_pk: *pk,
        signature: sig.to_bytes().to_vec(),
    };
    net.nodes[0].lock().unwrap().submit_tx(anchor_tx).unwrap();
    net.propose_and_broadcast();

    // Query list_anchors
    let resp: rpc::ListAnchorsResponse = client
        .get(format!("{base}/list_anchors"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.total, 1);
    assert_eq!(resp.anchors[0].epoch, 1);
    assert_eq!(resp.anchors[0].btc_tx_id.as_deref(), Some("test_btc_tx"));
    assert!(resp.anchors[0].eth_tx_id.is_none());
    assert_eq!(resp.anchors[0].file_count, 1);

    // Query get_anchor for specific epoch
    let resp: rpc::GetAnchorResponse = client
        .post(format!("{base}/get_anchor"))
        .json(&rpc::GetAnchorRequest { epoch: Some(1) })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.epoch, 1);
    assert_eq!(resp.super_root, hex::encode(super_root));
}

/// L: RenewDeal transaction round-trip.
///
/// Tests that RenewDeal transactions are properly processed
/// and the deal registry is updated in ChainState.
#[tokio::test]
async fn renew_deal_tx_roundtrip() {
    let net = TestNetwork::spawn(3).await;
    let (sk, pk) = &net.keys[0];

    // First register a file
    let merkle_root = [0xF1; 32];
    let tx = make_register_tx(sk, pk, merkle_root);
    net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
    net.propose_and_broadcast();

    // Submit a RenewDeal tx (initial deal, not renewal)
    let data_cid = "bafytest123456";
    let deal_id = 12345u64;

    let mut msg = Vec::new();
    msg.extend_from_slice(b"zk-vault:deal:");
    msg.extend_from_slice(data_cid.as_bytes());
    msg.extend_from_slice(&deal_id.to_le_bytes());
    let msg_hash = blake3::hash(&msg);
    let sig = sk.sign(msg_hash.as_bytes());

    let tx = Transaction::RenewDeal {
        data_cid: data_cid.to_string(),
        deal_id,
        provider: "f01234".to_string(),
        end_epoch: 2880000, // ~540 days at 30s epochs
        is_renewal: false,
        merkle_root,
        validator_pk: *pk,
        signature: sig.to_bytes().to_vec(),
    };

    net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
    net.propose_and_broadcast();

    // Verify deal registry on all nodes
    for node in &net.nodes {
        let n = node.lock().unwrap();
        let deals = n.get_deals("bafytest123456");
        assert!(deals.is_some(), "Deal should exist");
        let deals = deals.unwrap();
        assert_eq!(deals.len(), 1);
        assert_eq!(deals[0].deal_id, 12345);
        assert_eq!(deals[0].provider, "f01234");
        assert_eq!(deals[0].end_epoch, 2880000);
        assert!(!deals[0].is_renewal);
    }

    // Submit a renewal for the same CID
    let new_deal_id = 67890u64;
    let mut msg2 = Vec::new();
    msg2.extend_from_slice(b"zk-vault:deal:");
    msg2.extend_from_slice(data_cid.as_bytes());
    msg2.extend_from_slice(&new_deal_id.to_le_bytes());
    let msg2_hash = blake3::hash(&msg2);
    let sig2 = sk.sign(msg2_hash.as_bytes());

    let renewal_tx = Transaction::RenewDeal {
        data_cid: data_cid.to_string(),
        deal_id: new_deal_id,
        provider: "f05678".to_string(),
        end_epoch: 5760000,
        is_renewal: true,
        merkle_root,
        validator_pk: *pk,
        signature: sig2.to_bytes().to_vec(),
    };

    net.nodes[0].lock().unwrap().submit_tx(renewal_tx).unwrap();
    net.propose_and_broadcast();

    // Now should have 2 deals for the same CID
    for node in &net.nodes {
        let n = node.lock().unwrap();
        let deals = n.get_deals("bafytest123456").unwrap();
        assert_eq!(deals.len(), 2);
        assert!(!deals[0].is_renewal);
        assert!(deals[1].is_renewal);
        assert_eq!(deals[1].deal_id, 67890);
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

/// L: Deal list RPC endpoint.
#[tokio::test]
async fn deal_list_rpc() {
    let net = TestNetwork::spawn(3).await;
    let client = reqwest::Client::new();
    let (sk, pk) = &net.keys[0];
    let base = &net.urls[0];

    // Register a file
    let merkle_root = [0xF2; 32];
    let tx = make_register_tx(sk, pk, merkle_root);
    net.nodes[0].lock().unwrap().submit_tx(tx).unwrap();
    net.propose_and_broadcast();

    // Create a deal
    let data_cid = "bafytest_rpc_deal";
    let deal_id = 99999u64;
    let mut msg = Vec::new();
    msg.extend_from_slice(b"zk-vault:deal:");
    msg.extend_from_slice(data_cid.as_bytes());
    msg.extend_from_slice(&deal_id.to_le_bytes());
    let msg_hash = blake3::hash(&msg);
    let sig = sk.sign(msg_hash.as_bytes());

    let deal_tx = Transaction::RenewDeal {
        data_cid: data_cid.to_string(),
        deal_id,
        provider: "f09999".to_string(),
        end_epoch: 1000000,
        is_renewal: false,
        merkle_root,
        validator_pk: *pk,
        signature: sig.to_bytes().to_vec(),
    };
    net.nodes[0].lock().unwrap().submit_tx(deal_tx).unwrap();
    net.propose_and_broadcast();

    // Query list_deals
    let resp: rpc::ListDealsResponse = client
        .get(format!("{base}/list_deals"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.total, 1);
    assert_eq!(resp.deals[0].deal_id, 99999);
    assert_eq!(resp.deals[0].provider, "f09999");

    // Query get_deals for specific CID
    let resp: rpc::GetDealsResponse = client
        .post(format!("{base}/get_deals"))
        .json(&rpc::GetDealsRequest {
            data_cid: data_cid.to_string(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp.deals.len(), 1);
    assert_eq!(resp.deals[0].data_cid, data_cid);
}

/// L: DealMonitor detects expiring deals.
#[tokio::test]
async fn deal_monitor_detects_expiry() {
    use zk_vault_chain::deal_monitor::{DealMonitor, DealMonitorConfig};

    let keys: Vec<_> = (1..=3u8).map(make_keypair).collect();
    let validators: Vec<Validator> = keys
        .iter()
        .map(|(_, pk)| Validator::new(*pk, 100))
        .collect();
    let vs = ValidatorSet::new(validators);

    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(Storage::open(dir.path()).unwrap());
    let config = zk_vault_chain::node::NodeConfig {
        validator_address: Address::from_public_key(&keys[0].1),
        validator_pk: keys[0].1,
        mempool_config: zk_vault_chain::mempool::MempoolConfig::default(),
        replication_factor: 3,
    };
    let node = Arc::new(tokio::sync::RwLock::new(zk_vault_chain::node::Node::new(
        vs, config, storage,
    )));

    // Register a file and commit
    {
        let (sk, pk) = &keys[0];
        let merkle_root = [0xDD; 32];
        let sig = sk.sign(&merkle_root);
        let tx = Transaction::RegisterFile {
            merkle_root,
            file_count: 1,
            encrypted_size: 100,
            owner_pk: *pk,
            signature: sig.to_bytes().to_vec(),
        };
        let mut n = node.write().await;
        n.submit_tx(tx).unwrap();
        let block = n.on_propose(0);
        n.on_decided(block).unwrap();
    }

    // Add a deal that is about to expire (end_epoch = 1100, current = 1000)
    {
        let (sk, pk) = &keys[0];
        let data_cid = "bafyexpiring";
        let deal_id = 555u64;
        let mut msg = Vec::new();
        msg.extend_from_slice(b"zk-vault:deal:");
        msg.extend_from_slice(data_cid.as_bytes());
        msg.extend_from_slice(&deal_id.to_le_bytes());
        let msg_hash = blake3::hash(&msg);
        let sig = sk.sign(msg_hash.as_bytes());

        let tx = Transaction::RenewDeal {
            data_cid: data_cid.to_string(),
            deal_id,
            provider: "f0555".to_string(),
            end_epoch: 1100,
            is_renewal: false,
            merkle_root: [0xDD; 32],
            validator_pk: *pk,
            signature: sig.to_bytes().to_vec(),
        };
        let mut n = node.write().await;
        n.submit_tx(tx).unwrap();
        let block = n.on_propose(0);
        n.on_decided(block).unwrap();
    }

    // Create DealMonitor with renew_before_epochs = 200
    let monitor = DealMonitor::new(
        node.clone(),
        keys[0].0.clone(),
        DealMonitorConfig {
            check_interval_blocks: 10,
            renew_before_epochs: 200,
        },
    );

    // Check at current_filecoin_epoch = 1000 (remaining = 100, < 200 threshold)
    let needs_renewal = monitor.check_deals(1000).await;
    assert_eq!(needs_renewal.len(), 1);
    assert_eq!(needs_renewal[0], "bafyexpiring");

    // Check at epoch 500 (remaining = 600, > 200 threshold)
    let needs_renewal = monitor.check_deals(500).await;
    assert!(needs_renewal.is_empty());
}

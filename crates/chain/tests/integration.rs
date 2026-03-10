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

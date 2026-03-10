//! Single-node chain for local development and manual testing.
//!
//! Usage:
//!   cargo run -p zk-vault-chain --example local_node
//!
//! Then interact with curl:
//!   curl http://localhost:3030/health
//!   curl http://localhost:3030/status
//!
//! See printed instructions for submit_tx and propose examples.

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use zk_vault_chain::mempool::MempoolConfig;
use zk_vault_chain::node::{Node, NodeConfig};
use zk_vault_chain::rpc;
use zk_vault_chain::types::{Address, Validator, ValidatorSet};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt().with_env_filter("info").init();

    // Generate 3 validator keypairs (deterministic seeds for reproducibility)
    let keys: Vec<(SigningKey, [u8; 32])> = (1..=3u8)
        .map(|seed| {
            let mut secret = [0u8; 32];
            secret[0] = seed;
            let sk = SigningKey::from_bytes(&secret);
            let pk = sk.verifying_key().to_bytes();
            (sk, pk)
        })
        .collect();

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
    let addr = "127.0.0.1:3030";

    // Print example transaction for copy-paste
    let (sk, pk) = &keys[0];
    let merkle_root = [0xAB; 32];
    let sig = ed25519_dalek::Signer::sign(sk, &merkle_root);
    let tx = zk_vault_chain::types::Transaction::RegisterFile {
        merkle_root,
        file_count: 5,
        encrypted_size: 10240,
        owner_pk: *pk,
        signature: sig.to_bytes().to_vec(),
    };
    let tx_json = serde_json::to_string(&tx).unwrap();

    println!();
    println!("========================================");
    println!("  zk-vault chain node (local dev mode)");
    println!("========================================");
    println!();
    println!("RPC: http://{addr}");
    println!();
    println!("--- Try these commands ---");
    println!();
    println!("# Health check");
    println!("curl {addr}/health");
    println!();
    println!("# Node status");
    println!("curl -s {addr}/status | jq");
    println!();
    println!("# Submit a transaction");
    println!(
        "curl -s -X POST {addr}/submit_tx -H 'Content-Type: application/json' -d '{}' | jq",
        serde_json::to_string(&rpc::SubmitTxRequest {
            tx_json: tx_json.clone()
        })
        .unwrap()
    );
    println!();
    println!("# Propose + commit a block");
    println!("curl -s -X POST {addr}/propose | jq");
    println!();
    println!("# Query a file");
    println!(
        "curl -s -X POST {addr}/get_file -H 'Content-Type: application/json' -d '{}' | jq",
        serde_json::to_string(&rpc::GetFileRequest {
            merkle_root: hex::encode(merkle_root)
        })
        .unwrap()
    );
    println!();
    println!("=========================================");
    println!();

    rpc::serve(node, addr).await.unwrap();
}

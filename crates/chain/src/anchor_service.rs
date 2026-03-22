//! Epoch-based anchor scheduling service.
//!
//! At epoch boundaries (height % epoch_length == 0), the designated
//! validator computes the Super Merkle Root from all registered files
//! and anchors it to BTC/ETH. The receipts are then submitted as an
//! AnchorMerkleRoot transaction to the zk-vault chain.
//!
//! Anchor responsibility rotates among validators via round-robin.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::node::Node;
use crate::types::{Address, Height, Transaction};

/// Configuration for the anchor service.
#[derive(Debug, Clone, Default)]
pub struct AnchorConfig {
    /// Epoch length in blocks. Anchor is triggered every epoch_length blocks.
    /// Set to 0 to disable automatic anchoring.
    pub epoch_length: u64,
    /// Bitcoin anchor configuration (None = skip BTC anchoring).
    pub btc_config: Option<zk_vault_core::anchor::bitcoin::BitcoinConfig>,
    /// Ethereum anchor configuration (None = skip ETH anchoring).
    pub eth_config: Option<zk_vault_core::anchor::ethereum::EthereumConfig>,
}

/// The anchor service handles automatic BTC/ETH anchoring at epoch boundaries.
pub struct AnchorService {
    node: Arc<RwLock<Node>>,
    signing_key: SigningKey,
    address: Address,
    config: AnchorConfig,
}

impl AnchorService {
    pub fn new(node: Arc<RwLock<Node>>, signing_key: SigningKey, config: AnchorConfig) -> Self {
        let pk = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&pk);
        Self {
            node,
            signing_key,
            address,
            config,
        }
    }

    /// Check if anchoring is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.epoch_length > 0
            && (self.config.btc_config.is_some() || self.config.eth_config.is_some())
    }

    /// Check if the given height is an epoch boundary.
    pub fn is_epoch_boundary(&self, height: Height) -> bool {
        if self.config.epoch_length == 0 {
            return false;
        }
        height.0 > 0 && height.0 % self.config.epoch_length == 0
    }

    /// Determine which validator is responsible for anchoring at this epoch.
    /// Uses round-robin: epoch % validator_count.
    pub fn is_anchor_validator(&self, height: Height) -> bool {
        if !self.is_epoch_boundary(height) {
            return false;
        }

        let node = self.node.try_read();
        let node = match node {
            Ok(n) => n,
            Err(_) => return false,
        };

        let validators = &node.validator_set().validators;
        if validators.is_empty() {
            return false;
        }

        let epoch = height.0 / self.config.epoch_length;
        let idx = (epoch as usize) % validators.len();
        validators[idx].address == self.address
    }

    /// Execute the anchor process for the current epoch.
    ///
    /// 1. Compute Super Merkle Root from all registered files
    /// 2. Anchor to BTC/ETH
    /// 3. Submit AnchorMerkleRoot tx
    pub async fn execute_anchor(&self, height: Height) {
        if !self.is_enabled() {
            return;
        }

        let epoch = height.0 / self.config.epoch_length;

        info!(height = height.0, epoch, "Starting epoch anchor");

        // 1. Compute Super Merkle Root
        let (super_root, file_count) = {
            let node = self.node.read().await;
            let state = node.state();

            if state.file_registry.is_empty() {
                debug!("No files registered, skipping anchor");
                return;
            }

            // Check if this epoch was already anchored
            if state.anchor_history.contains_key(&epoch) {
                debug!(epoch, "Epoch already anchored, skipping");
                return;
            }

            let leaf_hashes: Vec<[u8; 32]> = state.file_registry.keys().copied().collect();
            let tree = zk_vault_core::merkle::tree::MerkleTree::from_leaf_hashes(leaf_hashes);

            match tree.root() {
                Some(root) => (root, state.file_registry.len() as u32),
                None => {
                    debug!("Empty Merkle tree, skipping anchor");
                    return;
                }
            }
        };

        info!(
            epoch,
            super_root = hex::encode(super_root),
            file_count,
            "Super Merkle Root computed"
        );

        // 2. Anchor to BTC/ETH
        let mut btc_tx_id = None;
        let mut eth_tx_id = None;

        if let Some(btc_config) = &self.config.btc_config {
            let anchor = zk_vault_core::anchor::bitcoin::BitcoinAnchor::new(btc_config.clone());
            use zk_vault_core::anchor::BlockchainAnchor;
            match anchor.anchor(&super_root).await {
                Ok(receipt) => {
                    info!(
                        tx_id = %receipt.tx_id,
                        "BTC anchor successful"
                    );
                    btc_tx_id = Some(receipt.tx_id);
                }
                Err(e) => {
                    error!(err = %e, "BTC anchor failed");
                }
            }
        }

        if let Some(eth_config) = &self.config.eth_config {
            let anchor = zk_vault_core::anchor::ethereum::EthereumAnchor::new(eth_config.clone());
            use zk_vault_core::anchor::BlockchainAnchor;
            match anchor.anchor(&super_root).await {
                Ok(receipt) => {
                    info!(
                        tx_id = %receipt.tx_id,
                        "ETH anchor successful"
                    );
                    eth_tx_id = Some(receipt.tx_id);
                }
                Err(e) => {
                    error!(err = %e, "ETH anchor failed");
                }
            }
        }

        // 3. Submit AnchorMerkleRoot transaction
        let pk = self.signing_key.verifying_key().to_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"zk-vault:anchor:");
        msg.extend_from_slice(&super_root);
        msg.extend_from_slice(&epoch.to_le_bytes());
        let msg_hash = blake3::hash(&msg);
        let signature = self.signing_key.sign(msg_hash.as_bytes());

        let tx = Transaction::AnchorMerkleRoot {
            super_root,
            epoch,
            btc_tx_id,
            eth_tx_id,
            file_count,
            anchor_validator_pk: pk,
            signature: signature.to_bytes().to_vec(),
        };

        let mut node = self.node.write().await;
        match node.submit_tx(tx) {
            Ok(hash) => {
                info!(
                    epoch,
                    tx_hash = hex::encode(hash),
                    "AnchorMerkleRoot tx submitted"
                );
            }
            Err(e) => {
                error!(err = %e, "Failed to submit AnchorMerkleRoot tx");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::MempoolConfig;
    use crate::node::NodeConfig;
    use crate::storage::Storage;
    use crate::types::{Validator, ValidatorSet};
    use ed25519_dalek::SigningKey;

    fn make_keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        let sk = SigningKey::from_bytes(&secret);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn test_setup() -> (
        Arc<RwLock<Node>>,
        Vec<(SigningKey, [u8; 32])>,
        tempfile::TempDir,
    ) {
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
        let storage = Arc::new(Storage::open(dir.path()).unwrap());
        let node = Arc::new(RwLock::new(Node::new(vs, config, storage)));
        (node, keys, dir)
    }

    #[test]
    fn epoch_boundary_detection() {
        let (node, keys, _dir) = test_setup();
        let config = AnchorConfig {
            epoch_length: 10,
            btc_config: None,
            eth_config: None,
        };
        let service = AnchorService::new(node, keys[0].0.clone(), config);

        assert!(!service.is_epoch_boundary(Height(0)));
        assert!(!service.is_epoch_boundary(Height(5)));
        assert!(service.is_epoch_boundary(Height(10)));
        assert!(!service.is_epoch_boundary(Height(15)));
        assert!(service.is_epoch_boundary(Height(20)));
    }

    #[test]
    fn disabled_when_epoch_zero() {
        let (node, keys, _dir) = test_setup();
        let config = AnchorConfig::default(); // epoch_length = 0
        let service = AnchorService::new(node, keys[0].0.clone(), config);

        assert!(!service.is_enabled());
        assert!(!service.is_epoch_boundary(Height(100)));
    }

    #[test]
    fn anchor_validator_round_robin() {
        let (node, keys, _dir) = test_setup();
        // 3 validators, epoch_length = 10

        let config = AnchorConfig {
            epoch_length: 10,
            btc_config: None,
            eth_config: Some(zk_vault_core::anchor::ethereum::EthereumConfig {
                rpc_url: "http://localhost:8545".to_string(),
                network: "test".to_string(),
                private_key_hex: "00".to_string(),
                chain_id: 1,
            }),
        };
        let svc0 = AnchorService::new(Arc::clone(&node), keys[0].0.clone(), config.clone());
        let svc1 = AnchorService::new(Arc::clone(&node), keys[1].0.clone(), config.clone());
        let svc2 = AnchorService::new(Arc::clone(&node), keys[2].0.clone(), config);

        // epoch 1 (height 10): epoch % 3 = 1 -> validator 1
        assert!(!svc0.is_anchor_validator(Height(10)));
        assert!(svc1.is_anchor_validator(Height(10)));
        assert!(!svc2.is_anchor_validator(Height(10)));

        // epoch 2 (height 20): epoch % 3 = 2 -> validator 2
        assert!(!svc0.is_anchor_validator(Height(20)));
        assert!(!svc1.is_anchor_validator(Height(20)));
        assert!(svc2.is_anchor_validator(Height(20)));

        // epoch 3 (height 30): epoch % 3 = 0 -> validator 0
        assert!(svc0.is_anchor_validator(Height(30)));
        assert!(!svc1.is_anchor_validator(Height(30)));
        assert!(!svc2.is_anchor_validator(Height(30)));
    }

    #[tokio::test]
    async fn execute_anchor_no_files_skips() {
        let (node, keys, _dir) = test_setup();
        let config = AnchorConfig {
            epoch_length: 10,
            btc_config: None,
            eth_config: Some(zk_vault_core::anchor::ethereum::EthereumConfig {
                rpc_url: "http://localhost:8545".to_string(),
                network: "test".to_string(),
                private_key_hex: "00".to_string(),
                chain_id: 1,
            }),
        };
        let service = AnchorService::new(node.clone(), keys[0].0.clone(), config);

        // No files registered, should skip
        service.execute_anchor(Height(10)).await;

        let n = node.read().await;
        assert!(n.state().anchor_history.is_empty());
        assert_eq!(n.pending_tx_count(), 0);
    }

    #[tokio::test]
    async fn execute_anchor_submits_tx() {
        let (node, keys, _dir) = test_setup();

        // Register a file first
        {
            let (sk, pk) = &keys[0];
            use ed25519_dalek::Signer;
            let merkle_root = [0xAA; 32];
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

        // Create anchor service with a dummy eth config (will fail to connect
        // but will still submit AnchorMerkleRoot tx with None receipts)
        let config = AnchorConfig {
            epoch_length: 1,
            btc_config: None,
            eth_config: Some(zk_vault_core::anchor::ethereum::EthereumConfig {
                rpc_url: "http://localhost:99999".to_string(), // will fail
                network: "test".to_string(),
                private_key_hex: "0000000000000000000000000000000000000000000000000000000000000001"
                    .to_string(),
                chain_id: 1,
            }),
        };
        let service = AnchorService::new(node.clone(), keys[0].0.clone(), config);

        service.execute_anchor(Height(1)).await;

        // Should have submitted AnchorMerkleRoot tx to mempool
        let n = node.read().await;
        assert_eq!(
            n.pending_tx_count(),
            1,
            "AnchorMerkleRoot tx should be in mempool"
        );
    }
}

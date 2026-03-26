//! Filecoin deal monitoring service.
//!
//! Periodically checks the status of active Filecoin deals and
//! triggers renewal when deals approach expiry.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::node::Node;
use crate::types::{Address, Height, Transaction};

/// Configuration for the deal monitor.
#[derive(Debug, Clone, Default)]
pub struct DealMonitorConfig {
    /// How often to check deals (in blocks). 0 = disabled.
    pub check_interval_blocks: u64,
    /// Filecoin epochs before deal expiry to trigger renewal.
    pub renew_before_epochs: u64,
}

/// Monitors Filecoin deals and triggers renewals.
pub struct DealMonitor {
    node: Arc<RwLock<Node>>,
    signing_key: SigningKey,
    #[allow(dead_code)]
    address: Address,
    config: DealMonitorConfig,
}

impl DealMonitor {
    pub fn new(
        node: Arc<RwLock<Node>>,
        signing_key: SigningKey,
        config: DealMonitorConfig,
    ) -> Self {
        let pk = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&pk);
        Self {
            node,
            signing_key,
            address,
            config,
        }
    }

    /// Check if monitoring is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.check_interval_blocks > 0
    }

    /// Check if the given height triggers a deal check.
    pub fn should_check(&self, height: Height) -> bool {
        if !self.is_enabled() {
            return false;
        }
        height.0 > 0 && height.0 % self.config.check_interval_blocks == 0
    }

    /// Check all deals and identify those needing renewal.
    /// Returns the CIDs of deals that need renewal.
    pub async fn check_deals(&self, current_filecoin_epoch: u64) -> Vec<String> {
        let node = self.node.read().await;
        let deal_registry = &node.state().deal_registry;

        let mut needs_renewal = Vec::new();

        for (cid, deals) in deal_registry {
            // Find the latest deal for this CID
            if let Some(latest) = deals.last() {
                let remaining = latest.end_epoch.saturating_sub(current_filecoin_epoch);
                if remaining <= self.config.renew_before_epochs {
                    info!(
                        cid = %cid,
                        end_epoch = latest.end_epoch,
                        remaining_epochs = remaining,
                        "Deal approaching expiry, needs renewal"
                    );
                    needs_renewal.push(cid.clone());
                }
            }
        }

        if needs_renewal.is_empty() {
            debug!("All deals healthy");
        }

        needs_renewal
    }

    /// Submit a RenewDeal transaction for a given CID.
    pub async fn submit_renewal(
        &self,
        data_cid: &str,
        deal_id: u64,
        provider: &str,
        end_epoch: u64,
        merkle_root: [u8; 32],
    ) {
        let pk = self.signing_key.verifying_key().to_bytes();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"zk-vault:deal:");
        msg.extend_from_slice(data_cid.as_bytes());
        msg.extend_from_slice(&deal_id.to_le_bytes());
        let msg_hash = blake3::hash(&msg);
        let signature = self.signing_key.sign(msg_hash.as_bytes());

        let tx = Transaction::RenewDeal {
            data_cid: data_cid.to_string(),
            deal_id,
            provider: provider.to_string(),
            end_epoch,
            is_renewal: true,
            merkle_root,
            validator_pk: pk,
            signature: signature.to_bytes().to_vec(),
        };

        let mut node = self.node.write().await;
        match node.submit_tx(tx) {
            Ok(hash) => {
                info!(
                    cid = %data_cid,
                    deal_id,
                    tx_hash = hex::encode(hash),
                    "RenewDeal tx submitted"
                );
            }
            Err(e) => {
                warn!(cid = %data_cid, err = %e, "Failed to submit RenewDeal tx");
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

    fn make_keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        let sk = SigningKey::from_bytes(&secret);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn check_interval() {
        let keys: Vec<_> = (1..=3).map(make_keypair).collect();
        let validators: Vec<Validator> = keys
            .iter()
            .map(|(_, pk)| Validator::new(*pk, 100))
            .collect();
        let vs = ValidatorSet::new(validators);
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(dir.path()).unwrap());
        let config = NodeConfig {
            validator_address: Address::from_public_key(&keys[0].1),
            validator_pk: keys[0].1,
            mempool_config: MempoolConfig::default(),
            replication_factor: 3,
        };
        let node = Arc::new(RwLock::new(Node::new(vs, config, storage)));

        let monitor = DealMonitor::new(
            node,
            keys[0].0.clone(),
            DealMonitorConfig {
                check_interval_blocks: 50,
                renew_before_epochs: 1000,
            },
        );

        assert!(monitor.is_enabled());
        assert!(!monitor.should_check(Height(0)));
        assert!(!monitor.should_check(Height(25)));
        assert!(monitor.should_check(Height(50)));
        assert!(monitor.should_check(Height(100)));
    }

    #[test]
    fn disabled_when_interval_zero() {
        let keys: Vec<_> = (1..=1).map(make_keypair).collect();
        let validators: Vec<Validator> = keys
            .iter()
            .map(|(_, pk)| Validator::new(*pk, 100))
            .collect();
        let vs = ValidatorSet::new(validators);
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(dir.path()).unwrap());
        let config = NodeConfig {
            validator_address: Address::from_public_key(&keys[0].1),
            validator_pk: keys[0].1,
            mempool_config: MempoolConfig::default(),
            replication_factor: 3,
        };
        let node = Arc::new(RwLock::new(Node::new(vs, config, storage)));

        let monitor = DealMonitor::new(node, keys[0].0.clone(), DealMonitorConfig::default());

        assert!(!monitor.is_enabled());
        assert!(!monitor.should_check(Height(100)));
    }
}

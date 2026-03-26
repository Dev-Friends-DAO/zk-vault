//! Chain state machine: applies transactions and maintains state.
//!
//! The state machine processes blocks produced by Malachite consensus,
//! validating each transaction and updating the FileRegistry and
//! validator set accordingly.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::types::{Address, Block, BlockId, Height, Transaction, Validator, ValidatorSet};

// ── Errors ──

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("Invalid signature on transaction")]
    InvalidSignature,

    #[error("Duplicate registration: merkle root {0} already registered")]
    DuplicateRegistration(String),

    #[error("File not found: merkle root {0}")]
    FileNotFound(String),

    #[error("Unauthorized: signer is not a validator")]
    Unauthorized,

    #[error("Invalid block height: expected {expected}, got {got}")]
    InvalidHeight { expected: u64, got: u64 },

    #[error("Invalid prev_block_id: expected {expected}, got {got}")]
    InvalidPrevBlockId { expected: BlockId, got: BlockId },

    #[error("Ed25519 verification error: {0}")]
    Ed25519Error(String),

    #[error("Guardian already registered: {0}")]
    DuplicateGuardian(String),

    #[error("No recovery request found for {0}")]
    NoRecoveryRequest(String),

    #[error("Guardian not in guardian set: {0}")]
    GuardianNotFound(String),

    #[error("Key has been revoked")]
    RevokedKey,

    #[error("Recovery already completed")]
    RecoveryCompleted,

    #[error("No guardian set found for {0}")]
    NoGuardianSet(String),

    #[error("Guardian set threshold mismatch")]
    ThresholdMismatch,
}

pub type Result<T> = std::result::Result<T, StateError>;

// ── FileRegistry entry ──

/// A registered backup on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Owner's Ed25519 public key.
    pub owner_pk: [u8; 32],
    /// Number of files in the backup.
    pub file_count: u32,
    /// Total encrypted size in bytes.
    pub encrypted_size: u64,
    /// Block height at which it was registered.
    pub registered_at: Height,
    /// Set of verifier public keys who attested integrity.
    pub verifications: BTreeSet<[u8; 32]>,
}

// ── Guardian Recovery types ──

/// Guardian entry in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianEntry {
    pub guardian_pk: [u8; 32],
    pub encrypted_share: String,
    pub registered_at: Height,
}

/// Guardian set for a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianSet {
    pub owner_pk: [u8; 32],
    pub threshold: u8,
    pub total_guardians: u8,
    pub guardians: Vec<GuardianEntry>,
}

/// Recovery request status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryStatus {
    Pending,
    Completed,
    Cancelled,
}

/// Active recovery request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub owner_pk: [u8; 32],
    pub new_pk: [u8; 32],
    pub requested_at: Height,
    pub status: RecoveryStatus,
    pub approvals: Vec<RecoveryApproval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryApproval {
    pub guardian_pk: [u8; 32],
    pub share_data: String,
    pub approved_at: Height,
}

/// Key status entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    pub current_pk: [u8; 32],
    pub revoked_pks: Vec<[u8; 32]>,
    pub last_rotated: Height,
}

/// A recorded Filecoin storage deal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DealEntry {
    /// CID of the stored data.
    pub data_cid: String,
    /// Filecoin deal ID.
    pub deal_id: u64,
    /// Storage provider address.
    pub provider: String,
    /// Deal end epoch on Filecoin chain.
    pub end_epoch: u64,
    /// Whether this is a renewal.
    pub is_renewal: bool,
    /// Original merkle root.
    pub merkle_root: [u8; 32],
    /// Validator who recorded this deal.
    pub validator_pk: [u8; 32],
    /// Block height at which this was recorded.
    pub recorded_at: Height,
}

/// A recorded anchor event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorEntry {
    /// The Super Merkle Root that was anchored.
    pub super_root: [u8; 32],
    /// Epoch number.
    pub epoch: u64,
    /// Bitcoin transaction ID (if successful).
    pub btc_tx_id: Option<String>,
    /// Ethereum transaction ID (if successful).
    pub eth_tx_id: Option<String>,
    /// Number of files included.
    pub file_count: u32,
    /// Validator who performed the anchor.
    pub anchor_validator_pk: [u8; 32],
    /// Block height at which the anchor was recorded.
    pub recorded_at: Height,
}

// ── Endowment types ──

/// Configuration for the Endowment module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndowmentConfig {
    /// Immediate validator share in basis points (1500 = 15%).
    pub immediate_share_bps: u16,
    /// Pool share in basis points (8500 = 85%).
    pub pool_share_bps: u16,
    /// Annual decay rate in basis points (3000 = 30%).
    pub decay_rate_bps: u16,
    /// Epoch length for decay application (in blocks).
    pub decay_epoch_length: u64,
    /// Minimum distribution rate per block (floor).
    pub min_distribution_rate: u64,
    /// Percentage of block rewards to endowment pool in bps (500 = 5%).
    pub block_reward_pool_bps: u16,
}

impl Default for EndowmentConfig {
    fn default() -> Self {
        Self {
            immediate_share_bps: 1500,
            pool_share_bps: 8500,
            decay_rate_bps: 3000,
            decay_epoch_length: 100,
            min_distribution_rate: 1,
            block_reward_pool_bps: 500,
        }
    }
}

/// The Endowment Pool state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndowmentPool {
    /// Current pool balance (abstract units).
    pub balance: u64,
    /// Total amount ever deposited into the pool.
    pub total_deposited: u64,
    /// Total amount ever distributed from the pool.
    pub total_distributed: u64,
    /// Current distribution rate per block (abstract units).
    pub distribution_rate: u64,
    /// Last epoch at which decay was applied.
    pub last_decay_epoch: u64,
    /// Per-validator accumulated rewards: validator_pk -> accumulated_reward.
    #[serde(with = "hex_key_map")]
    pub validator_rewards: BTreeMap<[u8; 32], u64>,
}

/// Custom serde for `BTreeMap<[u8; 32], u64>` using hex-encoded string keys.
mod hex_key_map {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S>(map: &BTreeMap<[u8; 32], u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string_map: BTreeMap<String, u64> =
            map.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
        string_map.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<[u8; 32], u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string_map: BTreeMap<String, u64> = BTreeMap::deserialize(deserializer)?;
        string_map
            .into_iter()
            .map(|(k, v)| {
                let bytes = hex::decode(&k).map_err(serde::de::Error::custom)?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
                Ok((arr, v))
            })
            .collect()
    }
}

// ── Chain State ──

/// The full chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// Current block height.
    pub height: Height,
    /// Last committed block ID.
    pub last_block_id: BlockId,
    /// Current validator set.
    pub validator_set: ValidatorSet,
    /// The file registry: merkle_root → FileEntry.
    pub file_registry: BTreeMap<[u8; 32], FileEntry>,
    /// Guardian registry: owner_pk → GuardianSet.
    pub guardian_registry: BTreeMap<[u8; 32], GuardianSet>,
    /// Active recovery requests: owner_pk → RecoveryRequest.
    pub recovery_requests: BTreeMap<[u8; 32], RecoveryRequest>,
    /// Key registry: owner_pk → KeyEntry (for revocation tracking).
    pub key_registry: BTreeMap<[u8; 32], KeyEntry>,
    /// Blob replica tracking: blob_key -> set of validator PKs that hold the blob.
    #[serde(default)]
    pub blob_replicas: BTreeMap<String, BTreeSet<[u8; 32]>>,
    /// Anchor history: epoch -> AnchorEntry.
    #[serde(default)]
    pub anchor_history: BTreeMap<u64, AnchorEntry>,
    /// Filecoin deal registry: data_cid -> Vec<DealEntry> (multiple SPs per CID).
    #[serde(default)]
    pub deal_registry: BTreeMap<String, Vec<DealEntry>>,
    /// Endowment configuration.
    #[serde(default)]
    pub endowment_config: EndowmentConfig,
    /// Endowment Pool state.
    #[serde(default)]
    pub endowment_pool: EndowmentPool,
}

impl ChainState {
    /// Create the initial chain state from a genesis validator set.
    pub fn genesis(validator_set: ValidatorSet) -> Self {
        let genesis_block = Block::genesis(&validator_set);
        Self {
            height: Height::GENESIS,
            last_block_id: genesis_block.id(),
            validator_set,
            file_registry: BTreeMap::new(),
            guardian_registry: BTreeMap::new(),
            recovery_requests: BTreeMap::new(),
            key_registry: BTreeMap::new(),
            blob_replicas: BTreeMap::new(),
            anchor_history: BTreeMap::new(),
            deal_registry: BTreeMap::new(),
            endowment_config: EndowmentConfig::default(),
            endowment_pool: EndowmentPool::default(),
        }
    }

    /// Compute the state root: BLAKE3 hash of the file registry, guardian registry, and key registry.
    pub fn state_root(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for (merkle_root, entry) in &self.file_registry {
            hasher.update(merkle_root);
            let entry_bytes =
                serde_json::to_vec(entry).expect("FileEntry serialization cannot fail");
            hasher.update(&entry_bytes);
        }
        for (owner_pk, guardian_set) in &self.guardian_registry {
            hasher.update(owner_pk);
            let gs_bytes =
                serde_json::to_vec(guardian_set).expect("GuardianSet serialization cannot fail");
            hasher.update(&gs_bytes);
        }
        for (owner_pk, key_entry) in &self.key_registry {
            hasher.update(owner_pk);
            let ke_bytes =
                serde_json::to_vec(key_entry).expect("KeyEntry serialization cannot fail");
            hasher.update(&ke_bytes);
        }
        for (blob_key, replicas) in &self.blob_replicas {
            hasher.update(blob_key.as_bytes());
            for pk in replicas {
                hasher.update(pk);
            }
        }
        for (epoch, entry) in &self.anchor_history {
            hasher.update(&epoch.to_le_bytes());
            let entry_bytes =
                serde_json::to_vec(entry).expect("AnchorEntry serialization cannot fail");
            hasher.update(&entry_bytes);
        }
        for (cid, deals) in &self.deal_registry {
            hasher.update(cid.as_bytes());
            let deals_bytes =
                serde_json::to_vec(deals).expect("DealEntry serialization cannot fail");
            hasher.update(&deals_bytes);
        }
        let endowment_bytes = serde_json::to_vec(&self.endowment_pool)
            .expect("EndowmentPool serialization cannot fail");
        hasher.update(&endowment_bytes);
        *hasher.finalize().as_bytes()
    }

    /// Number of registered backups.
    pub fn file_count(&self) -> usize {
        self.file_registry.len()
    }

    /// Look up a file entry by merkle root.
    pub fn get_file(&self, merkle_root: &[u8; 32]) -> Option<&FileEntry> {
        self.file_registry.get(merkle_root)
    }

    /// Apply a block to the state. Validates and executes all transactions.
    pub fn apply_block(&mut self, block: &Block) -> Result<()> {
        // Validate block height
        let expected_height = Height(self.height.0 + 1);
        if block.header.height != expected_height {
            return Err(StateError::InvalidHeight {
                expected: expected_height.0,
                got: block.header.height.0,
            });
        }

        // Validate prev_block_id
        if block.header.prev_block_id != self.last_block_id {
            return Err(StateError::InvalidPrevBlockId {
                expected: self.last_block_id,
                got: block.header.prev_block_id,
            });
        }

        // Apply each transaction
        for tx in &block.transactions {
            self.apply_tx(tx, block.header.height)?;
        }

        // Distribute endowment rewards for this block
        self.distribute_endowment();

        // Update chain metadata
        self.height = block.header.height;
        self.last_block_id = block.id();

        Ok(())
    }

    /// Apply a single transaction to the state.
    pub(crate) fn apply_tx(&mut self, tx: &Transaction, height: Height) -> Result<()> {
        match tx {
            Transaction::RegisterFile {
                merkle_root,
                file_count,
                encrypted_size,
                owner_pk,
                signature,
            } => {
                // Check key is not revoked
                if let Some(key_entry) = self.key_registry.get(owner_pk) {
                    if key_entry.revoked_pks.contains(owner_pk) {
                        return Err(StateError::RevokedKey);
                    }
                }

                // Verify signature
                verify_ed25519(owner_pk, merkle_root, signature)?;

                // Check for duplicates
                if self.file_registry.contains_key(merkle_root) {
                    return Err(StateError::DuplicateRegistration(hex::encode(
                        &merkle_root[..8],
                    )));
                }

                // Register
                self.file_registry.insert(
                    *merkle_root,
                    FileEntry {
                        owner_pk: *owner_pk,
                        file_count: *file_count,
                        encrypted_size: *encrypted_size,
                        registered_at: height,
                        verifications: BTreeSet::new(),
                    },
                );
            }

            Transaction::VerifyIntegrity {
                merkle_root,
                verifier_pk,
                signature,
            } => {
                // Check key is not revoked
                if let Some(key_entry) = self.key_registry.get(verifier_pk) {
                    if key_entry.revoked_pks.contains(verifier_pk) {
                        return Err(StateError::RevokedKey);
                    }
                }

                // Verify signature
                verify_ed25519(verifier_pk, merkle_root, signature)?;

                // File must exist
                let entry = self
                    .file_registry
                    .get_mut(merkle_root)
                    .ok_or_else(|| StateError::FileNotFound(hex::encode(&merkle_root[..8])))?;

                // Add verification
                entry.verifications.insert(*verifier_pk);
            }

            Transaction::UpdateValidatorSet {
                validators,
                signature,
            } => {
                // The signer must be a current validator (governance)
                // For now, verify that the signature is from a validator
                // using the first 32 bytes of signature as the signer's pk
                if signature.len() < 96 {
                    return Err(StateError::InvalidSignature);
                }
                let signer_pk: [u8; 32] = signature[..32]
                    .try_into()
                    .map_err(|_| StateError::InvalidSignature)?;
                let addr = Address::from_public_key(&signer_pk);
                if self.validator_set.get_by_address(&addr).is_none() {
                    return Err(StateError::Unauthorized);
                }

                // Verify signature over the serialized validator list
                let msg = serde_json::to_vec(validators)
                    .expect("Validator list serialization cannot fail");
                verify_ed25519(&signer_pk, &msg, &signature[32..])?;

                // Update validator set
                let new_validators: Vec<Validator> = validators
                    .iter()
                    .map(|(pk, power)| Validator::new(*pk, *power))
                    .collect();
                self.validator_set = ValidatorSet::new(new_validators);
            }

            Transaction::RegisterGuardian {
                owner_pk,
                guardian_pk,
                encrypted_share,
                threshold,
                total_guardians,
                signature,
            } => {
                // Verify owner signature over BLAKE3(domain || guardian_pk || threshold || total_guardians)
                let mut msg = Vec::new();
                msg.extend_from_slice(b"zk-vault:register-guardian:");
                msg.extend_from_slice(guardian_pk);
                msg.push(*threshold);
                msg.push(*total_guardians);
                let msg_hash = blake3::hash(&msg);
                verify_ed25519(owner_pk, msg_hash.as_bytes(), signature)?;

                // Create or update guardian set
                let guardian_set =
                    self.guardian_registry
                        .entry(*owner_pk)
                        .or_insert_with(|| GuardianSet {
                            owner_pk: *owner_pk,
                            threshold: *threshold,
                            total_guardians: *total_guardians,
                            guardians: Vec::new(),
                        });

                // Validate threshold and total_guardians match
                if guardian_set.threshold != *threshold
                    || guardian_set.total_guardians != *total_guardians
                {
                    return Err(StateError::ThresholdMismatch);
                }

                // Check for duplicate guardian
                if guardian_set
                    .guardians
                    .iter()
                    .any(|g| g.guardian_pk == *guardian_pk)
                {
                    return Err(StateError::DuplicateGuardian(hex::encode(
                        &guardian_pk[..8],
                    )));
                }

                // Add guardian entry
                guardian_set.guardians.push(GuardianEntry {
                    guardian_pk: *guardian_pk,
                    encrypted_share: encrypted_share.clone(),
                    registered_at: height,
                });
            }

            Transaction::RequestRecovery {
                owner_pk,
                new_pk,
                signature,
            } => {
                // Verify signature (with new_pk over owner_pk, since original key may be lost)
                verify_ed25519(new_pk, owner_pk, signature)?;

                // Check guardian set exists for owner_pk
                if !self.guardian_registry.contains_key(owner_pk) {
                    return Err(StateError::NoGuardianSet(hex::encode(&owner_pk[..8])));
                }

                // Create recovery request with Pending status
                self.recovery_requests.insert(
                    *owner_pk,
                    RecoveryRequest {
                        owner_pk: *owner_pk,
                        new_pk: *new_pk,
                        requested_at: height,
                        status: RecoveryStatus::Pending,
                        approvals: Vec::new(),
                    },
                );
            }

            Transaction::ApproveRecovery {
                owner_pk,
                guardian_pk,
                share_data,
                signature,
            } => {
                // Verify guardian signature over BLAKE3(domain || owner_pk || share_data)
                let mut msg = Vec::new();
                msg.extend_from_slice(b"zk-vault:approve-recovery:");
                msg.extend_from_slice(owner_pk);
                msg.extend_from_slice(share_data.as_bytes());
                let msg_hash = blake3::hash(&msg);
                verify_ed25519(guardian_pk, msg_hash.as_bytes(), signature)?;

                // Check guardian is in the owner's guardian set
                let guardian_set = self
                    .guardian_registry
                    .get(owner_pk)
                    .ok_or_else(|| StateError::NoGuardianSet(hex::encode(&owner_pk[..8])))?;

                if !guardian_set
                    .guardians
                    .iter()
                    .any(|g| g.guardian_pk == *guardian_pk)
                {
                    return Err(StateError::GuardianNotFound(hex::encode(&guardian_pk[..8])));
                }

                let threshold = guardian_set.threshold;

                // Check recovery request exists and is Pending
                let request = self
                    .recovery_requests
                    .get_mut(owner_pk)
                    .ok_or_else(|| StateError::NoRecoveryRequest(hex::encode(&owner_pk[..8])))?;

                if request.status != RecoveryStatus::Pending {
                    return Err(StateError::RecoveryCompleted);
                }

                // Add approval
                request.approvals.push(RecoveryApproval {
                    guardian_pk: *guardian_pk,
                    share_data: share_data.clone(),
                    approved_at: height,
                });

                // If approvals >= threshold, mark as Completed
                if request.approvals.len() >= threshold as usize {
                    request.status = RecoveryStatus::Completed;
                }
            }

            Transaction::RevokeKeys {
                owner_pk,
                new_ed25519_pk,
                signature,
            } => {
                // Verify signature with current owner_pk over BLAKE3(domain || new_ed25519_pk)
                let mut msg = Vec::new();
                msg.extend_from_slice(b"zk-vault:revoke-keys:");
                msg.extend_from_slice(new_ed25519_pk);
                let msg_hash = blake3::hash(&msg);
                verify_ed25519(owner_pk, msg_hash.as_bytes(), signature)?;

                // Check key is not already revoked
                if let Some(key_entry) = self.key_registry.get(owner_pk) {
                    if key_entry.revoked_pks.contains(owner_pk) {
                        return Err(StateError::RevokedKey);
                    }
                }

                // Update key_registry
                let key_entry = self
                    .key_registry
                    .entry(*owner_pk)
                    .or_insert_with(|| KeyEntry {
                        current_pk: *owner_pk,
                        revoked_pks: Vec::new(),
                        last_rotated: height,
                    });

                // Add current pk to revoked list, set new current pk
                key_entry.revoked_pks.push(key_entry.current_pk);
                key_entry.current_pk = *new_ed25519_pk;
                key_entry.last_rotated = height;
            }

            Transaction::UpdateStorageStatus {
                blob_key,
                validator_pk,
                holds_blob,
                signature,
            } => {
                // Verify validator is in the current set
                let addr = Address::from_public_key(validator_pk);
                if self.validator_set.get_by_address(&addr).is_none() {
                    return Err(StateError::Unauthorized);
                }

                // Verify signature over domain-separated message
                let mut msg = Vec::new();
                msg.extend_from_slice(b"zk-vault:storage-status:");
                msg.extend_from_slice(blob_key.as_bytes());
                msg.push(if *holds_blob { 1 } else { 0 });
                let msg_hash = blake3::hash(&msg);
                verify_ed25519(validator_pk, msg_hash.as_bytes(), signature)?;

                if *holds_blob {
                    self.blob_replicas
                        .entry(blob_key.clone())
                        .or_default()
                        .insert(*validator_pk);
                } else if let Some(set) = self.blob_replicas.get_mut(blob_key.as_str()) {
                    set.remove(validator_pk);
                    if set.is_empty() {
                        self.blob_replicas.remove(blob_key.as_str());
                    }
                }
            }

            Transaction::AnchorMerkleRoot {
                super_root,
                epoch,
                btc_tx_id,
                eth_tx_id,
                file_count,
                anchor_validator_pk,
                signature,
            } => {
                // Verify the anchor validator is in the current set
                let addr = Address::from_public_key(anchor_validator_pk);
                if self.validator_set.get_by_address(&addr).is_none() {
                    return Err(StateError::Unauthorized);
                }

                // Verify signature over domain-separated message
                let mut msg = Vec::new();
                msg.extend_from_slice(b"zk-vault:anchor:");
                msg.extend_from_slice(super_root);
                msg.extend_from_slice(&epoch.to_le_bytes());
                let msg_hash = blake3::hash(&msg);
                verify_ed25519(anchor_validator_pk, msg_hash.as_bytes(), signature)?;

                // Store anchor entry
                self.anchor_history.insert(
                    *epoch,
                    AnchorEntry {
                        super_root: *super_root,
                        epoch: *epoch,
                        btc_tx_id: btc_tx_id.clone(),
                        eth_tx_id: eth_tx_id.clone(),
                        file_count: *file_count,
                        anchor_validator_pk: *anchor_validator_pk,
                        recorded_at: height,
                    },
                );
            }

            Transaction::RenewDeal {
                data_cid,
                deal_id,
                provider,
                end_epoch,
                is_renewal,
                merkle_root,
                validator_pk,
                signature,
            } => {
                // Verify validator is in the current set
                let addr = Address::from_public_key(validator_pk);
                if self.validator_set.get_by_address(&addr).is_none() {
                    return Err(StateError::Unauthorized);
                }

                // Verify signature
                let mut msg = Vec::new();
                msg.extend_from_slice(b"zk-vault:deal:");
                msg.extend_from_slice(data_cid.as_bytes());
                msg.extend_from_slice(&deal_id.to_le_bytes());
                let msg_hash = blake3::hash(&msg);
                verify_ed25519(validator_pk, msg_hash.as_bytes(), signature)?;

                // Add deal entry
                let entry = DealEntry {
                    data_cid: data_cid.clone(),
                    deal_id: *deal_id,
                    provider: provider.clone(),
                    end_epoch: *end_epoch,
                    is_renewal: *is_renewal,
                    merkle_root: *merkle_root,
                    validator_pk: *validator_pk,
                    recorded_at: height,
                };

                self.deal_registry
                    .entry(data_cid.clone())
                    .or_default()
                    .push(entry);
            }

            Transaction::Endow {
                merkle_root,
                amount,
                payer_pk,
                signature,
            } => {
                // Verify signature
                let mut msg = Vec::new();
                msg.extend_from_slice(b"zk-vault:endow:");
                msg.extend_from_slice(merkle_root);
                msg.extend_from_slice(&amount.to_le_bytes());
                let msg_hash = blake3::hash(&msg);
                verify_ed25519(payer_pk, msg_hash.as_bytes(), signature)?;

                // File must be registered
                if !self.file_registry.contains_key(merkle_root) {
                    return Err(StateError::FileNotFound(hex::encode(&merkle_root[..8])));
                }

                // Split: immediate_share to validators, rest to pool
                let immediate = (*amount as u128
                    * self.endowment_config.immediate_share_bps as u128
                    / 10_000) as u64;
                let to_pool = amount.saturating_sub(immediate);

                // Distribute immediate share equally among current validators
                let validator_count = self.validator_set.validators.len() as u64;
                if validator_count > 0 && immediate > 0 {
                    let per_validator = immediate / validator_count;
                    for v in &self.validator_set.validators {
                        *self
                            .endowment_pool
                            .validator_rewards
                            .entry(v.public_key)
                            .or_insert(0) += per_validator;
                    }
                }

                // Add to pool
                self.endowment_pool.balance += to_pool;
                self.endowment_pool.total_deposited += to_pool;

                // Set initial distribution rate if this is the first deposit
                if self.endowment_pool.distribution_rate == 0 && to_pool > 0 {
                    // Start with a rate that would distribute the pool over ~1 year
                    // assuming decay_epoch_length blocks per epoch
                    let epochs_per_year = 365 * 24 * 60; // ~525,600 minutes
                    self.endowment_pool.distribution_rate = to_pool / epochs_per_year.max(1);
                    if self.endowment_pool.distribution_rate == 0 {
                        self.endowment_pool.distribution_rate = 1;
                    }
                }
            }

            Transaction::DonateToEndowment {
                amount,
                donor_pk,
                signature,
            } => {
                // Verify signature
                let mut msg = Vec::new();
                msg.extend_from_slice(b"zk-vault:donate:");
                msg.extend_from_slice(&amount.to_le_bytes());
                let msg_hash = blake3::hash(&msg);
                verify_ed25519(donor_pk, msg_hash.as_bytes(), signature)?;

                // Add to pool
                self.endowment_pool.balance += *amount;
                self.endowment_pool.total_deposited += *amount;
            }
        }

        Ok(())
    }

    /// Distribute endowment rewards for a block.
    /// Called after applying all transactions in a block.
    /// Distributes from the pool to validators proportional to their blob storage.
    pub fn distribute_endowment(&mut self) {
        if self.endowment_pool.balance == 0 || self.endowment_pool.distribution_rate == 0 {
            return;
        }

        // Apply Kryder's Law decay at epoch boundaries
        let current_epoch = self.height.0 / self.endowment_config.decay_epoch_length.max(1);
        if current_epoch > self.endowment_pool.last_decay_epoch
            && self.endowment_config.decay_epoch_length > 0
        {
            let epochs_elapsed = current_epoch - self.endowment_pool.last_decay_epoch;
            for _ in 0..epochs_elapsed {
                let decay = (self.endowment_pool.distribution_rate as u128
                    * self.endowment_config.decay_rate_bps as u128
                    / 10_000) as u64;
                self.endowment_pool.distribution_rate = self
                    .endowment_pool
                    .distribution_rate
                    .saturating_sub(decay)
                    .max(self.endowment_config.min_distribution_rate);
            }
            self.endowment_pool.last_decay_epoch = current_epoch;
        }

        // Calculate this block's distribution
        let block_distribution = self
            .endowment_pool
            .distribution_rate
            .min(self.endowment_pool.balance);

        if block_distribution == 0 {
            return;
        }

        // Distribute proportional to blob storage
        // Use blob_replicas to determine how much each validator stores
        let mut validator_storage: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for replicas in self.blob_replicas.values() {
            for pk in replicas {
                *validator_storage.entry(*pk).or_insert(0) += 1;
            }
        }

        let total_storage: u64 = validator_storage.values().sum();
        if total_storage == 0 {
            // No data stored, distribute equally among validators as fallback
            let validator_count = self.validator_set.validators.len() as u64;
            if validator_count > 0 {
                let per_validator = block_distribution / validator_count;
                if per_validator > 0 {
                    for v in &self.validator_set.validators {
                        *self
                            .endowment_pool
                            .validator_rewards
                            .entry(v.public_key)
                            .or_insert(0) += per_validator;
                    }
                    let distributed = per_validator * validator_count;
                    self.endowment_pool.balance -= distributed;
                    self.endowment_pool.total_distributed += distributed;
                }
            }
            return;
        }

        // Proportional distribution
        let mut total_paid = 0u64;
        for (pk, storage) in &validator_storage {
            let share =
                (block_distribution as u128 * *storage as u128 / total_storage as u128) as u64;
            if share > 0 {
                *self
                    .endowment_pool
                    .validator_rewards
                    .entry(*pk)
                    .or_insert(0) += share;
                total_paid += share;
            }
        }

        self.endowment_pool.balance -= total_paid;
        self.endowment_pool.total_distributed += total_paid;
    }
}

/// Verify an Ed25519 signature.
fn verify_ed25519(pk_bytes: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_bytes(pk_bytes)
        .map_err(|e| StateError::Ed25519Error(format!("Invalid public key: {e}")))?;

    let sig = Signature::from_slice(signature)
        .map_err(|e| StateError::Ed25519Error(format!("Invalid signature: {e}")))?;

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(message, &sig)
        .map_err(|e| StateError::Ed25519Error(format!("Verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let mut secret = [0u8; 32];
        secret[0] = seed;
        let sk = SigningKey::from_bytes(&secret);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn test_validator_set() -> (ValidatorSet, Vec<(SigningKey, [u8; 32])>) {
        let keys: Vec<_> = (1..=3).map(make_keypair).collect();
        let validators: Vec<Validator> = keys
            .iter()
            .map(|(_, pk)| Validator::new(*pk, 100))
            .collect();
        (ValidatorSet::new(validators), keys)
    }

    fn make_block(state: &ChainState, txs: Vec<Transaction>) -> Block {
        let header = BlockHeader {
            height: Height(state.height.0 + 1),
            timestamp: 1000,
            prev_block_id: state.last_block_id,
            state_root: [0u8; 32], // filled after apply
            tx_root: [0u8; 32],
            proposer: state.validator_set.validators[0].address,
            tx_count: txs.len() as u32,
        };
        Block {
            header,
            transactions: txs,
        }
    }

    #[test]
    fn genesis_state() {
        let (vs, _) = test_validator_set();
        let state = ChainState::genesis(vs.clone());
        assert_eq!(state.height, Height::GENESIS);
        assert_eq!(state.file_count(), 0);
        assert_eq!(state.validator_set.validators.len(), 3);
    }

    #[test]
    fn register_file() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);

        let (sk, pk) = &keys[0];
        let merkle_root = [0xAB; 32];
        let sig = sk.sign(&merkle_root);

        let tx = Transaction::RegisterFile {
            merkle_root,
            file_count: 5,
            encrypted_size: 10240,
            owner_pk: *pk,
            signature: sig.to_bytes().to_vec(),
        };

        let block = make_block(&state, vec![tx]);
        state.apply_block(&block).unwrap();

        assert_eq!(state.height, Height(1));
        assert_eq!(state.file_count(), 1);

        let entry = state.get_file(&merkle_root).unwrap();
        assert_eq!(entry.owner_pk, *pk);
        assert_eq!(entry.file_count, 5);
        assert_eq!(entry.encrypted_size, 10240);
        assert_eq!(entry.registered_at, Height(1));
        assert!(entry.verifications.is_empty());
    }

    #[test]
    fn duplicate_registration_fails() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);

        let (sk, pk) = &keys[0];
        let merkle_root = [0xAB; 32];
        let sig = sk.sign(&merkle_root);

        let tx = Transaction::RegisterFile {
            merkle_root,
            file_count: 1,
            encrypted_size: 100,
            owner_pk: *pk,
            signature: sig.to_bytes().to_vec(),
        };

        let block1 = make_block(&state, vec![tx.clone()]);
        state.apply_block(&block1).unwrap();

        let block2 = make_block(&state, vec![tx]);
        let result = state.apply_block(&block2);
        assert!(result.is_err());
    }

    #[test]
    fn verify_integrity() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);

        // Register first
        let (sk0, pk0) = &keys[0];
        let merkle_root = [0xCD; 32];
        let sig0 = sk0.sign(&merkle_root);

        let register_tx = Transaction::RegisterFile {
            merkle_root,
            file_count: 3,
            encrypted_size: 5000,
            owner_pk: *pk0,
            signature: sig0.to_bytes().to_vec(),
        };
        let block1 = make_block(&state, vec![register_tx]);
        state.apply_block(&block1).unwrap();

        // Verify with a different key
        let (sk1, pk1) = &keys[1];
        let sig1 = sk1.sign(&merkle_root);

        let verify_tx = Transaction::VerifyIntegrity {
            merkle_root,
            verifier_pk: *pk1,
            signature: sig1.to_bytes().to_vec(),
        };
        let block2 = make_block(&state, vec![verify_tx]);
        state.apply_block(&block2).unwrap();

        let entry = state.get_file(&merkle_root).unwrap();
        assert_eq!(entry.verifications.len(), 1);
        assert!(entry.verifications.contains(pk1));
    }

    #[test]
    fn verify_nonexistent_file_fails() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);

        let (sk, pk) = &keys[0];
        let merkle_root = [0xFF; 32];
        let sig = sk.sign(&merkle_root);

        let tx = Transaction::VerifyIntegrity {
            merkle_root,
            verifier_pk: *pk,
            signature: sig.to_bytes().to_vec(),
        };
        let block = make_block(&state, vec![tx]);
        let result = state.apply_block(&block);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_signature_fails() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);

        let (_, pk) = &keys[0];
        let merkle_root = [0xAB; 32];
        let bad_sig = vec![0u8; 64]; // garbage signature

        let tx = Transaction::RegisterFile {
            merkle_root,
            file_count: 1,
            encrypted_size: 100,
            owner_pk: *pk,
            signature: bad_sig,
        };
        let block = make_block(&state, vec![tx]);
        let result = state.apply_block(&block);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_height_fails() {
        let (vs, _) = test_validator_set();
        let mut state = ChainState::genesis(vs.clone());

        // Create block at height 5 instead of 1
        let header = BlockHeader {
            height: Height(5),
            timestamp: 1000,
            prev_block_id: state.last_block_id,
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            proposer: vs.validators[0].address,
            tx_count: 0,
        };
        let block = Block {
            header,
            transactions: vec![],
        };
        let result = state.apply_block(&block);
        assert!(result.is_err());
    }

    #[test]
    fn state_root_changes_after_tx() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);
        let root_before = state.state_root();

        let (sk, pk) = &keys[0];
        let merkle_root = [0xAB; 32];
        let sig = sk.sign(&merkle_root);

        let tx = Transaction::RegisterFile {
            merkle_root,
            file_count: 1,
            encrypted_size: 100,
            owner_pk: *pk,
            signature: sig.to_bytes().to_vec(),
        };
        let block = make_block(&state, vec![tx]);
        state.apply_block(&block).unwrap();

        let root_after = state.state_root();
        assert_ne!(root_before, root_after);
    }

    // ── Guardian Recovery tests ──

    fn register_guardian_tx(
        owner_sk: &SigningKey,
        owner_pk: &[u8; 32],
        guardian_pk: &[u8; 32],
        encrypted_share: &str,
        threshold: u8,
        total_guardians: u8,
    ) -> Transaction {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"zk-vault:register-guardian:");
        msg.extend_from_slice(guardian_pk);
        msg.push(threshold);
        msg.push(total_guardians);
        let msg_hash = blake3::hash(&msg);
        let sig = owner_sk.sign(msg_hash.as_bytes());
        Transaction::RegisterGuardian {
            owner_pk: *owner_pk,
            guardian_pk: *guardian_pk,
            encrypted_share: encrypted_share.to_string(),
            threshold,
            total_guardians,
            signature: sig.to_bytes().to_vec(),
        }
    }

    #[test]
    fn register_guardian() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);
        let (owner_sk, owner_pk) = &keys[0];

        // Register 3 guardians
        let mut txs = Vec::new();
        for i in 1..=3u8 {
            let (_, gpk) = make_keypair(10 + i);
            txs.push(register_guardian_tx(
                owner_sk,
                owner_pk,
                &gpk,
                &format!("share_{i}"),
                2,
                3,
            ));
        }

        let block = make_block(&state, txs);
        state.apply_block(&block).unwrap();

        let gs = state.guardian_registry.get(owner_pk).unwrap();
        assert_eq!(gs.guardians.len(), 3);
        assert_eq!(gs.threshold, 2);
        assert_eq!(gs.total_guardians, 3);
    }

    #[test]
    fn request_recovery() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);
        let (owner_sk, owner_pk) = &keys[0];

        // Register guardians first
        let guardian_keys: Vec<_> = (11..=13).map(make_keypair).collect();
        let mut txs = Vec::new();
        for (_, gpk) in &guardian_keys {
            txs.push(register_guardian_tx(owner_sk, owner_pk, gpk, "share", 2, 3));
        }
        let block = make_block(&state, txs);
        state.apply_block(&block).unwrap();

        // Request recovery with a new key
        let (new_sk, new_pk) = make_keypair(99);
        let sig = new_sk.sign(owner_pk);
        let tx = Transaction::RequestRecovery {
            owner_pk: *owner_pk,
            new_pk,
            signature: sig.to_bytes().to_vec(),
        };
        let block2 = make_block(&state, vec![tx]);
        state.apply_block(&block2).unwrap();

        let req = state.recovery_requests.get(owner_pk).unwrap();
        assert_eq!(req.status, super::RecoveryStatus::Pending);
        assert_eq!(req.new_pk, new_pk);
    }

    #[test]
    fn approve_recovery() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);
        let (owner_sk, owner_pk) = &keys[0];

        // Register 3 guardians with threshold 2
        let guardian_keys: Vec<_> = (11..=13).map(make_keypair).collect();
        let mut txs = Vec::new();
        for (_, gpk) in &guardian_keys {
            txs.push(register_guardian_tx(owner_sk, owner_pk, gpk, "share", 2, 3));
        }
        let block = make_block(&state, txs);
        state.apply_block(&block).unwrap();

        // Request recovery
        let (new_sk, new_pk) = make_keypair(99);
        let sig = new_sk.sign(owner_pk);
        let block2 = make_block(
            &state,
            vec![Transaction::RequestRecovery {
                owner_pk: *owner_pk,
                new_pk,
                signature: sig.to_bytes().to_vec(),
            }],
        );
        state.apply_block(&block2).unwrap();

        // First guardian approves
        let (g1_sk, g1_pk) = &guardian_keys[0];
        let share_data_1 = "recovered_share_1";
        let mut msg1 = Vec::new();
        msg1.extend_from_slice(b"zk-vault:approve-recovery:");
        msg1.extend_from_slice(owner_pk);
        msg1.extend_from_slice(share_data_1.as_bytes());
        let msg1_hash = blake3::hash(&msg1);
        let g1_sig = g1_sk.sign(msg1_hash.as_bytes());
        let block3 = make_block(
            &state,
            vec![Transaction::ApproveRecovery {
                owner_pk: *owner_pk,
                guardian_pk: *g1_pk,
                share_data: share_data_1.to_string(),
                signature: g1_sig.to_bytes().to_vec(),
            }],
        );
        state.apply_block(&block3).unwrap();

        // Still pending (need 2)
        assert_eq!(
            state.recovery_requests.get(owner_pk).unwrap().status,
            super::RecoveryStatus::Pending
        );

        // Second guardian approves -> should complete
        let (g2_sk, g2_pk) = &guardian_keys[1];
        let share_data_2 = "recovered_share_2";
        let mut msg2 = Vec::new();
        msg2.extend_from_slice(b"zk-vault:approve-recovery:");
        msg2.extend_from_slice(owner_pk);
        msg2.extend_from_slice(share_data_2.as_bytes());
        let msg2_hash = blake3::hash(&msg2);
        let g2_sig = g2_sk.sign(msg2_hash.as_bytes());
        let block4 = make_block(
            &state,
            vec![Transaction::ApproveRecovery {
                owner_pk: *owner_pk,
                guardian_pk: *g2_pk,
                share_data: share_data_2.to_string(),
                signature: g2_sig.to_bytes().to_vec(),
            }],
        );
        state.apply_block(&block4).unwrap();

        // Now completed
        let req = state.recovery_requests.get(owner_pk).unwrap();
        assert_eq!(req.status, super::RecoveryStatus::Completed);
        assert_eq!(req.approvals.len(), 2);
    }

    #[test]
    fn revoke_keys() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);
        let (owner_sk, owner_pk) = &keys[0];

        // Revoke and set new key
        let (_, new_pk) = make_keypair(50);
        let mut revoke_msg = Vec::new();
        revoke_msg.extend_from_slice(b"zk-vault:revoke-keys:");
        revoke_msg.extend_from_slice(&new_pk);
        let msg_hash = blake3::hash(&revoke_msg);
        let sig = owner_sk.sign(msg_hash.as_bytes());
        let tx = Transaction::RevokeKeys {
            owner_pk: *owner_pk,
            new_ed25519_pk: new_pk,
            signature: sig.to_bytes().to_vec(),
        };
        let block = make_block(&state, vec![tx]);
        state.apply_block(&block).unwrap();

        let ke = state.key_registry.get(owner_pk).unwrap();
        assert_eq!(ke.current_pk, new_pk);
        assert!(ke.revoked_pks.contains(owner_pk));
        assert_eq!(ke.last_rotated, Height(1));
    }

    #[test]
    fn register_with_revoked_key_fails() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);
        let (owner_sk, owner_pk) = &keys[0];

        // Revoke key
        let (_, new_pk) = make_keypair(50);
        let mut revoke_msg = Vec::new();
        revoke_msg.extend_from_slice(b"zk-vault:revoke-keys:");
        revoke_msg.extend_from_slice(&new_pk);
        let msg_hash = blake3::hash(&revoke_msg);
        let sig = owner_sk.sign(msg_hash.as_bytes());
        let block = make_block(
            &state,
            vec![Transaction::RevokeKeys {
                owner_pk: *owner_pk,
                new_ed25519_pk: new_pk,
                signature: sig.to_bytes().to_vec(),
            }],
        );
        state.apply_block(&block).unwrap();

        // Try to register a file with the old (now revoked) key
        let merkle_root = [0xAB; 32];
        let file_sig = owner_sk.sign(&merkle_root);
        let tx = Transaction::RegisterFile {
            merkle_root,
            file_count: 1,
            encrypted_size: 100,
            owner_pk: *owner_pk,
            signature: file_sig.to_bytes().to_vec(),
        };
        let block2 = make_block(&state, vec![tx]);
        let result = state.apply_block(&block2);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_blocks_sequential() {
        let (vs, keys) = test_validator_set();
        let mut state = ChainState::genesis(vs);

        for i in 0..5u8 {
            let (sk, pk) = &keys[0];
            let mut merkle_root = [0u8; 32];
            merkle_root[0] = i;
            let sig = sk.sign(&merkle_root);

            let tx = Transaction::RegisterFile {
                merkle_root,
                file_count: i as u32 + 1,
                encrypted_size: 1000,
                owner_pk: *pk,
                signature: sig.to_bytes().to_vec(),
            };
            let block = make_block(&state, vec![tx]);
            state.apply_block(&block).unwrap();
        }

        assert_eq!(state.height, Height(5));
        assert_eq!(state.file_count(), 5);
    }
}

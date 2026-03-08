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
        }
    }

    /// Compute the state root: BLAKE3 hash of the file registry entries.
    pub fn state_root(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for (merkle_root, entry) in &self.file_registry {
            hasher.update(merkle_root);
            let entry_bytes =
                serde_json::to_vec(entry).expect("FileEntry serialization cannot fail");
            hasher.update(&entry_bytes);
        }
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

        // Update chain metadata
        self.height = block.header.height;
        self.last_block_id = block.id();

        Ok(())
    }

    /// Apply a single transaction to the state.
    fn apply_tx(&mut self, tx: &Transaction, height: Height) -> Result<()> {
        match tx {
            Transaction::RegisterFile {
                merkle_root,
                file_count,
                encrypted_size,
                owner_pk,
                signature,
            } => {
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
        }

        Ok(())
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

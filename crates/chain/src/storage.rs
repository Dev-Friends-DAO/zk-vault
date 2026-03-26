//! RocksDB persistence layer for chain state and blob storage.
//!
//! Uses Column Families to separate different data types:
//! - "default": chain metadata (height, block_id, validator_set)
//! - "blobs": encrypted data blobs (Mode B)
//! - "files": file registry entries
//! - "guardians": guardian registry
//! - "recovery": recovery requests
//! - "keys": key registry (revocation tracking)
//!
//! Chain state is persisted atomically using RocksDB `WriteBatch`.
//! This guarantees that either all changes from a block commit are
//! written, or none are — making the storage crash-safe.

use std::path::Path;

use rocksdb::{ColumnFamilyDescriptor, Options, DB};

use crate::state::{FileEntry, GuardianSet, KeyEntry, RecoveryRequest};
use crate::types::{BlockId, Height, ValidatorSet};

const CF_BLOBS: &str = "blobs";
const CF_FILES: &str = "files";
const CF_GUARDIANS: &str = "guardians";
const CF_RECOVERY: &str = "recovery";
const CF_KEYS: &str = "keys";
const CF_BLOB_REPLICAS: &str = "blob_replicas";
const CF_BLOCKS: &str = "blocks";
const CF_ANCHORS: &str = "anchors";
const CF_DEALS: &str = "deals";

const META_HEIGHT: &[u8] = b"height";
const META_LAST_BLOCK_ID: &[u8] = b"last_block_id";
const META_VALIDATOR_SET: &[u8] = b"validator_set";
const META_ENDOWMENT_CONFIG: &[u8] = b"endowment_config";
const META_ENDOWMENT_POOL: &[u8] = b"endowment_pool";

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("RocksDB error: {0}")]
    Rocks(#[from] rocksdb::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Data not found: {0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// RocksDB-backed persistent storage.
pub struct Storage {
    db: DB,
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Storage")
            .field("path", &self.db.path())
            .finish()
    }
}

impl Storage {
    /// Open or create a RocksDB database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new("default", Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOBS, Options::default()),
            ColumnFamilyDescriptor::new(CF_FILES, Options::default()),
            ColumnFamilyDescriptor::new(CF_GUARDIANS, Options::default()),
            ColumnFamilyDescriptor::new(CF_RECOVERY, Options::default()),
            ColumnFamilyDescriptor::new(CF_KEYS, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOB_REPLICAS, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_ANCHORS, Options::default()),
            ColumnFamilyDescriptor::new(CF_DEALS, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)?;
        Ok(Self { db })
    }

    /// Get a column family handle, returning an error if not found.
    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::NotFound(format!("Column family '{name}' not found")))
    }

    // ── Metadata operations ──

    pub fn save_height(&self, height: Height) -> Result<()> {
        self.db.put(META_HEIGHT, height.0.to_le_bytes())?;
        Ok(())
    }

    pub fn load_height(&self) -> Result<Option<Height>> {
        match self.db.get(META_HEIGHT)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| StorageError::Serialization("Invalid height bytes".into()))?;
                Ok(Some(Height(u64::from_le_bytes(arr))))
            }
            None => Ok(None),
        }
    }

    pub fn save_last_block_id(&self, id: &BlockId) -> Result<()> {
        self.db.put(META_LAST_BLOCK_ID, id.as_bytes())?;
        Ok(())
    }

    pub fn load_last_block_id(&self) -> Result<Option<BlockId>> {
        match self.db.get(META_LAST_BLOCK_ID)? {
            Some(bytes) => {
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| StorageError::Serialization("Invalid block ID bytes".into()))?;
                Ok(Some(BlockId::new(arr)))
            }
            None => Ok(None),
        }
    }

    pub fn save_validator_set(&self, vs: &ValidatorSet) -> Result<()> {
        let json =
            serde_json::to_vec(vs).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(META_VALIDATOR_SET, json)?;
        Ok(())
    }

    pub fn load_validator_set(&self) -> Result<Option<ValidatorSet>> {
        match self.db.get(META_VALIDATOR_SET)? {
            Some(bytes) => {
                let vs = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(vs))
            }
            None => Ok(None),
        }
    }

    // ── Endowment operations ──

    pub fn save_endowment_config(&self, config: &crate::state::EndowmentConfig) -> Result<()> {
        let json =
            serde_json::to_vec(config).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(META_ENDOWMENT_CONFIG, json)?;
        Ok(())
    }

    pub fn load_endowment_config(&self) -> Result<Option<crate::state::EndowmentConfig>> {
        match self.db.get(META_ENDOWMENT_CONFIG)? {
            Some(bytes) => {
                let config = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    pub fn save_endowment_pool(&self, pool: &crate::state::EndowmentPool) -> Result<()> {
        let json =
            serde_json::to_vec(pool).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(META_ENDOWMENT_POOL, json)?;
        Ok(())
    }

    pub fn load_endowment_pool(&self) -> Result<Option<crate::state::EndowmentPool>> {
        match self.db.get(META_ENDOWMENT_POOL)? {
            Some(bytes) => {
                let pool = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(pool))
            }
            None => Ok(None),
        }
    }

    // ── Blob operations (CF: blobs) ──

    pub fn put_blob(&self, key: &str, data: &[u8]) -> Result<()> {
        let cf = self.cf(CF_BLOBS)?;
        self.db.put_cf(&cf, key.as_bytes(), data)?;
        Ok(())
    }

    pub fn get_blob(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let cf = self.cf(CF_BLOBS)?;
        Ok(self.db.get_cf(&cf, key.as_bytes())?)
    }

    pub fn delete_blob(&self, key: &str) -> Result<()> {
        let cf = self.cf(CF_BLOBS)?;
        self.db.delete_cf(&cf, key.as_bytes())?;
        Ok(())
    }

    pub fn list_blob_keys(&self) -> Result<Vec<String>> {
        let cf = self.cf(CF_BLOBS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut keys = Vec::new();
        for item in iter {
            let (key, _) = item?;
            if let Ok(s) = String::from_utf8(key.to_vec()) {
                keys.push(s);
            }
        }
        Ok(keys)
    }

    pub fn blob_count_and_size(&self) -> Result<(usize, u64)> {
        let cf = self.cf(CF_BLOBS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut count = 0usize;
        let mut total_size = 0u64;
        for item in iter {
            let (_, value) = item?;
            count += 1;
            total_size += value.len() as u64;
        }
        Ok((count, total_size))
    }

    // ── File registry operations (CF: files) ──

    pub fn put_file(&self, merkle_root: &[u8; 32], entry: &FileEntry) -> Result<()> {
        let cf = self.cf(CF_FILES)?;
        let key = hex::encode(merkle_root);
        let value =
            serde_json::to_vec(entry).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put_cf(&cf, key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_file(&self, merkle_root: &[u8; 32]) -> Result<Option<FileEntry>> {
        let cf = self.cf(CF_FILES)?;
        let key = hex::encode(merkle_root);
        match self.db.get_cf(&cf, key.as_bytes())? {
            Some(bytes) => {
                let entry = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    pub fn load_all_files(&self) -> Result<std::collections::BTreeMap<[u8; 32], FileEntry>> {
        let cf = self.cf(CF_FILES)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut map = std::collections::BTreeMap::new();
        for item in iter {
            let (key, value) = item?;
            let key_str = String::from_utf8(key.to_vec())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let merkle_root_bytes =
                hex::decode(&key_str).map_err(|e| StorageError::Serialization(e.to_string()))?;
            let merkle_root: [u8; 32] = merkle_root_bytes
                .try_into()
                .map_err(|_| StorageError::Serialization("Invalid merkle root length".into()))?;
            let entry: FileEntry = serde_json::from_slice(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            map.insert(merkle_root, entry);
        }
        Ok(map)
    }

    // ── Guardian registry operations (CF: guardians) ──

    pub fn put_guardian_set(&self, owner_pk: &[u8; 32], set: &GuardianSet) -> Result<()> {
        let cf = self.cf(CF_GUARDIANS)?;
        let key = hex::encode(owner_pk);
        let value =
            serde_json::to_vec(set).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put_cf(&cf, key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_guardian_set(&self, owner_pk: &[u8; 32]) -> Result<Option<GuardianSet>> {
        let cf = self.cf(CF_GUARDIANS)?;
        let key = hex::encode(owner_pk);
        match self.db.get_cf(&cf, key.as_bytes())? {
            Some(bytes) => {
                let set = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(set))
            }
            None => Ok(None),
        }
    }

    pub fn load_all_guardians(&self) -> Result<std::collections::BTreeMap<[u8; 32], GuardianSet>> {
        let cf = self.cf(CF_GUARDIANS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut map = std::collections::BTreeMap::new();
        for item in iter {
            let (key, value) = item?;
            let key_str = String::from_utf8(key.to_vec())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let pk_bytes =
                hex::decode(&key_str).map_err(|e| StorageError::Serialization(e.to_string()))?;
            let pk: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| StorageError::Serialization("Invalid pk length".into()))?;
            let set: GuardianSet = serde_json::from_slice(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            map.insert(pk, set);
        }
        Ok(map)
    }

    // ── Recovery request operations (CF: recovery) ──

    pub fn put_recovery_request(&self, owner_pk: &[u8; 32], req: &RecoveryRequest) -> Result<()> {
        let cf = self.cf(CF_RECOVERY)?;
        let key = hex::encode(owner_pk);
        let value =
            serde_json::to_vec(req).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put_cf(&cf, key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_recovery_request(&self, owner_pk: &[u8; 32]) -> Result<Option<RecoveryRequest>> {
        let cf = self.cf(CF_RECOVERY)?;
        let key = hex::encode(owner_pk);
        match self.db.get_cf(&cf, key.as_bytes())? {
            Some(bytes) => {
                let req = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(req))
            }
            None => Ok(None),
        }
    }

    pub fn load_all_recovery_requests(
        &self,
    ) -> Result<std::collections::BTreeMap<[u8; 32], RecoveryRequest>> {
        let cf = self.cf(CF_RECOVERY)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut map = std::collections::BTreeMap::new();
        for item in iter {
            let (key, value) = item?;
            let key_str = String::from_utf8(key.to_vec())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let pk_bytes =
                hex::decode(&key_str).map_err(|e| StorageError::Serialization(e.to_string()))?;
            let pk: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| StorageError::Serialization("Invalid pk length".into()))?;
            let req: RecoveryRequest = serde_json::from_slice(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            map.insert(pk, req);
        }
        Ok(map)
    }

    // ── Key registry operations (CF: keys) ──

    pub fn put_key_entry(&self, owner_pk: &[u8; 32], entry: &KeyEntry) -> Result<()> {
        let cf = self.cf(CF_KEYS)?;
        let key = hex::encode(owner_pk);
        let value =
            serde_json::to_vec(entry).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put_cf(&cf, key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_key_entry(&self, owner_pk: &[u8; 32]) -> Result<Option<KeyEntry>> {
        let cf = self.cf(CF_KEYS)?;
        let key = hex::encode(owner_pk);
        match self.db.get_cf(&cf, key.as_bytes())? {
            Some(bytes) => {
                let entry = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    pub fn load_all_keys(&self) -> Result<std::collections::BTreeMap<[u8; 32], KeyEntry>> {
        let cf = self.cf(CF_KEYS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut map = std::collections::BTreeMap::new();
        for item in iter {
            let (key, value) = item?;
            let key_str = String::from_utf8(key.to_vec())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let pk_bytes =
                hex::decode(&key_str).map_err(|e| StorageError::Serialization(e.to_string()))?;
            let pk: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| StorageError::Serialization("Invalid pk length".into()))?;
            let entry: KeyEntry = serde_json::from_slice(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            map.insert(pk, entry);
        }
        Ok(map)
    }

    // ── Blob replicas operations (CF: blob_replicas) ──

    pub fn load_all_blob_replicas(
        &self,
    ) -> Result<std::collections::BTreeMap<String, std::collections::BTreeSet<[u8; 32]>>> {
        let cf = self.cf(CF_BLOB_REPLICAS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut map = std::collections::BTreeMap::new();
        for item in iter {
            let (key, value) = item?;
            let blob_key = String::from_utf8(key.to_vec())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let replicas: std::collections::BTreeSet<[u8; 32]> = serde_json::from_slice(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            map.insert(blob_key, replicas);
        }
        Ok(map)
    }

    // ── Anchor history operations (CF: anchors) ──

    pub fn load_all_anchors(
        &self,
    ) -> Result<std::collections::BTreeMap<u64, crate::state::AnchorEntry>> {
        let cf = self.cf(CF_ANCHORS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut map = std::collections::BTreeMap::new();
        for item in iter {
            let (key, value) = item?;
            let epoch_bytes: [u8; 8] = key
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Serialization("Invalid epoch key length".into()))?;
            let epoch = u64::from_be_bytes(epoch_bytes);
            let entry: crate::state::AnchorEntry = serde_json::from_slice(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            map.insert(epoch, entry);
        }
        Ok(map)
    }

    // ── Deal registry operations (CF: deals) ──

    pub fn load_all_deals(
        &self,
    ) -> Result<std::collections::BTreeMap<String, Vec<crate::state::DealEntry>>> {
        let cf = self.cf(CF_DEALS)?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut map = std::collections::BTreeMap::new();
        for item in iter {
            let (key, value) = item?;
            let cid = String::from_utf8(key.to_vec())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            let deals: Vec<crate::state::DealEntry> = serde_json::from_slice(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            map.insert(cid, deals);
        }
        Ok(map)
    }

    // ── Block history operations (CF: blocks) ──

    pub fn save_block(&self, height: Height, block: &crate::types::Block) -> Result<()> {
        let cf = self.cf(CF_BLOCKS)?;
        let key = height.0.to_be_bytes();
        let value =
            serde_json::to_vec(block).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put_cf(&cf, key, value)?;
        Ok(())
    }

    pub fn load_block(&self, height: Height) -> Result<Option<crate::types::Block>> {
        let cf = self.cf(CF_BLOCKS)?;
        let key = height.0.to_be_bytes();
        match self.db.get_cf(&cf, key)? {
            Some(bytes) => {
                let block = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    pub fn load_blocks(&self, from: Height, to: Height) -> Result<Vec<crate::types::Block>> {
        let cf = self.cf(CF_BLOCKS)?;
        let mut blocks = Vec::new();
        for h in from.0..=to.0 {
            let key = h.to_be_bytes();
            if let Some(bytes) = self.db.get_cf(&cf, key)? {
                let block: crate::types::Block = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    // ── Bulk save (after apply_block) ──

    /// Save the full chain state to RocksDB atomically using WriteBatch.
    /// Either all changes are persisted or none (crash-safe).
    pub fn save_chain_state(&self, state: &crate::state::ChainState) -> Result<()> {
        use rocksdb::WriteBatch;

        let mut batch = WriteBatch::default();

        // Metadata
        batch.put(META_HEIGHT, state.height.0.to_le_bytes());
        batch.put(META_LAST_BLOCK_ID, state.last_block_id.as_bytes());
        let vs_json = serde_json::to_vec(&state.validator_set)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        batch.put(META_VALIDATOR_SET, vs_json);

        // File registry
        let cf_files = self.cf(CF_FILES)?;
        for (root, entry) in &state.file_registry {
            let key = hex::encode(root);
            let value = serde_json::to_vec(entry)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            batch.put_cf(&cf_files, key.as_bytes(), value);
        }

        // Guardian registry
        let cf_guardians = self.cf(CF_GUARDIANS)?;
        for (pk, set) in &state.guardian_registry {
            let key = hex::encode(pk);
            let value =
                serde_json::to_vec(set).map_err(|e| StorageError::Serialization(e.to_string()))?;
            batch.put_cf(&cf_guardians, key.as_bytes(), value);
        }

        // Recovery requests
        let cf_recovery = self.cf(CF_RECOVERY)?;
        for (pk, req) in &state.recovery_requests {
            let key = hex::encode(pk);
            let value =
                serde_json::to_vec(req).map_err(|e| StorageError::Serialization(e.to_string()))?;
            batch.put_cf(&cf_recovery, key.as_bytes(), value);
        }

        // Key registry
        let cf_keys = self.cf(CF_KEYS)?;
        for (pk, entry) in &state.key_registry {
            let key = hex::encode(pk);
            let value = serde_json::to_vec(entry)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            batch.put_cf(&cf_keys, key.as_bytes(), value);
        }

        // Blob replicas
        let cf_blob_replicas = self.cf(CF_BLOB_REPLICAS)?;
        for (blob_key, replicas) in &state.blob_replicas {
            let value = serde_json::to_vec(replicas)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            batch.put_cf(&cf_blob_replicas, blob_key.as_bytes(), value);
        }

        // Anchor history
        let cf_anchors = self.cf(CF_ANCHORS)?;
        for (epoch, entry) in &state.anchor_history {
            let key = epoch.to_be_bytes();
            let value = serde_json::to_vec(entry)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            batch.put_cf(&cf_anchors, key, value);
        }

        // Deal registry
        let cf_deals = self.cf(CF_DEALS)?;
        for (cid, deals) in &state.deal_registry {
            let value = serde_json::to_vec(deals)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            batch.put_cf(&cf_deals, cid.as_bytes(), value);
        }

        // Endowment
        let endowment_config_json = serde_json::to_vec(&state.endowment_config)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        batch.put(META_ENDOWMENT_CONFIG, endowment_config_json);
        let endowment_pool_json = serde_json::to_vec(&state.endowment_pool)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        batch.put(META_ENDOWMENT_POOL, endowment_pool_json);

        // Atomic write
        self.db.write(batch)?;

        Ok(())
    }

    /// Load full chain state from RocksDB. Returns None if no state saved (fresh DB).
    pub fn load_chain_state(&self) -> Result<Option<crate::state::ChainState>> {
        let height = match self.load_height()? {
            Some(h) => h,
            None => return Ok(None),
        };
        let last_block_id = self
            .load_last_block_id()?
            .ok_or_else(|| StorageError::NotFound("last_block_id".into()))?;
        let validator_set = self
            .load_validator_set()?
            .ok_or_else(|| StorageError::NotFound("validator_set".into()))?;

        let file_registry = self.load_all_files()?;
        let guardian_registry = self.load_all_guardians()?;
        let recovery_requests = self.load_all_recovery_requests()?;
        let key_registry = self.load_all_keys()?;
        let blob_replicas = self.load_all_blob_replicas()?;
        let anchor_history = self.load_all_anchors()?;
        let deal_registry = self.load_all_deals()?;
        let endowment_config = self.load_endowment_config()?.unwrap_or_default();
        let endowment_pool = self.load_endowment_pool()?.unwrap_or_default();

        Ok(Some(crate::state::ChainState {
            height,
            last_block_id,
            validator_set,
            file_registry,
            guardian_registry,
            recovery_requests,
            key_registry,
            blob_replicas,
            anchor_history,
            deal_registry,
            endowment_config,
            endowment_pool,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::*;
    use crate::types::*;
    use std::collections::BTreeSet;

    fn open_temp_storage() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        (storage, dir)
    }

    #[test]
    fn metadata_roundtrip() {
        let (storage, _dir) = open_temp_storage();

        storage.save_height(Height(42)).unwrap();
        assert_eq!(storage.load_height().unwrap(), Some(Height(42)));

        let block_id = BlockId::new([0xAB; 32]);
        storage.save_last_block_id(&block_id).unwrap();
        assert_eq!(
            storage.load_last_block_id().unwrap().unwrap().as_bytes(),
            block_id.as_bytes()
        );
    }

    #[test]
    fn blob_operations() {
        let (storage, _dir) = open_temp_storage();

        storage.put_blob("key1", &[1, 2, 3]).unwrap();
        storage.put_blob("key2", &[4, 5, 6, 7]).unwrap();

        assert_eq!(storage.get_blob("key1").unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(storage.get_blob("nonexistent").unwrap(), None);

        let (count, size) = storage.blob_count_and_size().unwrap();
        assert_eq!(count, 2);
        assert_eq!(size, 7);

        let mut keys = storage.list_blob_keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["key1", "key2"]);

        storage.delete_blob("key1").unwrap();
        assert_eq!(storage.get_blob("key1").unwrap(), None);
    }

    #[test]
    fn file_registry_roundtrip() {
        let (storage, _dir) = open_temp_storage();
        let root = [0xAB; 32];
        let entry = FileEntry {
            owner_pk: [1u8; 32],
            file_count: 5,
            encrypted_size: 1024,
            registered_at: Height(1),
            verifications: BTreeSet::new(),
        };

        storage.put_file(&root, &entry).unwrap();
        let loaded = storage.get_file(&root).unwrap().unwrap();
        assert_eq!(loaded.owner_pk, entry.owner_pk);
        assert_eq!(loaded.file_count, 5);
    }

    #[test]
    fn chain_state_full_roundtrip() {
        let (storage, _dir) = open_temp_storage();

        // Initially empty
        assert!(storage.load_chain_state().unwrap().is_none());

        // Create a state with some data
        let validators = vec![Validator::new([1u8; 32], 100)];
        let vs = ValidatorSet::new(validators);
        let mut state = crate::state::ChainState::genesis(vs);

        // Add a file entry
        state.file_registry.insert(
            [0xAB; 32],
            FileEntry {
                owner_pk: [1u8; 32],
                file_count: 3,
                encrypted_size: 500,
                registered_at: Height(1),
                verifications: BTreeSet::new(),
            },
        );

        // Save and reload
        storage.save_chain_state(&state).unwrap();
        let loaded = storage.load_chain_state().unwrap().unwrap();

        assert_eq!(loaded.height, state.height);
        assert_eq!(loaded.file_registry.len(), 1);
        assert_eq!(loaded.file_registry[&[0xAB; 32]].file_count, 3);
    }

    #[test]
    fn fresh_db_returns_none() {
        let (storage, _dir) = open_temp_storage();
        assert!(storage.load_chain_state().unwrap().is_none());
        assert!(storage.load_height().unwrap().is_none());
    }

    #[test]
    fn save_chain_state_is_atomic() {
        let (storage, _dir) = open_temp_storage();

        let validators = vec![Validator::new([1u8; 32], 100)];
        let vs = ValidatorSet::new(validators);
        let mut state = crate::state::ChainState::genesis(vs);

        // Add multiple entries across different registries
        state.file_registry.insert(
            [0xAA; 32],
            FileEntry {
                owner_pk: [1u8; 32],
                file_count: 1,
                encrypted_size: 100,
                registered_at: Height(1),
                verifications: BTreeSet::new(),
            },
        );
        state.file_registry.insert(
            [0xBB; 32],
            FileEntry {
                owner_pk: [2u8; 32],
                file_count: 2,
                encrypted_size: 200,
                registered_at: Height(1),
                verifications: BTreeSet::new(),
            },
        );

        // Save atomically
        storage.save_chain_state(&state).unwrap();

        // Verify all entries persisted
        let loaded = storage.load_chain_state().unwrap().unwrap();
        assert_eq!(loaded.file_registry.len(), 2);
        assert_eq!(loaded.height, state.height);
    }
}

//! Persistent blob store for Mode B (native validator storage).
//!
//! Backed by RocksDB via the shared Storage layer.

use std::sync::Arc;

use crate::storage::{Storage, StorageError};

/// RocksDB-backed blob store for encrypted backup data.
pub struct BlobStore {
    storage: Arc<Storage>,
}

impl std::fmt::Debug for BlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobStore").finish()
    }
}

impl BlobStore {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    /// Store a blob. Overwrites if key already exists.
    pub fn put(&self, key: String, data: Vec<u8>) -> Result<usize, StorageError> {
        let size = data.len();
        self.storage.put_blob(&key, &data)?;
        Ok(size)
    }

    /// Retrieve a blob by key.
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.storage.get_blob(key)
    }

    /// Check if a blob exists.
    pub fn exists(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self.storage.get_blob(key)?.is_some())
    }

    /// Delete a blob. Returns true if it existed.
    pub fn delete(&self, key: &str) -> Result<bool, StorageError> {
        let existed = self.exists(key)?;
        if existed {
            self.storage.delete_blob(key)?;
        }
        Ok(existed)
    }

    /// Number of stored blobs.
    pub fn len(&self) -> Result<usize, StorageError> {
        let (count, _) = self.storage.blob_count_and_size()?;
        Ok(count)
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> Result<bool, StorageError> {
        Ok(self.len()? == 0)
    }

    /// Total bytes stored.
    pub fn total_size(&self) -> Result<u64, StorageError> {
        let (_, size) = self.storage.blob_count_and_size()?;
        Ok(size)
    }

    /// List all keys.
    pub fn keys(&self) -> Result<Vec<String>, StorageError> {
        self.storage.list_blob_keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;

    fn test_store() -> (BlobStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(dir.path()).unwrap());
        (BlobStore::new(storage), dir)
    }

    #[test]
    fn put_and_get() {
        let (store, _dir) = test_store();
        store.put("key1".to_string(), vec![1, 2, 3]).unwrap();
        assert_eq!(store.get("key1").unwrap(), Some(vec![1, 2, 3]));
        assert_eq!(store.get("key2").unwrap(), None);
    }

    #[test]
    fn exists_and_delete() {
        let (store, _dir) = test_store();
        store.put("key1".to_string(), vec![1]).unwrap();
        assert!(store.exists("key1").unwrap());
        assert!(!store.exists("key2").unwrap());

        assert!(store.delete("key1").unwrap());
        assert!(!store.exists("key1").unwrap());
        assert!(!store.delete("key1").unwrap()); // already deleted
    }

    #[test]
    fn len_and_total_size() {
        let (store, _dir) = test_store();
        assert!(store.is_empty().unwrap());

        store.put("a".to_string(), vec![0; 100]).unwrap();
        store.put("b".to_string(), vec![0; 200]).unwrap();

        assert_eq!(store.len().unwrap(), 2);
        assert_eq!(store.total_size().unwrap(), 300);
    }

    #[test]
    fn overwrite() {
        let (store, _dir) = test_store();
        store.put("key".to_string(), vec![1, 2, 3]).unwrap();
        store.put("key".to_string(), vec![4, 5]).unwrap();
        assert_eq!(store.get("key").unwrap(), Some(vec![4, 5]));
        assert_eq!(store.len().unwrap(), 1);
    }

    #[test]
    fn keys_list() {
        let (store, _dir) = test_store();
        store.put("b".to_string(), vec![1]).unwrap();
        store.put("a".to_string(), vec![2]).unwrap();
        let mut keys = store.keys().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }
}

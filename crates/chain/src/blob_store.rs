//! Persistent blob store for Mode B (native validator storage).
//!
//! Backed by RocksDB via the shared Storage layer.

use std::sync::Arc;

use crate::storage::Storage;

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
    pub fn put(&self, key: String, data: Vec<u8>) -> usize {
        let size = data.len();
        self.storage
            .put_blob(&key, &data)
            .expect("BlobStore put failed");
        size
    }

    /// Retrieve a blob by key.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.storage.get_blob(key).expect("BlobStore get failed")
    }

    /// Check if a blob exists.
    pub fn exists(&self, key: &str) -> bool {
        self.storage
            .get_blob(key)
            .expect("BlobStore exists failed")
            .is_some()
    }

    /// Delete a blob. Returns true if it existed.
    pub fn delete(&self, key: &str) -> bool {
        let existed = self.exists(key);
        if existed {
            self.storage
                .delete_blob(key)
                .expect("BlobStore delete failed");
        }
        existed
    }

    /// Number of stored blobs.
    pub fn len(&self) -> usize {
        let (count, _) = self
            .storage
            .blob_count_and_size()
            .expect("BlobStore count failed");
        count
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes stored.
    pub fn total_size(&self) -> u64 {
        let (_, size) = self
            .storage
            .blob_count_and_size()
            .expect("BlobStore size failed");
        size
    }

    /// List all keys.
    pub fn keys(&self) -> Vec<String> {
        self.storage
            .list_blob_keys()
            .expect("BlobStore keys failed")
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
        store.put("key1".to_string(), vec![1, 2, 3]);
        assert_eq!(store.get("key1"), Some(vec![1, 2, 3]));
        assert_eq!(store.get("key2"), None);
    }

    #[test]
    fn exists_and_delete() {
        let (store, _dir) = test_store();
        store.put("key1".to_string(), vec![1]);
        assert!(store.exists("key1"));
        assert!(!store.exists("key2"));

        assert!(store.delete("key1"));
        assert!(!store.exists("key1"));
        assert!(!store.delete("key1")); // already deleted
    }

    #[test]
    fn len_and_total_size() {
        let (store, _dir) = test_store();
        assert!(store.is_empty());

        store.put("a".to_string(), vec![0; 100]);
        store.put("b".to_string(), vec![0; 200]);

        assert_eq!(store.len(), 2);
        assert_eq!(store.total_size(), 300);
    }

    #[test]
    fn overwrite() {
        let (store, _dir) = test_store();
        store.put("key".to_string(), vec![1, 2, 3]);
        store.put("key".to_string(), vec![4, 5]);
        assert_eq!(store.get("key"), Some(vec![4, 5]));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn keys_list() {
        let (store, _dir) = test_store();
        store.put("b".to_string(), vec![1]);
        store.put("a".to_string(), vec![2]);
        let mut keys = store.keys();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }
}

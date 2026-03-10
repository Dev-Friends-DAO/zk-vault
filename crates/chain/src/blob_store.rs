//! In-memory blob store for Mode B (native validator storage).
//!
//! Stores encrypted data blobs keyed by storage key. In Phase H this
//! will be backed by redb for persistence across restarts.

use std::collections::HashMap;

/// In-memory blob store for encrypted backup data.
#[derive(Debug, Clone, Default)]
pub struct BlobStore {
    /// Storage key → encrypted data.
    blobs: HashMap<String, Vec<u8>>,
}

impl BlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a blob. Overwrites if key already exists.
    pub fn put(&mut self, key: String, data: Vec<u8>) -> usize {
        let size = data.len();
        self.blobs.insert(key, data);
        size
    }

    /// Retrieve a blob by key.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.blobs.get(key).map(|v| v.as_slice())
    }

    /// Check if a blob exists.
    pub fn exists(&self, key: &str) -> bool {
        self.blobs.contains_key(key)
    }

    /// Delete a blob. Returns true if it existed.
    pub fn delete(&mut self, key: &str) -> bool {
        self.blobs.remove(key).is_some()
    }

    /// Number of stored blobs.
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Total bytes stored.
    pub fn total_size(&self) -> u64 {
        self.blobs.values().map(|v| v.len() as u64).sum()
    }

    /// List all keys.
    pub fn keys(&self) -> Vec<&str> {
        self.blobs.keys().map(|k| k.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get() {
        let mut store = BlobStore::new();
        store.put("key1".to_string(), vec![1, 2, 3]);
        assert_eq!(store.get("key1"), Some([1, 2, 3].as_slice()));
        assert_eq!(store.get("key2"), None);
    }

    #[test]
    fn exists_and_delete() {
        let mut store = BlobStore::new();
        store.put("key1".to_string(), vec![1]);
        assert!(store.exists("key1"));
        assert!(!store.exists("key2"));

        assert!(store.delete("key1"));
        assert!(!store.exists("key1"));
        assert!(!store.delete("key1")); // already deleted
    }

    #[test]
    fn len_and_total_size() {
        let mut store = BlobStore::new();
        assert!(store.is_empty());

        store.put("a".to_string(), vec![0; 100]);
        store.put("b".to_string(), vec![0; 200]);

        assert_eq!(store.len(), 2);
        assert_eq!(store.total_size(), 300);
    }

    #[test]
    fn overwrite() {
        let mut store = BlobStore::new();
        store.put("key".to_string(), vec![1, 2, 3]);
        store.put("key".to_string(), vec![4, 5]);
        assert_eq!(store.get("key"), Some([4, 5].as_slice()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn keys_list() {
        let mut store = BlobStore::new();
        store.put("b".to_string(), vec![1]);
        store.put("a".to_string(), vec![2]);
        let mut keys = store.keys();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }
}

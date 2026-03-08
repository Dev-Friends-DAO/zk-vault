/// BLAKE3 Merkle tree with domain separation.
///
/// Domain separation prevents second-preimage attacks:
///   leaf_hash(data)     = BLAKE3(0x00 || data)
///   internal_hash(l, r) = BLAKE3(0x01 || l || r)
///
/// If the number of leaves at any level is odd, the last node is promoted
/// (not duplicated), avoiding the CVE-2012-2459 vulnerability.
use crate::crypto::hash;

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

/// Hash a leaf node with domain separation.
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + data.len());
    input.push(LEAF_PREFIX);
    input.extend_from_slice(data);
    hash::hash(&input)
}

/// Hash two child nodes to produce a parent.
pub fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + 64);
    input.push(INTERNAL_PREFIX);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    hash::hash(&input)
}

/// A BLAKE3 Merkle tree.
pub struct MerkleTree {
    /// All levels of the tree. levels[0] = leaves, levels[last] = [root].
    pub(crate) levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data.
    /// Each item in `leaf_data` is hashed with the leaf prefix.
    pub fn from_leaves(leaf_data: &[&[u8]]) -> Self {
        if leaf_data.is_empty() {
            return Self {
                levels: vec![vec![]],
            };
        }

        let leaves: Vec<[u8; 32]> = leaf_data.iter().map(|d| leaf_hash(d)).collect();
        let mut levels = vec![leaves];

        // Build tree bottom-up
        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next = Vec::with_capacity(current.len().div_ceil(2));

            let mut i = 0;
            while i + 1 < current.len() {
                next.push(internal_hash(&current[i], &current[i + 1]));
                i += 2;
            }
            // Odd node: promote without duplication
            if i < current.len() {
                next.push(current[i]);
            }

            levels.push(next);
        }

        Self { levels }
    }

    /// Build from pre-computed leaf hashes.
    pub fn from_leaf_hashes(leaves: Vec<[u8; 32]>) -> Self {
        if leaves.is_empty() {
            return Self {
                levels: vec![vec![]],
            };
        }

        let mut levels = vec![leaves];

        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next = Vec::with_capacity(current.len().div_ceil(2));

            let mut i = 0;
            while i + 1 < current.len() {
                next.push(internal_hash(&current[i], &current[i + 1]));
                i += 2;
            }
            if i < current.len() {
                next.push(current[i]);
            }

            levels.push(next);
        }

        Self { levels }
    }

    /// Get the Merkle root. Returns None if tree is empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        self.levels.last()?.first().copied()
    }

    /// Number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.levels.first().map_or(0, |l| l.len())
    }

    /// Get the leaf hashes.
    pub fn leaves(&self) -> &[[u8; 32]] {
        self.levels.first().map_or(&[], |l| l.as_slice())
    }

    /// Get all levels (for debugging/testing).
    pub fn levels(&self) -> &[Vec<[u8; 32]>] {
        &self.levels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let tree = MerkleTree::from_leaves(&[b"hello"]);
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.root(), Some(leaf_hash(b"hello")));
    }

    #[test]
    fn test_two_leaves() {
        let tree = MerkleTree::from_leaves(&[b"a", b"b"]);
        let expected = internal_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
        assert_eq!(tree.root(), Some(expected));
    }

    #[test]
    fn test_three_leaves_odd_promotion() {
        let tree = MerkleTree::from_leaves(&[b"a", b"b", b"c"]);
        // Level 0: [H(a), H(b), H(c)]
        // Level 1: [H(H(a)||H(b)), H(c)]  (H(c) promoted)
        // Level 2: [H(level1[0] || level1[1])]
        let h_ab = internal_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
        let h_c = leaf_hash(b"c"); // promoted, not duplicated
        let root = internal_hash(&h_ab, &h_c);
        assert_eq!(tree.root(), Some(root));
    }

    #[test]
    fn test_four_leaves() {
        let tree = MerkleTree::from_leaves(&[b"a", b"b", b"c", b"d"]);
        let h_ab = internal_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
        let h_cd = internal_hash(&leaf_hash(b"c"), &leaf_hash(b"d"));
        let root = internal_hash(&h_ab, &h_cd);
        assert_eq!(tree.root(), Some(root));
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::from_leaves(&[]);
        assert_eq!(tree.root(), None);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_deterministic() {
        let t1 = MerkleTree::from_leaves(&[b"x", b"y", b"z"]);
        let t2 = MerkleTree::from_leaves(&[b"x", b"y", b"z"]);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn test_domain_separation() {
        // A leaf hash should differ from an internal hash of the same data
        let data = [0u8; 64];
        let lh = leaf_hash(&data);
        let ih = internal_hash(
            &data[..32].try_into().unwrap(),
            &data[32..].try_into().unwrap(),
        );
        assert_ne!(lh, ih);
    }
}

/// Merkle inclusion proof generation and verification.
use super::tree::{internal_hash, MerkleTree};
use serde::{Deserialize, Serialize};

/// Position of a sibling in a Merkle proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Position {
    Left,
    Right,
}

/// A Merkle inclusion proof for a single leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: [u8; 32],
    pub siblings: Vec<(Position, [u8; 32])>,
}

impl MerkleTree {
    /// Generate an inclusion proof for the leaf at `index`.
    pub fn prove(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaf_count() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut idx = index;

        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            if level.len() <= 1 {
                break;
            }
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

            if sibling_idx < level.len() {
                let position = if idx % 2 == 0 {
                    Position::Right
                } else {
                    Position::Left
                };
                siblings.push((position, level[sibling_idx]));
            }
            // If sibling doesn't exist (odd promotion), no sibling needed at this level

            idx /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            leaf_hash: self.leaves()[index],
            siblings,
        })
    }
}

/// Verify a Merkle inclusion proof against a known root.
pub fn verify_proof(root: &[u8; 32], proof: &MerkleProof) -> bool {
    let mut current = proof.leaf_hash;

    for (position, sibling) in &proof.siblings {
        current = match position {
            Position::Left => internal_hash(sibling, &current),
            Position::Right => internal_hash(&current, sibling),
        };
    }

    &current == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::tree::MerkleTree;

    #[test]
    fn test_proof_single_leaf() {
        let tree = MerkleTree::from_leaves(&[b"only"]);
        let proof = tree.prove(0).unwrap();
        assert!(verify_proof(&tree.root().unwrap(), &proof));
    }

    #[test]
    fn test_proof_two_leaves() {
        let tree = MerkleTree::from_leaves(&[b"a", b"b"]);
        let root = tree.root().unwrap();

        let proof_a = tree.prove(0).unwrap();
        let proof_b = tree.prove(1).unwrap();

        assert!(verify_proof(&root, &proof_a));
        assert!(verify_proof(&root, &proof_b));
    }

    #[test]
    fn test_proof_four_leaves() {
        let tree = MerkleTree::from_leaves(&[b"w", b"x", b"y", b"z"]);
        let root = tree.root().unwrap();

        for i in 0..4 {
            let proof = tree.prove(i).unwrap();
            assert!(verify_proof(&root, &proof), "Proof failed for leaf {i}");
        }
    }

    #[test]
    fn test_proof_seven_leaves() {
        let items: Vec<Vec<u8>> = (0..7u8).map(|i| vec![i]).collect();
        let refs: Vec<&[u8]> = items.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::from_leaves(&refs);
        let root = tree.root().unwrap();

        for i in 0..7 {
            let proof = tree.prove(i).unwrap();
            assert!(verify_proof(&root, &proof), "Proof failed for leaf {i}");
        }
    }

    #[test]
    fn test_proof_wrong_root_fails() {
        let tree = MerkleTree::from_leaves(&[b"a", b"b"]);
        let proof = tree.prove(0).unwrap();
        let wrong_root = [0xFF; 32];
        assert!(!verify_proof(&wrong_root, &proof));
    }

    #[test]
    fn test_proof_out_of_bounds() {
        let tree = MerkleTree::from_leaves(&[b"a"]);
        assert!(tree.prove(1).is_none());
    }
}

/// Super Merkle Tree: aggregates multiple users' Merkle roots into a single
/// Super Root for cost-efficient blockchain anchoring.
///
/// Instead of anchoring each user's root individually (O(n) transactions),
/// all roots are combined into one tree and a single Super Root is anchored
/// (O(1) transactions). Each user receives a proof linking their root to the
/// Super Root.
///
/// ```text
/// User A Root ─┐
/// User B Root ─┤
/// User C Root ─┼──▶ Super Merkle Tree ──▶ Super Root
/// ...          │                              │
/// User N Root ─┘                              ▼
///                                     Bitcoin OP_RETURN (1 tx)
/// ```
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::proof::{verify_proof, MerkleProof};
use super::tree::MerkleTree;

/// An entry in the Super Merkle Tree: a user's root hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRoot {
    pub user_id: Uuid,
    pub merkle_root: [u8; 32],
}

/// The Super Merkle Tree with user-to-index mapping.
pub struct SuperMerkleTree {
    tree: MerkleTree,
    entries: Vec<UserRoot>,
}

/// A user-specific proof linking their root to the Super Root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSuperProof {
    pub user_id: Uuid,
    pub user_root: [u8; 32],
    pub super_root: [u8; 32],
    pub proof: MerkleProof,
}

impl SuperMerkleTree {
    /// Build a Super Merkle Tree from a list of user roots.
    ///
    /// The user roots are used directly as leaf hashes (they are already
    /// domain-separated Merkle roots from individual user trees).
    pub fn from_user_roots(entries: Vec<UserRoot>) -> Self {
        let leaf_hashes: Vec<[u8; 32]> = entries.iter().map(|e| e.merkle_root).collect();
        let tree = MerkleTree::from_leaf_hashes(leaf_hashes);
        Self { tree, entries }
    }

    /// Get the Super Root hash.
    pub fn super_root(&self) -> Option<[u8; 32]> {
        self.tree.root()
    }

    /// Generate a proof for a specific user by their UUID.
    pub fn prove_user(&self, user_id: &Uuid) -> Option<UserSuperProof> {
        let index = self.entries.iter().position(|e| &e.user_id == user_id)?;
        let proof = self.tree.prove(index)?;
        let super_root = self.tree.root()?;

        Some(UserSuperProof {
            user_id: *user_id,
            user_root: self.entries[index].merkle_root,
            super_root,
            proof,
        })
    }

    /// Generate proofs for all users. Returns a Vec in the same order as entries.
    pub fn prove_all(&self) -> Vec<UserSuperProof> {
        let super_root = match self.tree.root() {
            Some(r) => r,
            None => return vec![],
        };

        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| {
                let proof = self.tree.prove(i)?;
                Some(UserSuperProof {
                    user_id: entry.user_id,
                    user_root: entry.merkle_root,
                    super_root,
                    proof,
                })
            })
            .collect()
    }

    /// Number of users in the tree.
    pub fn user_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the user entries.
    pub fn entries(&self) -> &[UserRoot] {
        &self.entries
    }
}

/// Verify a user's Super Merkle proof against a known Super Root.
pub fn verify_user_proof(super_root: &[u8; 32], proof: &UserSuperProof) -> bool {
    // Check the proof's claimed super root matches
    if &proof.super_root != super_root {
        return false;
    }

    // Verify the Merkle inclusion proof
    verify_proof(super_root, &proof.proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user_root(id: Uuid, data: &[u8]) -> UserRoot {
        use crate::crypto::hash;
        UserRoot {
            user_id: id,
            merkle_root: hash::hash(data),
        }
    }

    #[test]
    fn test_single_user() {
        let id = Uuid::now_v7();
        let entries = vec![make_user_root(id, b"user-a-root")];
        let st = SuperMerkleTree::from_user_roots(entries);

        assert_eq!(st.user_count(), 1);
        let super_root = st.super_root().unwrap();

        let proof = st.prove_user(&id).unwrap();
        assert!(verify_user_proof(&super_root, &proof));
    }

    #[test]
    fn test_multiple_users() {
        let ids: Vec<Uuid> = (0..5).map(|_| Uuid::now_v7()).collect();
        let entries: Vec<UserRoot> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| make_user_root(*id, format!("user-{i}").as_bytes()))
            .collect();

        let st = SuperMerkleTree::from_user_roots(entries);
        let super_root = st.super_root().unwrap();

        for id in &ids {
            let proof = st.prove_user(id).unwrap();
            assert!(verify_user_proof(&super_root, &proof), "Failed for user {id}");
        }
    }

    #[test]
    fn test_prove_all() {
        let ids: Vec<Uuid> = (0..10).map(|_| Uuid::now_v7()).collect();
        let entries: Vec<UserRoot> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| make_user_root(*id, format!("root-{i}").as_bytes()))
            .collect();

        let st = SuperMerkleTree::from_user_roots(entries);
        let super_root = st.super_root().unwrap();
        let proofs = st.prove_all();

        assert_eq!(proofs.len(), 10);
        for proof in &proofs {
            assert!(verify_user_proof(&super_root, proof));
        }
    }

    #[test]
    fn test_wrong_super_root_fails() {
        let id = Uuid::now_v7();
        let entries = vec![make_user_root(id, b"data")];
        let st = SuperMerkleTree::from_user_roots(entries);

        let proof = st.prove_user(&id).unwrap();
        let wrong_root = [0xFF; 32];
        assert!(!verify_user_proof(&wrong_root, &proof));
    }

    #[test]
    fn test_unknown_user_returns_none() {
        let id = Uuid::now_v7();
        let unknown = Uuid::now_v7();
        let entries = vec![make_user_root(id, b"data")];
        let st = SuperMerkleTree::from_user_roots(entries);

        assert!(st.prove_user(&unknown).is_none());
    }

    #[test]
    fn test_empty_tree() {
        let st = SuperMerkleTree::from_user_roots(vec![]);
        assert_eq!(st.user_count(), 0);
        assert!(st.super_root().is_none());
        assert!(st.prove_all().is_empty());
    }

    #[test]
    fn test_large_batch() {
        let ids: Vec<Uuid> = (0..1000).map(|_| Uuid::now_v7()).collect();
        let entries: Vec<UserRoot> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| make_user_root(*id, format!("batch-{i}").as_bytes()))
            .collect();

        let st = SuperMerkleTree::from_user_roots(entries);
        let super_root = st.super_root().unwrap();

        // Spot-check a few
        for idx in [0, 499, 999] {
            let proof = st.prove_user(&ids[idx]).unwrap();
            assert!(verify_user_proof(&super_root, &proof));
        }
    }
}

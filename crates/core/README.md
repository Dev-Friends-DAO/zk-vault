# zk-vault-core

Core cryptographic library for zk-vault: post-quantum encryption, key management, Merkle trees, manifests, storage backends, and anchoring.

## Modules

```
zk-vault-core/
├── crypto/
│   ├── aead.rs        # XChaCha20-Poly1305 symmetric encryption
│   ├── bundle.rs      # Encrypted bundle format (version | kem_ct | eph_pk | nonce | wrapped_key | ciphertext)
│   ├── hash.rs        # BLAKE3 hashing, keyed hash, key derivation
│   ├── kdf.rs         # Argon2id passphrase → PDK derivation
│   ├── kem.rs         # Hybrid KEM (ML-KEM-768 + X25519) encapsulate / decapsulate
│   ├── keys.rs        # Key generation, keystore (encrypt/save/load/unlock)
│   ├── sensitive.rs   # Zeroize-on-drop wrappers for sensitive data
│   ├── sign.rs        # Hybrid signatures (ML-DSA-65 + Ed25519)
│   └── streaming.rs   # Chunked encryption for large files (64 KiB chunks)
├── merkle/
│   ├── tree.rs        # BLAKE3 Merkle tree construction
│   ├── proof.rs       # Merkle inclusion proofs (generate + verify)
│   └── super_tree.rs  # Super Merkle Tree (batch all users → single root)
├── manifest/          # Backup manifest (file list, hashes, storage locations)
├── restore/           # Bundle decryption + hash verification
├── storage/
│   ├── s3.rs          # S3-compatible storage backend (AWS, B2, MinIO, etc.)
│   └── filecoin.rs    # Filecoin / Storacha storage backend
├── anchor/
│   ├── bitcoin.rs     # Bitcoin OP_RETURN anchoring
│   ├── ethereum.rs    # Ethereum calldata anchoring
│   └── batch.rs       # Super Merkle Tree batching for anchoring
├── sources/
│   └── google_drive.rs  # Google Drive data source
├── pipeline.rs        # Encryption pipeline orchestration
└── error.rs           # Error types
```

| Module | Role |
|---|---|
| `crypto::aead` | XChaCha20-Poly1305 encrypt/decrypt with AAD |
| `crypto::bundle` | Serialization format for encrypted files |
| `crypto::hash` | BLAKE3 hashing (hash, keyed_hash, derive_key) |
| `crypto::kdf` | Argon2id (t=3, m=256MB, p=4) passphrase derivation |
| `crypto::kem` | Hybrid KEM: ML-KEM-768 + X25519 → wrapping key → wrap/unwrap symmetric key |
| `crypto::keys` | Key generation (4 key pairs), keystore persistence, unlock with passphrase |
| `crypto::sensitive` | `SensitiveBytes32` / `SensitiveVec` with `Zeroize` on drop |
| `crypto::sign` | Hybrid signatures: ML-DSA-65 + Ed25519 |
| `crypto::streaming` | Large-file chunked encryption (nonce XOR chunk_index, truncation-resistant AAD) |
| `merkle::tree` | BLAKE3 Merkle tree from leaf hashes |
| `merkle::proof` | Generate and verify Merkle inclusion proofs |
| `merkle::super_tree` | Aggregate per-user roots into a single super root for anchoring |
| `manifest` | `BackupManifest` + `ManifestBuilder` + integrity verification |
| `restore` | Decrypt encrypted bundles, verify content hash |
| `storage::s3` | S3 upload/download/exists via `rust-s3` |
| `storage::filecoin` | Filecoin deal creation via Storacha API |
| `anchor::bitcoin` | Write Merkle root to Bitcoin via OP_RETURN |
| `anchor::ethereum` | Write Merkle root to Ethereum calldata |
| `anchor::batch` | Super Merkle Tree for batch anchoring |

## Algorithms

| Component | Algorithm |
|---|---|
| Key encapsulation (PQ) | ML-KEM-768 (`pqcrypto-kyber`) |
| Key encapsulation (classical) | X25519 (`x25519-dalek`) |
| Symmetric encryption | XChaCha20-Poly1305 (`chacha20poly1305`) |
| Signatures (PQ) | ML-DSA-65 (`pqcrypto-dilithium`) |
| Signatures (classical) | Ed25519 (`ed25519-dalek`) |
| Hashing | BLAKE3 (`blake3`) |
| KDF | Argon2id (`argon2`) |
| Memory safety | `zeroize` on all key material |

## Tests

```bash
# Run all core tests (60 tests)
cargo test -p zk-vault-core

# With output
cargo test -p zk-vault-core -- --nocapture
```

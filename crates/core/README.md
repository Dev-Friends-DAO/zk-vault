# zk-vault-core

Core cryptographic library for zk-vault: post-quantum encryption, key management, mnemonic recovery, Shamir Secret Sharing, guardian encryption, Merkle trees, manifests, storage backends, and anchoring.

## Modules

```
zk-vault-core/
├── crypto/
│   ├── aead.rs        # XChaCha20-Poly1305 symmetric encryption
│   ├── bundle.rs      # Encrypted bundle format (version | kem_ct | eph_pk | nonce | wrapped_key | ciphertext)
│   ├── hash.rs        # BLAKE3 hashing, keyed hash, key derivation
│   ├── kdf.rs         # Argon2id passphrase → PDK derivation
│   ├── kem.rs         # Hybrid KEM (ML-KEM-768 + X25519) encapsulate / decapsulate
│   ├── guardian.rs    # Hybrid PQ KEM encryption of Shamir shares for guardians
│   ├── keys.rs        # Key generation, keystore v2 (PDK→MK→individual keys), mnemonic recovery
│   ├── mnemonic.rs    # BIP-39 24-word mnemonic ↔ master key encoding
│   ├── sensitive.rs   # Zeroize-on-drop wrappers for sensitive data
│   ├── shamir.rs      # Shamir Secret Sharing over GF(256) (split/reconstruct)
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
| `crypto::guardian` | Hybrid PQ KEM encryption of Shamir shares for guardians (`encrypt_share_for_guardian`, `decrypt_guardian_share`) |
| `crypto::kdf` | Argon2id (t=3, m=256MB, p=4) passphrase derivation + optional keyfile/hwkey mixing via BLAKE3 |
| `crypto::kem` | Hybrid KEM: ML-KEM-768 + X25519 → wrapping key → wrap/unwrap symmetric key |
| `crypto::keys` | Key generation (4 key pairs), keystore v2 (PDK→MK→individual keys), mnemonic recovery, keyfile/hwkey support |
| `crypto::mnemonic` | BIP-39 24-word mnemonic encoding/decoding of master key (`master_key_to_mnemonic`, `mnemonic_to_master_key`) |
| `crypto::sensitive` | `SensitiveBytes32` / `SensitiveVec` with `Zeroize` on drop |
| `crypto::shamir` | Shamir Secret Sharing over GF(256): `split(secret, threshold, total)` and `reconstruct(shares, threshold)` |
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
| Mnemonic | BIP-39 (`bip39`) |
| Shamir SSS | `sharks` (GF(256)) |

### Key Hierarchy (v2)

PDK encrypts only the Master Key. MK individually encrypts each secret key. This ensures that recovering MK (via mnemonic or Shamir reconstruction) is sufficient to recover all keys.

```
Passphrase + [keyfile] + [hwkey] → Argon2id + BLAKE3 → PDK
PDK → encrypts → MK
MK → encrypts → { ML-KEM-768 sk, X25519 sk, ML-DSA-65 sk, Ed25519 sk }
MK → derives  → per-backup DEKs via HKDF
```

## Tests

```bash
# Run all core tests (81 tests)
cargo test -p zk-vault-core

# With output
cargo test -p zk-vault-core -- --nocapture
```

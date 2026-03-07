# zk-vault

**Quantum-secure, distributed, and persistent encrypted backup.**

> Store data that must never be exposed on the internet, making data management easy, while achieving quantum-secure distributed persistent data with no single point of failure.

## What is zk-vault?

zk-vault encrypts your important data on your device with post-quantum cryptography and stores it across a distributed network with no single point of failure. No server, validator, or storage provider ever sees your plaintext data.

**"zk" means:** Today, zero-knowledge architecture — the system never accesses your plaintext. In the future, zero-knowledge proofs will be integrated to enable cryptographic verification without revealing data. See [docs/PRODUCT.md](docs/PRODUCT.md) for the full vision.

## Architecture

```
+---------------------------------------------------------------+
|                         CLIENT                                 |
|  Data Sources --> PQ Encryption --> Round-trip Verification    |
|                                                                |
|  Layer 0: Local Encrypted Backup (USB / External HDD / NAS)   |
|           Always present. Independent of all networks.         |
+-------------------------------+-------------------------------+
                                |
                                v
+---------------------------------------------------------------+
|                      zk-vault Chain                            |
|                  BFT Consensus (PoA --> DPoS)                  |
|                                                                |
|  On-chain state:                                               |
|    File Registry / Manifests / Merkle Roots                    |
|                                                                |
|  Storage (user selects):                                       |
|    Mode B: Native --> validators store data directly           |
|    Mode C: Filecoin --> delegated to Filecoin SPs              |
|    (can use both simultaneously)                               |
+----------+--------------------------+-------------------------+
           |                          |
           v                          v
+-------------------+      +--------------------+
|     Filecoin      |      |    BTC / ETH       |
|   (Mode C only)   |      |    Anchoring       |
|                   |      |                    |
|  Encrypted data   |      |  Merkle root       |
|  PoSt verified    |      |  tamper-proof      |
|  Multi-SP/region  |      |  timestamp         |
+-------------------+      +--------------------+
```

| Component | Role |
|---|---|
| Local (Layer 0) | Safety net — independent of all crypto-economics |
| zk-vault Chain | State management + storage + coordination |
| Filecoin | External verified storage (user's choice) |
| BTC / ETH | Immutable proof of data integrity |

## Encryption

Post-quantum hybrid encryption — secure against both classical and quantum attacks.

| Component | Algorithm |
|---|---|
| Key encapsulation (PQ) | ML-KEM-768 |
| Key encapsulation (classical) | X25519 |
| Symmetric encryption | XChaCha20-Poly1305 |
| Signatures (PQ) | ML-DSA-65 |
| Signatures (classical) | Ed25519 |
| Hashing | BLAKE3 |
| KDF | Argon2id (t=3, m=256MB, p=4) |
| Memory safety | `zeroize` on all key material |

**Why hybrid:** If either the post-quantum or classical algorithm is broken, the other still protects data.

### Key Hierarchy

```
User Passphrase (never leaves client)
    |
    v  Argon2id (t=3, m=256MB, p=4)
Passphrase-Derived Key (PDK)
    |
    +-- Master Key (MK) -- 256-bit random, client-side
    |     +-- ML-KEM-768 secret key
    |     +-- X25519 secret key
    |     +-- ML-DSA-65 secret key
    |     +-- Ed25519 secret key
    |     +-- Per-backup DEKs via HKDF
    |
    +-- Authentication credentials
```

### Per-File Encryption

1. Generate random 256-bit symmetric key
2. Encrypt: `XChaCha20-Poly1305(sym_key, nonce, plaintext, aad)`
3. Hybrid KEM key wrap: `ML-KEM-768 + X25519 → wrapping_key → wrap sym_key`
4. Bundle: `[version | kem_ct(1088B) | eph_pk(32B) | nonce(24B) | wrapped_key(48B) | ciphertext]`
5. Zeroize all key material from memory

Files larger than 64 KiB use streaming encryption with per-chunk nonces (`base_nonce XOR chunk_index`) and truncation-resistant AAD.

## Storage

Users select their storage mode:

| | Mode B (Native) | Mode C (Filecoin) |
|---|---|---|
| Data stored by | Chain validators | Filecoin Storage Providers |
| Verification | BFT consensus | PoSt (zk-SNARK) |
| Speed | Fast (direct access) | Slower (IPFS gateway) |
| Best for | Smaller data, fast access | Large data, maximum distribution |

Both modes can be used simultaneously for critical data.

Layer 0 (local encrypted backup) is always independent of both modes.

## Anchoring

A 32-byte Merkle root (BLAKE3) of all backed-up data is written to Bitcoin (OP_RETURN) and Ethereum (calldata). This proves data existed at a specific time and has not been tampered with since.

All users' roots are batched into a single Super Merkle Tree, so one transaction per chain covers all users.

| Users | Per-user cost (BTC) |
|---|---|
| 1 | ~$0.50 |
| 1,000 | ~$0.0005 |
| 100,000 | ~$0.000005 |

## Threat Model

| Threat | Defense |
|---|---|
| Quantum computers (harvest now, decrypt later) | ML-KEM-768 + ML-DSA-65 |
| PQ algorithm break | X25519 + Ed25519 classical fallback |
| Network interception | Client-side encryption before transmission |
| Validator compromise | Zero-knowledge architecture: ciphertext only |
| Storage single point of failure | Mode B + Mode C + Layer 0 |
| Data tampering | Merkle tree + BTC/ETH anchoring |
| Passphrase brute force | Argon2id (256MB memory-hard) |
| Memory dump | `zeroize` on all key material |
| Passphrase loss | Guardian recovery network |
| Chain failure | Layer 0 is always independent |

## Tech Stack

| Component | Technology |
|---|---|
| Language | Rust (2021 edition) |
| PQ KEM | `pqcrypto-kyber` (ML-KEM-768) |
| PQ Signatures | `pqcrypto-dilithium` (ML-DSA-65) |
| Symmetric | `chacha20poly1305` (XChaCha20-Poly1305) |
| Classical KEM | `x25519-dalek` |
| Classical Signatures | `ed25519-dalek` |
| Hashing | `blake3` |
| KDF | `argon2` |
| Memory safety | `zeroize` |
| Bitcoin | `rust-bitcoin` |
| Ethereum | `alloy` |

## Documentation

- **[docs/PRODUCT.md](docs/PRODUCT.md)** — Full product vision, architecture details, and design exploration (includes items under consideration)

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

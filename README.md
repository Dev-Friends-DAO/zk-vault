# zk-vault

**Post-Quantum Zero-Knowledge Secure Backup Platform**

Securely back up your important internet data with post-quantum encryption, no single point of failure, and tamper-proof guarantees.

## What is zk-vault?

zk-vault is a zero-knowledge backup platform that protects your data against both current and future threats, including quantum computers. The server never sees your plaintext data — all encryption happens on your device.

### Key Features

- **Post-Quantum Hybrid Encryption** — ML-KEM-768 + X25519 key encapsulation, XChaCha20-Poly1305 AEAD
- **Zero-Knowledge Architecture** — Server handles only ciphertext. OPAQUE authentication means the server never learns your password
- **No Single Point of Failure** — Tiered hybrid storage across Storj, Filecoin, and IPFS
- **Tamper-Proof** — BLAKE3 Merkle trees with blockchain anchoring on Bitcoin and Ethereum
- **Pluggable Data Sources** — Start with Google Drive, extensible to Gmail, Notion, GitHub, etc.
- **Pluggable Blockchain Anchors** — Independent multi-chain anchoring (not cross-chain bridges)

## Architecture

```
CLIENT (Desktop / Web+WASM / CLI)
  │  All encryption/decryption happens here
  │  Data source fetching happens here (zero plaintext on network)
  │
  ▼
API SERVER (Rust + Axum)
  │  Routes ciphertext only — never touches plaintext
  │
  ├── Storj ────── Hot storage (S3-compatible, fast retrieval)
  ├── Filecoin ─── Cold archive (cryptographic storage proofs)
  ├── IPFS ─────── Content-addressed distribution
  └── Arweave ──── Permanent manifest storage (pay once, store forever)

INTEGRITY
  ├── BLAKE3 Merkle Tree → per-user integrity
  ├── Super Merkle Tree ─→ batch all users into single root
  ├── Bitcoin OP_RETURN ─→ primary anchor (highest trust)
  └── Ethereum calldata ─→ secondary anchor (redundancy)
```

## Security Design

### Threat Model

| Threat | Defense |
|--------|---------|
| Quantum computers (harvest now, decrypt later) | ML-KEM-768 + ML-DSA-65 (NIST PQC standards) |
| PQ algorithm vulnerability discovered | X25519 + Ed25519 classical fallback |
| Network interception (MITM) | Client-side encryption before any transmission |
| Server compromise | Zero-knowledge: server holds ciphertext only |
| Storage single point of failure | Storj + Filecoin + IPFS — 3-tier distributed |
| Data tampering | Content-addressed storage + Merkle tree + blockchain anchors |
| Passphrase brute force | Argon2id (256MB memory-hard KDF) |
| Memory dump attacks | `zeroize` crate for all key material |
| Auth credential leaks | OPAQUE protocol (server never holds password hash) |

### Key Hierarchy

```
User Passphrase (never leaves client)
    │
    ▼  Argon2id (t=3, m=256MB, p=4)
Passphrase-Derived Key (PDK)
    │
    ├── Master Key (MK) — 256-bit random, generated client-side
    │     ├── ML-KEM-768 secret key  (post-quantum KEM)
    │     ├── X25519 secret key      (classical KEM)
    │     ├── ML-DSA-65 secret key   (post-quantum signatures)
    │     ├── Ed25519 secret key     (classical signatures)
    │     └── Per-backup DEKs via HKDF
    │
    └── OPAQUE authentication (server knows nothing)
```

### Per-File Encryption

1. Generate random 256-bit symmetric key
2. Encrypt: `XChaCha20-Poly1305(sym_key, nonce, plaintext, aad)`
3. Hybrid KEM key wrap:
   - `ML-KEM-768.Encapsulate(pk)` → post-quantum shared secret
   - `X25519-DH(eph_sk, pk)` → classical shared secret
   - `wrapping_key = BLAKE3(ss_pq || ss_classical || domain_separator)`
   - Wrap symmetric key with wrapping_key
4. Bundle format: `[version | kem_ct(1088B) | eph_pk(32B) | nonce(24B) | wrapped_key(48B) | ciphertext]`
5. Zeroize all key material from memory

### Network Security

```
Data Source ──[TLS]──► Client (plaintext received)
                         │
                         ▼
                  [Local Encryption]
                         │
                         ▼ (ciphertext only)
Client ──[TLS]──► API Server ──► Storage
                  (never touches plaintext)
```

No plaintext ever flows over the network from client to server. Even if TLS is compromised, attackers only see post-quantum encrypted ciphertext.

## Storage Architecture

### Why Hybrid (Not Single Backend)

| Single backend problem | Solution |
|------------------------|----------|
| IPFS alone: no persistence guarantee without pinning | Filecoin (economic incentive layer) + Storj (reliable hot storage) |
| Filecoin alone: deals expire, retrieval is slow | Storj (S3-compatible, instant retrieval) as hot tier |
| Storj alone: Storj Labs is a single point of failure | Filecoin + IPFS for fully decentralized backup |
| Arweave alone: expensive for large data ($6-8/GB) | Only manifests (few KB) go to Arweave |

### IPFS vs Filecoin

- **IPFS** = Content addressing and distribution protocol. Finds data by CID hash. **No persistence guarantee** — data disappears when nodes garbage-collect
- **Filecoin** = Economic incentive layer for IPFS. Its own blockchain (FIL token). Storage providers cryptographically prove they hold your data via Proof-of-Replication (PoRep) and Proof-of-Spacetime (PoSt)
- They are separate protocols. IPFS can work without Filecoin (via pinning services like Pinata), but that introduces centralized dependency

## Blockchain Anchoring

### Multi-Chain, Not Cross-Chain

**Critical design decision:** We anchor the same hash independently on multiple chains. No cross-chain bridges.

- Cross-chain bridges have lost **$2.8B+ to hacks** since 2022
- Chain independence is the feature — bridging creates shared failure points
- Verification: client checks each chain independently, confirms hashes match

### Why Bitcoin + Ethereum

**Bitcoin (primary anchor):**
- 17 years of zero downtime. Most likely chain to exist in 20+ years
- "Your backup is anchored on Bitcoin" = strongest trust signal
- OP_RETURN: 32-byte hash, typically $0.02-$1.00/tx
- Same pattern as OpenTimestamps (running since 2016)
- **Bitcoin is not storage. It provides timestamped proof of existence.**

**Ethereum (secondary anchor):**
- Redundancy. Currently ~$0.002/tx at 0.04 gwei gas
- Future extensibility via smart contract verification
- Alloy v1.0 Rust SDK is excellent

### Super Merkle Tree Batching

All users' Merkle roots are aggregated into a single "super" root, anchored in one transaction per chain per month. Cost is fixed regardless of user count:

| Users | Without batching (BTC) | With batching | Per-user cost |
|-------|------------------------|---------------|---------------|
| 1 | $0.50 | $0.50 | $0.50 |
| 1,000 | $500 | $0.50 | $0.0005 |
| 100,000 | $50,000 | $0.50 | $0.000005 |

### Chains We Evaluated and Rejected

- **Solana**: 68% validator decline, top 3 control 26% of stake, 7+ outages
- **Secret Network**: Privacy features are irrelevant (anchored data is already a hash — zero information leakage). SGX repeatedly broken. $29M market cap, 99.2% below ATH
- **Other privacy chains** (Aztec, Mina, Oasis, Aleo, Penumbra): Same reasoning — hash anchoring needs no privacy features

## Disaster Recovery

| Scenario | Recovery |
|----------|----------|
| Local machine lost | Passphrase → retrieve manifest from Arweave/IPFS → restore from Storj/Filecoin |
| Storj outage | Retrieve from Filecoin deals + IPFS, re-upload to Storj |
| Filecoin deal expired | Storj/IPFS still serving; create new deals |
| All IPFS pins lost | Redundant copies on Storj + Filecoin |
| Server completely lost | Manifests on Arweave (permanent). Anchors on Bitcoin/Ethereum. Client can autonomously restore |
| Passphrase forgotten | **Unrecoverable by design** (Recovery Key issued at registration) |
| PQ algorithms broken | X25519 + Ed25519 classical fallback |
| Classical algorithms broken | ML-KEM-768 + ML-DSA-65 PQ fallback |

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust (2021 edition, MSRV 1.75+) |
| Post-quantum KEM | ML-KEM-768 via `pqcrypto-kyber` |
| Post-quantum signatures | ML-DSA-65 via `pqcrypto-dilithium` |
| Symmetric encryption | XChaCha20-Poly1305 via `chacha20poly1305` |
| Classical KEM | X25519 via `x25519-dalek` |
| Classical signatures | Ed25519 via `ed25519-dalek` |
| Hashing | BLAKE3 |
| KDF | Argon2id |
| Memory safety | `zeroize` |
| Bitcoin | `rust-bitcoin` + `bdk` |
| Ethereum | `alloy` v1.0 |
| Hot storage | Storj (S3-compatible via `aws-sdk-s3`) |
| Cold storage | Filecoin (Storacha API) |
| Distribution | IPFS |
| Permanent anchoring | Arweave |
| API server | Axum |
| Authentication | OPAQUE (`opaque-ke`) |
| Database | PostgreSQL (`sqlx`) |

## Market Differentiation

**No existing product combines all three:**
1. Automated backup of SaaS/internet data (Google Drive, Gmail, Notion, etc.)
2. Zero-knowledge / client-side encryption
3. Decentralized storage backend (no single point of failure)

Post-quantum encryption + blockchain-anchored tamper-proof evidence provides further differentiation.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

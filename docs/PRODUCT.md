# zk-vault — Product Definition

> **This document reflects ongoing thinking and is subject to change.**
> It captures the current product vision, architecture, and design decisions as they evolve.
> Some sections are marked as brainstorming or under evaluation — these are not commitments.

## 1. Product Definition

**zk-vault** is a quantum-secure, distributed, and persistent encrypted backup system.

**Core philosophy:**

> Store data that must never be exposed on the internet, making data management easy, while achieving quantum-secure distributed persistent data with no single point of failure.

The product is born from a personal need: backing up important Google Drive data (deeply nested directories of Docs, Slides, Spreadsheets) in a way that is encrypted, distributed, and resilient — where no single entity can read, lose, or tamper with the data.

### What makes zk-vault different

|  | Google Drive | 1Password | Backblaze | Tarsnap | **zk-vault** |
|---|---|---|---|---|---|
| Encryption | Server-side | Client-side | Client-side | Client-side | **Post-quantum client-side** |
| Storage | Google | AgileBits | Backblaze | Tarsnap | **Distributed (chain + Filecoin)** |
| Proof of data retention | None | None | None | None | **PoSt (Filecoin) + BFT consensus** |
| Single point of failure | Google | AgileBits | Backblaze | Tarsnap | **None** |
| Key loss recovery | Password reset | Recovery Kit | Password reset | Unrecoverable | **Guardian Network** |
| Quantum resistance | None | None | None | None | **ML-KEM-768 + X25519** |
| If operator disappears | Data at risk | Data at risk | Data at risk | Data at risk | **Local backup + chain + Filecoin** |
| Trust model | Trust the company | Trust the company | Trust the company | Trust the company | **Trust mathematics** |

### The "zk" in zk-vault

Today, "zk" refers to our **zero-knowledge architecture** — the system is designed so that no server, validator, or storage provider ever has access to plaintext data. All encryption and decryption happens on the user's device.

As the product evolves, "zk" will also encompass **zero-knowledge proofs** (ZKP) — cryptographic proofs that allow verification of facts without revealing underlying data. See [Section 7](#7-zero-knowledge-proofs-zkp) for the full vision.

---

## 2. Architecture Overview

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
|    Deal Lifecycle / Guardian Registry                          |
|                                                                |
|  Storage (user selects):                                       |
|    Mode B: Native --> validators store data directly           |
|    Mode C: Filecoin --> delegated to Filecoin SPs              |
|    (can use both simultaneously)                               |
|                                                                |
|  Automation:                                                   |
|    Deal renewal / PoSt monitoring / Guardian liveness          |
|    Anchor scheduling                                           |
|                                                                |
|  Endowment Module:                                             |
|    One-time payment --> fund --> continuous validator rewards   |
|    Enables permanent data retention on-chain                   |
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

### Role summary

| Component | Role |
|---|---|
| Local (Layer 0) | Safety net — independent of all crypto-economics |
| zk-vault Chain | Brain + warehouse + permanent storage layer |
| Filecoin | External verified warehouse (user's choice) |
| BTC / ETH | Notary — immutable proof of data integrity |

### What was eliminated

The previous architecture included an API server (Axum), PostgreSQL database, Storj, IPFS, and Arweave as separate systems. In the evolved design:

| Eliminated | Replaced by |
|---|---|
| API Server (Axum) | Chain RPC |
| PostgreSQL | Chain state |
| Storj | Mode B (native storage) |
| IPFS | Chain node cache layer |
| Arweave | Endowment Module (on-chain permanence) |

The chain absorbs the coordination, state management, caching, and permanence roles that previously required 5 separate systems.

---

## 3. Encryption

### Post-Quantum Hybrid Scheme

zk-vault uses a dual-layer encryption approach that is secure against both classical and quantum attacks:

```
Per-file encryption:

1. Generate random 256-bit symmetric key (sym_key)
2. Encrypt plaintext:
     XChaCha20-Poly1305(sym_key, nonce, plaintext, aad)
3. Hybrid KEM key wrapping:
     ML-KEM-768.Encapsulate(pk)  --> post-quantum shared secret (ss_pq)
     X25519-DH(eph_sk, pk)      --> classical shared secret (ss_classical)
     wrapping_key = BLAKE3(ss_pq || ss_classical || domain_separator)
     wrapped_key = AEAD(wrapping_key, sym_key)
4. Bundle format:
     [version | kem_ct(1088B) | eph_pk(32B) | nonce(24B) | wrapped_key(48B) | ciphertext]
5. Zeroize all key material from memory (zeroize crate)
```

**Why hybrid:** If either the post-quantum or classical algorithm is broken, the other still protects the data. This is a hedge against both "PQ algorithm turns out to be weak" and "quantum computers arrive sooner than expected."

### Round-trip Verification

After encryption, the system immediately decrypts and compares with the original plaintext. This catches encryption bugs, bit-flips, and implementation errors at backup time — not 3 years later during a critical restore.

```
Encrypt(plaintext) --> ciphertext
Decrypt(ciphertext) --> plaintext'
Assert: hash(plaintext) == hash(plaintext')
```

### Hash Chain

Each step of the pipeline records a BLAKE3 hash, creating a chain of evidence:

```
H1 = hash(plaintext)           -- recorded in manifest
H2 = hash(ciphertext)          -- recorded in manifest, used as Merkle leaf
H3 = hash(uploaded_data)       -- compared with H2 at upload time

At restore:
H4 = hash(downloaded_data)     -- compared with H2
H5 = hash(decrypted_data)      -- compared with H1

If any hash mismatches, the exact point of corruption is identified.
```

### Key Hierarchy

```
User Passphrase (never leaves client)
    |
    v  Argon2id (t=3, m=256MB, p=4)
Passphrase-Derived Key (PDK)
    |
    +-- Master Key (MK) -- 256-bit random, generated client-side
    |     +-- ML-KEM-768 secret key  (post-quantum KEM)
    |     +-- X25519 secret key      (classical KEM)
    |     +-- ML-DSA-65 secret key   (post-quantum signatures)
    |     +-- Ed25519 secret key     (classical signatures)
    |     +-- Per-backup DEKs via HKDF
    |
    +-- Authentication credentials
```

### Streaming Encryption

Files larger than 64 KiB are encrypted in chunks to avoid loading entire files into memory:

- Base nonce: random 24 bytes
- Per-chunk nonce: `base_nonce XOR chunk_index` (prevents reordering)
- Per-chunk AAD: `[base_aad | chunk_index(8 LE) | is_final(1)]` (prevents truncation)
- Each chunk is independently authenticated via AEAD

---

## 4. dApp Chain Design

### Why a Custom Chain

The previous architecture relied on a centralized API server and PostgreSQL database. This contradicts the product's core philosophy of eliminating trust.

| Problem | Solution |
|---|---|
| API server is a single point of failure | Chain RPC (decentralized) |
| PostgreSQL state can be corrupted | BFT-protected on-chain state |
| Server operator must be trusted | Consensus among validators |
| Multi-device sync requires a server | Chain is the shared state |
| Deal renewal depends on a cron job | Chain-internal automation |
| Guardian coordination needs a coordinator | On-chain coordination |

### Consensus

**Initial phase: PoA (Proof of Authority)**
- 3-7 known validators
- BFT consensus (tolerates < 1/3 Byzantine validators)
- Instant finality
- No token required

**Growth phase: DPoS (Delegated Proof of Stake)**
- Validators selected by stake delegation
- Permissionless participation
- Economic security via slashing

The specific BFT implementation (CometBFT, GRANDPA, or other) is to be determined based on the chain framework selected.

### Chain Modules

> Note: "Module" is used as a generic term. The specific implementation pattern depends on the chain framework chosen.

**Core Module**
- FileRegistry: `file_id -> {content_hash, storage_locations, merkle_index, status}`
- Manifests: `backup_id -> {files[], merkle_root, timestamp, anchors}`
- MerkleRoots: historical record of all roots

**Endowment Module**
- Implements Arweave-like permanent storage economics on-chain
- One-time payment → endowment fund → continuous validator rewards
- Payment split: ~15% immediate to validators, ~85% to endowment pool
- Endowment distributes rewards per-block based on data held
- Based on the assumption that storage costs decline over time (Kryder's Law)

**Guardian Module**
- Guardian sets per user: `{guardians[], threshold, share_commitments[]}`
- Time-lock logic, Dead Man's Switch
- Liveness proof tracking
- Recovery initiation and verification

**Anchor Module**
- Schedules periodic Merkle root anchoring to BTC/ETH
- Super Merkle Tree aggregation (all users → single root)
- Tracks anchor receipts and verification status

**Storage Module**
- Mode B: coordinates data replication across validators
- Mode C: manages Filecoin deal lifecycle (creation, monitoring, renewal)
- Unified interface for both modes

### Consensus, Transactions, and BFT

**Transaction types:**

| Transaction | Purpose |
|---|---|
| `RegisterFile` | Record a new encrypted file with its storage locations |
| `UpdateStorageStatus` | Update file status (replicated, verified, expired) |
| `RenewDeal` | Trigger or record a Filecoin deal renewal |
| `AnchorMerkleRoot` | Record BTC/ETH anchor transaction IDs |
| `RegisterGuardian` | Add a guardian to a user's recovery set |
| `GuardianLiveness` | Submit periodic liveness proof |
| `InitiateRecovery` | Begin key recovery process |

**BFT properties:**
- Safety: no two honest validators decide on conflicting states
- Liveness: transactions are eventually finalized
- Fault tolerance: < 1/3 of validators can be Byzantine
- Finality: immediate (single block) with BFT consensus

**CAP theorem positioning:**
- The system is **AP** (Available + Partition-tolerant) across the multi-storage architecture
- Within the chain itself: **CP** (Consistent + Partition-tolerant) via BFT consensus
- Cross-system consistency (chain ↔ Filecoin) is eventual, reconciled via the manifest as source of truth

---

## 5. Storage Architecture

### Mode B: Native Store

Validators directly store encrypted data alongside chain state.

**Scaling phases:**

| Phase | Strategy | Validator load | Users |
|---|---|---|---|
| Phase 1 | Full replication | All data on every validator | ~100 |
| Phase 2 | Erasure coding (e.g., RS 10/30) | Each validator holds 1/3 of total | ~10,000 |
| Phase 3 | Sharding + erasure coding | Validators grouped into shards | ~1,000,000+ |

**Full replication (Phase 1):**
```
5 validators, 10 users x 50GB = 2.5TB per validator
Simple. Every validator has a complete copy.
Any single validator can serve any file.
```

**Erasure coding (Phase 2):**
```
Reed-Solomon (k=10, n=30):
  50GB file --> 30 pieces (each ~5GB)
  Any 10 pieces can reconstruct the original
  Each of 30 validators holds 5GB (not 50GB)
  10 validators can fail and data is still recoverable
```

**Sharding (Phase 3):**
```
100 validators --> 10 shards x 10 validators
Each shard handles a portion of the data
Erasure coding within each shard
Each validator: ~10TB (manageable on commodity hardware)
```

### Mode C: Filecoin Bridge

Encrypted data is stored on Filecoin via storage deals with multiple Storage Providers (SPs) across multiple geographic regions.

- 4-6 independent SPs per file for redundancy
- PoSt (Proof of Spacetime) provides cryptographic proof of data retention
- Deal lifecycle managed by the chain's Storage Module
- Retrieval via IPFS gateways (Filecoin data is accessible through IPFS)

**Filecoin's limitation:** Deals expire (180-540 days). The chain automates renewal, but active management is required. Filecoin is not permanent storage — it is verified rental storage.

### Endowment Model (On-chain Permanence)

Inspired by Arweave's economic model, but implemented as a chain module:

```
User pays once
    |
    +--> 15% to validators immediately (incentivize acceptance)
    |
    +--> 85% to Endowment Pool (on-chain treasury)
              |
              +--> Per-block distribution to validators
                   proportional to data they hold
                   |
                   +--> Distribution rate decreases over time
                        (models declining storage costs)
```

**Assumption:** Storage hardware costs decline ~30% per year (Kryder's Law). The endowment is designed to outlast the data's useful life.

**Risk:** If the chain's token loses value or Kryder's Law reverses, the model breaks. Mitigation: Layer 0 (local backup) is always independent of this model.

### User Choice

Users select their storage mode per backup:

| | Mode B (Native) | Mode C (Filecoin) |
|---|---|---|
| Speed | Fast (direct validator access) | Slower (IPFS gateway retrieval) |
| Verification | BFT consensus | PoSt (zk-SNARK) |
| Trust model | Trust validator set | Trust Filecoin protocol |
| Permanence | Endowment model | Deal renewal |
| Scalability | Limited by validator count | Virtually unlimited |
| Best for | Smaller data, fast access | Large data, maximum distribution |

Users can also use **both modes simultaneously** for critical data — Mode B for fast access, Mode C for independently verified redundancy.

---

## 6. Anchoring

### What anchoring does

Anchoring writes a 32-byte fingerprint (Merkle root) of all backed-up data to a public blockchain. It does not store data — it stores proof that data existed at a specific point in time.

**Concrete process:**

```
1. Compute BLAKE3 hash of each encrypted file
     file_1 --> H1 = BLAKE3(encrypted_file_1)
     file_2 --> H2 = BLAKE3(encrypted_file_2)
     file_3 --> H3 = BLAKE3(encrypted_file_3)

2. Build Merkle Tree
            [Root]
           /      \
        [H12]    [H3]
       /    \
     [H1]  [H2]

     Root = 32-byte hash (e.g., 0x7a3b...)

3. Write Root to Bitcoin
     Bitcoin Transaction:
       Input:  UTXO
       Output: OP_RETURN 0x7a3b...   <-- 32 bytes, permanently on Bitcoin
       Output: change

4. Write same Root to Ethereum (redundancy)
     Ethereum Transaction:
       To: self
       Calldata: 0x7a3b...           <-- 32 bytes, permanently on Ethereum
```

### What anchoring proves

```
At restore time (e.g., 3 years later):

1. Download encrypted files
2. Recompute Merkle Tree --> Root'
3. Check Bitcoin block #N --> Root stored is 0x7a3b...
4. Root' == 0x7a3b... ?
     Yes --> Data has not been tampered with since backup
     No  --> Data was modified (corruption or attack detected)
```

**Proves:**
- Data existed at a specific point in time
- Data has not been modified since that point
- The proof itself cannot be forged (Bitcoin's hash rate protects it)

**Does NOT prove:**
- That the data is correct (encryption could have been buggy)
- That the data still exists somewhere (storage is a separate concern)

### Why Bitcoin + Ethereum

**Bitcoin:** 17 years of zero downtime. Highest hash rate. Most likely to exist in 20+ years. Strongest immutability guarantee available.

**Ethereum:** Redundancy on an independent chain. Future extensibility via smart contract verification (e.g., on-chain proof verification).

### Super Merkle Tree Batching

All users' individual Merkle roots are aggregated into a single "super root," anchored in one transaction per chain per period. Cost is fixed regardless of user count:

| Users | Per-user cost (BTC anchor) |
|---|---|
| 1 | ~$0.50 |
| 1,000 | ~$0.0005 |
| 100,000 | ~$0.000005 |

### Future: ZKP-Enhanced Anchoring

Currently, the anchor proves "this hash existed at this time." With ZKP (see Section 7), the anchor could prove: "this hash was correctly computed from N files that were correctly encrypted and stored" — transforming the anchor from a timestamp into a verified commitment.

---

## 7. Zero-Knowledge Proofs (ZKP)

> **Status: To be evaluated in later phases.**
> The following represents the full design space of ZKP applications in zk-vault.
> Adoption of each use case will be decided in future phases based on feasibility,
> cost, and user need.

### Current state

zk-vault does not currently generate or verify zero-knowledge proofs. The "zk" in the name refers to the zero-knowledge architecture (server/validators never access plaintext).

However, the system already benefits from ZKP indirectly: Filecoin's PoSt (Mode C) uses zk-SNARKs internally to prove storage providers hold data.

### Potential ZKP applications

The following 10 use cases have been identified across the entire data lifecycle:

**During backup:**

| # | Use case | What it proves | Without revealing |
|---|---|---|---|
| 1 | **Proof of Provenance** | Data was obtained from an authenticated source (e.g., Google Drive API) | The data itself |
| 2 | **Proof of Correct Encryption** | Ciphertext was produced by correctly encrypting some plaintext with the correct algorithm and key | Plaintext, key, nonce |
| 3 | **Proof of Correct Merkle Construction** | Merkle tree was correctly built from N leaf hashes, producing root X | Individual leaf hashes |
| 4 | **Proof of Completeness** | All N files from the data source are included in the backup; none missing | The file list |

**During storage:**

| # | Use case | What it proves | Without revealing |
|---|---|---|---|
| 5 | **Proof of Replication** (Mode B) | A validator holds a correct copy of the data | The data itself |
| 6 | **Cross-Mode Consistency** | Data in Mode B and Mode C is identical | Either copy of the data |

**During recovery and access:**

| # | Use case | What it proves | Without revealing |
|---|---|---|---|
| 7 | **Guardian Knowledge Proof** | The user knows the answer to a recovery challenge | The answer itself |
| 8 | **Selective Disclosure** | A file matching certain criteria exists in the backup | Other files or file contents |
| 9 | **Anonymous Retrieval** | The requester has access rights to the requested data | The requester's identity |

**System-wide:**

| # | Use case | What it proves | Without revealing |
|---|---|---|---|
| 10 | **Recursive Proof Aggregation** | All of the above, combined into a single proof | Everything above |

### Recursive proof aggregation

The most powerful application. Individual proofs are aggregated hierarchically:

```
Per-file proof:     "File X was correctly encrypted"
       | aggregate
Per-backup proof:   "All N files in this backup are correct"
       | aggregate
Per-user proof:     "All backups for this user are correct"
       | aggregate
Per-epoch proof:    "All users' backups in this period are correct"
       | anchor
Bitcoin OP_RETURN:  32 bytes that cover EVERYTHING
```

A single 32-byte Bitcoin anchor proves the correctness of all users' all backups' all files. The density of meaning in those 32 bytes is vastly different from a simple hash.

### ZKP technology considerations

The system's post-quantum commitment (ML-KEM-768, ML-DSA-65) creates a constraint: the proof system should also be quantum-resistant.

| Proof system | Quantum-resistant | Compatibility |
|---|---|---|
| Groth16 (arkworks) | No (elliptic curve) | Inconsistent with PQ stance |
| Halo2 | No (elliptic curve) | Inconsistent with PQ stance |
| **STARKs (e.g., risc0)** | **Yes (hash-based)** | **Consistent** |
| Plonky2 | Partial | Uncertain |

STARKs (via risc0 zkVM) are the most natural fit: quantum-resistant, and existing Rust encryption code can run directly inside the zkVM as a guest program.

---

## 8. Guardian Recovery

> **Status: Brainstorming in progress. Design not finalized.**

### The problem

If the user loses their passphrase, all data is permanently lost. This is the most critical UX vulnerability for a self-sovereign encryption system.

### Concept: Guardian profiles

**Solo Profile (no human relationships required):**

```
3-of-5 guardians, all non-human:
  1. Hardware wallet A (e.g., Ledger, at home)
  2. Hardware wallet B (stored elsewhere)
  3. FIDO2 security key
  4. Time-locked smart contract (30-day delay)
  5. Knowledge proof (ZKP of secret answer)
```

**Social Profile (trusted relationships):**

```
3-of-5 guardians, mixed:
  1. Friend
  2. Family member
  3. Hardware wallet
  4. Time-locked contract
  5. Knowledge proof
```

### Concepts under exploration

- **Shamir Secret Sharing:** Master key split into N shares, any K can reconstruct
- **MPC Recovery:** Guardians participate in multi-party computation; no single guardian ever sees the full key
- **Time-lock Recovery:** Recovery request is posted on-chain; if the legitimate owner doesn't cancel within N days, the key is released
- **Dead Man's Switch:** If the user doesn't check in for N days, recovery is automatically initiated
- **ZKP Knowledge Proof:** Prove knowledge of a secret answer without revealing it; no hash stored on-chain (immune to dictionary attacks)

### Open questions

- How to handle guardian key rotation?
- What happens if guardians collude?
- How to incentivize non-human guardians (hardware wallet availability)?
- Should there be a recovery-of-last-resort mechanism?

---

## 9. Web3 Elements

### Authentication

The current implementation plans OPAQUE (RFC 9497) for password-based authentication. With the move to a dApp chain, authentication approaches to be evaluated include:

- **Account Abstraction (ERC-4337 / chain-native):** Flexible account models, social recovery built in, gas abstraction
- **Wallet-based authentication:** Direct signing with user's wallet
- **Web3 auth protocols:** Various emerging standards for decentralized authentication
- **Hybrid approaches:** Passphrase-based encryption key + wallet-based chain authentication

The authentication layer must satisfy two distinct needs:
1. Chain interaction authentication (who can submit transactions)
2. Encryption key derivation (how to derive the master key that encrypts data)

These may use different mechanisms.

### Composability

With on-chain state, other applications can interact with zk-vault:

- **Cyber insurance:** Verify backup status without seeing backup contents
- **Legal evidence:** Cryptographic proof of data existence at a specific date (Bitcoin anchor)
- **Compliance:** Prove backup completeness for regulatory requirements
- **Cross-dApp integration:** Other dApps can verify data possession claims

### DAO Governance

Future consideration for protocol-level decisions:
- Endowment rate adjustments
- Erasure coding parameters
- Protocol upgrades
- New data source integrations

### Tokenomics

To be introduced at the appropriate phase. Core considerations:
- Endowment payments (storage fees)
- Validator rewards (block production + data storage)
- Guardian incentives (liveness maintenance)
- Staking and slashing (DPoS security)
- Governance participation

---

## 10. Roadmap

> **Status: Under reconsideration.**
> The following represents the current directional thinking, not a committed plan.

**Phase 1: Foundation**
- Layer 0: CLI local encrypted backup (no server required)
- Round-trip verification
- Hash chain (each step recorded)
- Write-ahead log for crash recovery

**Phase 2: dApp Chain + Storage**
- Chain with BFT consensus (PoA)
- Mode B (native storage) + Mode C (Filecoin bridge)
- Endowment module
- Anchoring automation (BTC + ETH)
- Replaces API server + PostgreSQL

**Phase 3: Recovery + ZKP**
- Guardian recovery system
- ZKP integration (evaluated per use case)
- Knowledge proofs for guardians

**Phase 4: Expansion**
- Additional data sources (Gmail, Notion, GitHub)
- Selective Disclosure
- Scaling (erasure coding, sharding)
- Tokenomics introduction

---

## 11. Historical Context

### Original architecture

The initial design (reflected in the current README and codebase) used:

```
CLIENT
  |
  v
API SERVER (Rust + Axum)
  |
  +-- Storj      (hot storage, S3-compatible)
  +-- Filecoin   (cold archive, PoSt)
  +-- IPFS       (content-addressed distribution)
  +-- Arweave    (permanent manifest storage)

INTEGRITY
  +-- BLAKE3 Merkle Tree
  +-- Bitcoin OP_RETURN
  +-- Ethereum calldata

STATE
  +-- PostgreSQL
```

### What changed and why

| Decision | Old | New | Rationale |
|---|---|---|---|
| Central server | Axum API server | dApp chain | Server was a single point of failure and trust dependency. Contradicts "trust mathematics" philosophy. |
| State management | PostgreSQL | On-chain state | DB was centralized, corruptible, and required the server to be running. |
| Hot storage | Storj (S3-compatible) | Mode B (validator storage) | Storj is trust-based. For a backup product, the "hot access" requirement was overweighted — backups are rarely accessed. |
| Content distribution | IPFS (separate system) | Chain node cache | IPFS was redundant once Filecoin data is accessible via IPFS gateways. Chain nodes can cache for fast retrieval. |
| Permanent manifests | Arweave (external) | Endowment module (on-chain) | Arweave dependency can be eliminated by implementing the same economic model on the chain itself. |
| Storage architecture | 4 backends, fixed | 2 modes, user-selectable | Reduced complexity. Each remaining system has a clear, non-overlapping role. |

### Why Rust

The decision to build in Rust has proven valuable:

- **Memory safety for cryptographic code:** `zeroize` crate ensures key material is cleared from memory. Ownership model prevents key leakage.
- **Post-quantum library ecosystem:** `pqcrypto-kyber`, `pqcrypto-dilithium` are mature Rust crates.
- **Performance:** Streaming encryption, Merkle tree construction, and future ZKP generation (risc0 zkVM runs Rust guest programs).
- **Chain framework compatibility:** Major chain frameworks (Substrate, etc.) are Rust-native.
- **Single-language codebase:** Encryption, chain logic, CLI, and ZKP can all be Rust, reducing context-switching and enabling code reuse.

---

## Appendix: Threat Model

| Threat | Defense |
|---|---|
| Quantum computers (harvest now, decrypt later) | ML-KEM-768 + ML-DSA-65 (NIST PQC standards) |
| PQ algorithm vulnerability discovered | X25519 + Ed25519 classical fallback |
| Network interception (MITM) | Client-side encryption before any transmission |
| Server/validator compromise | Zero-knowledge architecture: only ciphertext is stored |
| Storage single point of failure | Mode B (multi-validator) + Mode C (multi-SP) + Layer 0 (local) |
| Data tampering | Merkle tree + Bitcoin/Ethereum anchoring |
| Passphrase brute force | Argon2id (256MB memory-hard KDF) |
| Memory dump attacks | `zeroize` crate for all key material |
| Passphrase loss | Guardian recovery network |
| Chain failure | Layer 0 (local backup) is always independent |
| Filecoin deal expiry | Chain automates renewal; Mode B provides independent redundancy |
| Token value collapse | Layer 0 survives all economic scenarios |

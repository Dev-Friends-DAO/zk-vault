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
| Storage | Google | AgileBits | Backblaze | Tarsnap | **User's choice: personal cloud or distributed (chain + Filecoin)** |
| Proof of data retention | None | None | None | None | **PoSt (Filecoin) + BFT consensus** |
| Single point of failure | Google | AgileBits | Backblaze | Tarsnap | **None** |
| Key loss recovery | Password reset | Recovery Kit | Password reset | Unrecoverable | **Guardian Network** |
| Quantum resistance | None | None | None | None | **ML-KEM-768 + X25519** |
| If operator disappears | Data at risk | Data at risk | Data at risk | Data at risk | **Local backup + chain + Filecoin** |
| Trust model | Trust the company | Trust the company | Trust the company | Trust the company | **Trust mathematics** |

### Competitive Landscape

zk-vault operates at the intersection of post-quantum cryptography, dedicated backup chains, and decentralized storage — a combination no existing project replicates.

#### Web3 storage competitors

|  | **zk-vault** | Jackal Protocol | Lighthouse | Walrus (Sui) | Crust Network | Lumera |
|---|---|---|---|---|---|---|
| Own chain | **BFT (PoA→DPoS)** | Cosmos L1 (PoS) | No (on Filecoin) | Tied to Sui | Polkadot parachain | Cosmos L1 |
| PQ encryption | **ML-KEM-768 + X25519** | No | No | No | No | No |
| Multi-mode storage | **A (personal) / B (native) / C (Filecoin)** | Chain-only | Filecoin-only | Network-only | IPFS-only | Network-only |
| Layer 0 (local-first) | **Always present, chain-independent** | No | No | No | No | No |
| BTC + ETH anchoring | **Per-backup Merkle root** | Babylon (chain-level security) | No | No | No | No |
| Endowment model | **On-chain module (Kryder's Law)** | Prepaid subscription | Pay-once-store-forever | Token rewards | Standard fees | Pay-once-store-forever |
| Guardian recovery | **Shamir + MPC + time-lock + Dead Man's Switch + ZKP** | No | No | No | No | No |
| ZKP system | **STARKs via risc0 (PQ-safe, planned)** | No | No | No | Researching ZK | No |
| Composability | **Insurance, legal, compliance verification** | IBC + Outposts | SDK | Move contracts | Cross-chain storage | Limited |
| Migration path | **Mode A→B/C without re-encryption** | No | No | No | No | No |

**Jackal Protocol** is the closest competitor — a Cosmos appchain with a Google Drive-like UI (Jackal Vault), Proof-of-Persistence, and IBC composability. However, Jackal lacks post-quantum cryptography, Layer 0 independence, guardian recovery, BTC/ETH data-level anchoring, and a personal-to-chain migration path.

**Lighthouse** offers pay-once-store-forever on Filecoin with threshold encryption (Kavach/BLS) and token-gated access. Strong on permanence and encryption, but no own chain, no PQ, no guardian recovery, and no local-first mode.

**Lumera Protocol** (formerly Pastel Network) has the closest endowment economics — Cascade provides pay-once-store-forever with self-healing on its Cosmos L1. However, it targets AI data permanence, not personal backup, and lacks every other zk-vault pillar.

#### PQ-capable chains (not backup products)

| | QANplatform | QRL | Algorand |
|---|---|---|---|
| PQ signatures | CRYSTALS-Dilithium | XMSS → SPHINCS+ | Falcon-1024 |
| PQ encryption for data | No | No | No |
| Storage / backup | No | No | No |
| Purpose | General L1 | General ledger | General L1 |

These chains have post-quantum signatures for transaction security but none provides encrypted storage, backup functionality, or data-level PQ encryption. The combination of **PQ encryption + dedicated backup chain** is a complete whitespace.

#### Centralized backup products

|  | Google Drive | 1Password | Backblaze | Tarsnap |
|---|---|---|---|---|
| Encryption | Server-side | Client-side | Client-side | Client-side |
| PQ encryption | No | No | No | No |
| Single point of failure | Google | AgileBits | Backblaze | Tarsnap |
| If operator disappears | Data at risk | Data at risk | Data at risk | Data at risk |
| Trust model | Trust the company | Trust the company | Trust the company | Trust the company |

All centralized products share the same fundamental weakness: trust a single company. zk-vault replaces company trust with mathematical guarantees.

#### Key gaps in the market

1. **PQ encryption + backup chain**: No storage chain uses post-quantum cryptography. No PQ chain has storage functionality.
2. **Local-first with chain upgrade**: Every web3 storage project is network-first. None offers an independent local mode with seamless chain migration.
3. **Guardian recovery for storage**: Social/device recovery exists for wallets (ERC-4337) but not for encrypted backup systems.
4. **STARK-based backup verification**: risc0 zkVM is production-ready, but no storage project uses STARKs for backup integrity proofs or recursive proof aggregation.
5. **Dual-chain data anchoring**: Projects anchor to at most one chain. Per-backup Merkle root anchoring to both Bitcoin and Ethereum is not done by any competitor.

### The "zk" in zk-vault

Today, "zk" refers to our **zero-knowledge architecture** — the system is designed so that no server, validator, or storage provider ever has access to plaintext data. All encryption and decryption happens on the user's device.

As the product evolves, "zk" will also encompass **zero-knowledge proofs** (ZKP) — cryptographic proofs that allow verification of facts without revealing underlying data. See [Section 7](#7-zero-knowledge-proofs-zkp) for the full vision.

---

## 2. Architecture Overview

zk-vault supports two deployment models: **Personal Mode** (standalone, no chain required) and **Chain Mode** (networked, full web3 capabilities).

### Personal Mode (Mode A)

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
                  +----------------------------+
                  |   Storage Provider         |
                  |   (user selects)            |
                  |                            |
                  |   S3 / GCS / Azure Blob /  |
                  |   Backblaze B2 / MinIO /   |
                  |   any S3-compatible        |
                  +----------------------------+
```

No chain, no token, no validators. The client encrypts data locally and pushes to a standard cloud storage provider of the user's choice. Layer 0 is always present as local backup.

This is zk-vault at its simplest — post-quantum encrypted backup with no external dependencies beyond a storage provider.

### Chain Mode (Mode B / Mode C)

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

### Why Chain Mode adds value

Personal Mode is fully functional on its own. But by connecting to the zk-vault Chain, users gain capabilities that are impossible to achieve alone:

| Capability | Personal Mode (A) | Chain Mode (B/C) |
|---|---|---|
| PQ hybrid encryption | Yes | Yes |
| Local backup (Layer 0) | Yes | Yes |
| Cloud storage | User-managed | Chain-managed |
| Data integrity proof | Local hash chain | BTC/ETH anchoring (immutable) |
| Storage verification | Trust the provider | BFT consensus / Filecoin PoSt |
| Redundancy | 1 provider + local | Multi-validator / multi-SP + local |
| Single point of failure | Provider + local | None |
| Key recovery | Unrecoverable if lost | Guardian network |
| Permanent storage | Provider-dependent | Endowment model |
| Deal lifecycle | Manual renewal | Automated on-chain |
| Multi-device sync | Manual | Chain state |
| ZKP verification | N/A | Future: recursive proof aggregation |
| Composability | N/A | Other dApps can verify backup status |

**The growth path is natural:** Start with Personal Mode for immediate value. Move to Chain Mode when you want stronger guarantees — without re-encrypting or migrating data.

### Role summary

| Component | Role |
|---|---|
| Local (Layer 0) | Safety net — independent of all crypto-economics |
| Storage Provider (Mode A) | Simple cloud storage for encrypted data |
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

### Mode A: Personal Store (No Chain)

The simplest deployment. The client encrypts data locally and pushes to a user-selected cloud storage provider via S3-compatible API.

**Supported providers (any S3-compatible):**
- AWS S3, Google Cloud Storage, Azure Blob Storage
- Backblaze B2, Wasabi, MinIO (self-hosted)
- Any provider supporting the S3 protocol

**What you get:**
- Post-quantum hybrid encryption (identical to Chain Mode)
- Round-trip verification and hash chain
- Layer 0 local backup
- Simple, familiar cloud storage

**What you don't get:**
- No BFT consensus or third-party verification
- No BTC/ETH anchoring
- No guardian recovery
- No automated deal lifecycle
- No multi-device sync via chain state
- Storage provider is a single point of trust (mitigated by Layer 0)

**Migration to Chain Mode:** Data encrypted in Personal Mode is fully compatible with Chain Mode. Migration means registering existing encrypted files on-chain — no re-encryption required.

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

| | Mode A (Personal) | Mode B (Native) | Mode C (Filecoin) |
|---|---|---|---|
| Requires chain | No | Yes | Yes |
| Speed | Provider-dependent | Fast (direct validator access) | Slower (IPFS gateway retrieval) |
| Verification | Local hash chain only | BFT consensus | PoSt (zk-SNARK) |
| Trust model | Trust the provider | Trust validator set | Trust Filecoin protocol |
| Permanence | Provider-dependent | Endowment model | Deal renewal |
| Scalability | Virtually unlimited | Limited by validator count | Virtually unlimited |
| Best for | Personal use, quick start | Smaller data, fast access | Large data, maximum distribution |

In Chain Mode, users can use **both Mode B and Mode C simultaneously** for critical data — Mode B for fast access, Mode C for independently verified redundancy.

Mode A users can migrate to Chain Mode at any time without re-encrypting data.

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

Authentication in zk-vault serves two distinct purposes:

1. **Vault unlock** — Derive the PDK to decrypt secret keys (encryption layer)
2. **Chain interaction** — Authorize transactions on-chain (identity layer)

These are deliberately separated. Compromising one does not compromise the other.

#### Authentication Modules (User-Selectable)

| Method | Mode A | Mode B/C | Description |
|---|---|---|---|
| **Passphrase** | Default | Available | User-chosen passphrase → Argon2id → PDK |
| **Passkey / Biometrics** | Available | Available | FIDO2/WebAuthn via device Secure Enclave (Face ID, fingerprint, hardware key). No chain required — runs locally on device. |
| **Session Key** | — | Available | Time-limited key with restricted permissions (e.g., backup-only, 24h expiry). Avoids repeated passphrase entry. |
| **Social Recovery** | — | Available | Guardian-based account recovery (see Section 8). |
| **External Wallet** | — | Available | Existing wallet (e.g., MetaMask) for chain authentication. |

Users choose their preferred method(s). Multiple methods can be active simultaneously (e.g., Passkey for daily use + passphrase as fallback + Guardian Recovery for emergencies).

#### Account Abstraction (Chain-Native)

In Chain Mode, accounts use native Account Abstraction — not bolted on via ERC-4337, but designed into the chain's account model from the start.

```
Account {
    auth: AuthModule,          // Pluggable: passphrase / passkey / multi-sig / social recovery
    encryption: KeyStore,      // ML-KEM + X25519 secret keys (encrypted by PDK)
    permissions: Vec<SessionKey>,  // Scoped, time-limited access grants
}
```

AA enables:
- **Pluggable signature verification** — ML-DSA-65, Passkey (P-256), or any scheme
- **Session Keys** — Scoped permissions without full key access
- **Social Recovery** — Guardians rotate auth keys without touching encryption keys
- **Gas abstraction** — Meta-transactions for UX simplicity

#### Design Principle

Authentication and encryption keys are independent layers:

```
Authentication (who you are)     Encryption (protecting data)
  Passkey / Wallet / etc.          Passphrase → Argon2id → PDK
         |                                  |
         v                                  v
  Chain transactions              Decrypt secret keys
```

A compromised wallet cannot decrypt backups. A leaked passphrase cannot submit chain transactions (in Mode B/C with wallet auth). Defense in depth.

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
| Storage architecture | 4 backends, fixed | 3 modes (A/B/C), user-selectable | Reduced complexity. Mode A for standalone use, Mode B/C for chain-backed guarantees. |

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

---

## Appendix: Resource and Environmental Impact

zk-vault is designed to minimize its footprint on external systems and the environment. This section documents the real costs honestly.

### Blockchain impact

| Resource | Impact | Mitigation |
|---|---|---|
| Bitcoin block space | OP_RETURN: 32 bytes per anchor tx | Super Merkle Tree batches all users into 1 tx per period. Impact is negligible compared to Ordinals/BRC-20 traffic. |
| Ethereum block space | Calldata: 32 bytes per anchor tx | Same batching. One tx regardless of user count. |
| Filecoin (Mode C) | Storage deals + PoSt verification | This is Filecoin's intended use. zk-vault is a consumer, not a burden. |

### Energy and compute

| Resource | Impact | Mitigation |
|---|---|---|
| Mode B validators | Node operation requires electricity and hardware | PoA/DPoS — no Proof-of-Work mining. Validator energy is comparable to running a standard server. |
| Mode A storage providers | Utilizes existing cloud data center infrastructure | No additional infrastructure created. Piggybacks on AWS/GCS/Azure economies of scale. |
| Argon2id KDF | 256MB memory + CPU per key derivation | Intentional cost (brute-force resistance). Runs once per session on the user's device. |
| ZKP generation (future) | STARK proof generation is compute-intensive | Runs client-side. No externalized compute cost. |

### Storage overhead

| Resource | Impact | Mitigation |
|---|---|---|
| Per-file encryption overhead | ~1.2 KB per file (KEM ciphertext + ephemeral key + nonce + wrapped key) | Negligible for files > 1 KB. For very small files, batching can amortize the overhead. |
| Mode B full replication (Phase 1) | All validators store all data (e.g., 5 nodes x 500GB = 2.5TB total) | Transitional. Phases into erasure coding (Phase 2) and sharding (Phase 3), reducing per-validator load. |
| Mode C redundancy | 4-6 Filecoin SPs per file | Intentional redundancy for data durability. Storage cost is paid by the user. |

### Economic costs to users

| Resource | Impact | Notes |
|---|---|---|
| BTC/ETH anchoring fees | ~$0.50/user/anchor with 1 user; ~$0.0005 with 1,000 users | Cost decreases as user base grows due to Super Merkle Tree batching. |
| Filecoin deal fees | Market-rate storage deals, renewed every 180-540 days | Endowment model (Mode B) eliminates recurring fees via one-time payment. |
| Mode A cloud storage | Standard cloud storage pricing (S3, GCS, etc.) | User chooses provider and pricing tier. |

### What zk-vault does NOT do

- **No Proof-of-Work mining** — PoA/DPoS consensus has no mining energy cost
- **No blockchain bloat** — only 32-byte Merkle roots are anchored, not data
- **No spam transactions** — batching ensures minimal on-chain footprint
- **No new infrastructure required** — Mode A runs on existing cloud providers; Mode B validators are standard servers
- **No external data exposure** — all data is encrypted client-side before any network interaction

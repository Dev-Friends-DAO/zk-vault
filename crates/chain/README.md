# zk-vault-chain

Chain node for zk-vault: Malachite BFT consensus, state machine, mempool, and JSON-RPC server.

## Modules

```
zk-vault-chain/
├── types.rs       # Block, Transaction, Validator, Address, Height
├── consensus.rs   # Malachite BFT Context implementation
├── state.rs       # ChainState, FileRegistry, GuardianRegistry, RecoveryRequests, KeyRegistry, apply_block()
├── mempool.rs     # Mempool, BlockBuilder, pre-validation
├── blob_store.rs  # Mode B: in-memory encrypted data store
├── node.rs        # Node actor (consensus driver)
├── rpc.rs         # JSON-RPC server (axum)
├── examples/
│   └── local_node.rs   # Single-node local dev server
└── tests/
    └── integration.rs  # 3-node network simulation
```

| Module | Role |
|---|---|
| `types` | Core blockchain types: `Height`, `Address`, `Validator`, `ValidatorSet`, `Transaction`, `Block`, `BlockId` |
| `consensus` | Maps domain types to Malachite's trait system (`Context`, `Value`, `Vote`, `Proposal`, `SigningScheme`) |
| `state` | Chain state machine with `file_registry`, `guardian_registry`, `recovery_requests`, `key_registry`. Ed25519 signature verification, block validation. |
| `mempool` | Transaction buffer with deduplication, pre-validation, capacity limits, and `BlockBuilder` for block proposal |
| `node` | Central actor coordinating state + mempool: `on_propose()`, `on_decided()`, `submit_tx()`, `status()`, `get_guardians()`, `get_recovery_status()`, `get_key_status()` |
| `blob_store` | In-memory encrypted data store for Mode B (validators store blobs directly) |
| `rpc` | HTTP JSON-RPC server with `Arc<Mutex<Node>>` shared state |

## Transaction Lifecycle

```
Client TX
   │
   ▼
Mempool (in-memory BTreeMap)
   │  pre-validate: signature check, dedup, capacity
   ▼
on_propose() ── BlockBuilder reaps txs, trial-applies, computes state_root
   │
   ▼
Consensus (Malachite BFT, 2/3+ quorum)
   │
   ▼
on_decided() ── apply_block()
   │  ├─ ChainState 更新 (file/guardian/recovery/key registries)
   │  ├─ storage.save_chain_state() → RocksDB 永続化
   │  └─ Mempool purge + revalidate
   ▼
Block committed
```

On restart, `load_chain_state()` reconstructs `ChainState` from RocksDB.
Mempool is ephemeral — uncommitted transactions are lost on restart.

## Quick Start

```bash
# Run all chain tests
cargo test -p zk-vault-chain

# Start a local dev node
cargo run -p zk-vault-chain --example local_node
```

## RPC Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/status` | Node status (height, file count, validators, pending txs) |
| POST | `/submit_tx` | Submit a transaction to the mempool |
| POST | `/propose` | Trigger propose + decide cycle (dev/single-validator) |
| POST | `/get_file` | Query a registered file by merkle root |
| POST | `/upload_data` | Upload encrypted data blob (Mode B) |
| POST | `/download_data` | Download encrypted data blob (Mode B) |
| GET | `/list_data` | List stored blobs and total size (Mode B) |
| GET | `/anchor_status` | Super Merkle Tree root + per-file proofs for anchoring |
| POST | `/get_guardians` | Query guardian set for an owner |
| POST | `/get_recovery_status` | Query recovery request status for an owner |
| POST | `/get_key_status` | Query key status (current pk, revoked pks) for an owner |

See [docs/CLI.md](../../docs/CLI.md) for full RPC reference (request/response examples, error codes, curl commands, E2E workflows).

## Transaction Types

| Type | Fields | Description |
|---|---|---|
| `RegisterFile` | `merkle_root`, `file_count`, `encrypted_size`, `owner_pk`, `signature` | Register a new backup on-chain |
| `VerifyIntegrity` | `merkle_root`, `verifier_pk`, `signature` | Attest integrity of an existing backup |
| `UpdateValidatorSet` | `validators`, `signature` | Governance: update the validator set |
| `RegisterGuardian` | `owner_pk`, `guardian_pk`, `encrypted_share`, `threshold`, `signature` | Register a guardian with their PQ-encrypted Shamir share |
| `RequestRecovery` | `owner_pk`, `new_pk`, `signature` | Initiate key recovery (requires guardian set) |
| `ApproveRecovery` | `owner_pk`, `guardian_pk`, `share_data`, `signature` | Guardian approves recovery with decrypted share |
| `RevokeKeys` | `owner_pk`, `new_pk`, `signature` | Revoke current keys and register new ones |

## Tests

```bash
cargo test -p zk-vault-chain              # all (81 tests)
cargo test -p zk-vault-chain --lib        # unit tests only (67)
cargo test -p zk-vault-chain --test integration  # integration only (9)
```

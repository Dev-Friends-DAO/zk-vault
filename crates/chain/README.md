# zk-vault-chain

Chain node for zk-vault: Malachite BFT consensus, state machine, mempool, and JSON-RPC server.

## Modules

```
zk-vault-chain/
├── types.rs       # Block, Transaction, Validator, Address, Height
├── consensus.rs   # Malachite BFT Context implementation
├── state.rs       # ChainState, FileRegistry, apply_block()
├── mempool.rs     # Mempool, BlockBuilder, pre-validation
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
| `state` | Chain state machine with `FileRegistry` (`BTreeMap<merkle_root, FileEntry>`), Ed25519 signature verification, block validation |
| `mempool` | Transaction buffer with deduplication, pre-validation, capacity limits, and `BlockBuilder` for block proposal |
| `node` | Central actor coordinating state + mempool: `on_propose()`, `on_decided()`, `submit_tx()`, `status()` |
| `rpc` | HTTP JSON-RPC server with `Arc<Mutex<Node>>` shared state |

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

See [docs/CLI.md](../../docs/CLI.md) for full RPC reference (request/response examples, error codes, curl commands, E2E workflows).

## Transaction Types

| Type | Fields | Description |
|---|---|---|
| `RegisterFile` | `merkle_root`, `file_count`, `encrypted_size`, `owner_pk`, `signature` | Register a new backup on-chain |
| `VerifyIntegrity` | `merkle_root`, `verifier_pk`, `signature` | Attest integrity of an existing backup |
| `UpdateValidatorSet` | `validators`, `signature` | Governance: update the validator set |

## Tests

```bash
cargo test -p zk-vault-chain              # all (57 tests)
cargo test -p zk-vault-chain --lib        # unit tests only (51)
cargo test -p zk-vault-chain --test integration  # integration only (6)
```

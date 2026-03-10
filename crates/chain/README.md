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

Default address: `http://127.0.0.1:3030`

### GET /health

Health check.

```bash
curl localhost:3030/health
# ok
```

### GET /status

Returns current node status.

```bash
curl -s localhost:3030/status | jq
```

Response:

```json
{
  "height": 0,
  "last_block_id": "a1b2c3...",
  "state_root": "d4e5f6...",
  "file_count": 0,
  "validator_count": 3,
  "pending_txs": 0,
  "blocks_committed": 0
}
```

### POST /submit_tx

Submit a transaction to the mempool. The transaction is pre-validated (signature check, state check) before acceptance.

```bash
curl -s -X POST localhost:3030/submit_tx \
  -H 'Content-Type: application/json' \
  -d '{"tx_json":"{\"RegisterFile\":{...}}"}' | jq
```

Response:

```json
{
  "tx_hash": "abc123..."
}
```

Errors:
- `400` — Invalid JSON
- `422` — Pre-validation failed (bad signature, duplicate, etc.)

### POST /propose

Trigger a propose + decide cycle (for testing / single-validator mode). Builds a block from the mempool and commits it.

```bash
curl -s -X POST localhost:3030/propose | jq
```

Response:

```json
{
  "height": 1,
  "tx_count": 3
}
```

### POST /get_file

Query a registered file by merkle root (64 hex chars).

```bash
curl -s -X POST localhost:3030/get_file \
  -H 'Content-Type: application/json' \
  -d '{"merkle_root":"abababab...64 hex chars..."}' | jq
```

Response:

```json
{
  "merkle_root": "abab...",
  "owner_pk": "0102...",
  "file_count": 5,
  "encrypted_size": 10240,
  "registered_at": 1,
  "verification_count": 0
}
```

Errors:
- `400` — Invalid hex or wrong length
- `404` — File not found

## Typical Workflow

```bash
# 1. Start node
cargo run -p zk-vault-chain --example local_node

# 2. Check genesis status
curl -s localhost:3030/status | jq
# → height: 0, file_count: 0

# 3. Submit transaction (copy from startup output)
curl -s -X POST localhost:3030/submit_tx \
  -H 'Content-Type: application/json' \
  -d '{"tx_json":"..."}' | jq
# → tx_hash: "abc..."

# 4. Verify pending
curl -s localhost:3030/status | jq
# → pending_txs: 1

# 5. Commit block
curl -s -X POST localhost:3030/propose | jq
# → height: 1, tx_count: 1

# 6. Verify committed
curl -s localhost:3030/status | jq
# → height: 1, file_count: 1, pending_txs: 0

# 7. Query the file
curl -s -X POST localhost:3030/get_file \
  -H 'Content-Type: application/json' \
  -d '{"merkle_root":"abab..."}' | jq
# → owner_pk, file_count, registered_at, etc.
```

## Transaction Types

| Type | Fields | Description |
|---|---|---|
| `RegisterFile` | `merkle_root`, `file_count`, `encrypted_size`, `owner_pk`, `signature` | Register a new backup on-chain |
| `VerifyIntegrity` | `merkle_root`, `verifier_pk`, `signature` | Attest integrity of an existing backup |
| `UpdateValidatorSet` | `validators`, `signature` | Governance: update the validator set |

## Tests

```bash
# Unit tests (51 tests across all modules)
cargo test -p zk-vault-chain --lib

# Integration tests (6 tests: 3-node network simulation)
cargo test -p zk-vault-chain --test integration

# All chain tests
cargo test -p zk-vault-chain

# With output
cargo test -p zk-vault-chain -- --nocapture
```

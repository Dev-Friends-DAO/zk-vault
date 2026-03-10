# zk-vault Command Reference

All CLI commands, chain RPC endpoints, and development commands in one place.

## CLI Commands

### Install

```bash
cargo build -p zk-vault-cli --release
# Binary: target/release/zk-vault
```

### `zk-vault init`

Generate post-quantum + classical key pairs and create a new vault.

```bash
zk-vault init
```

- Prompts for a passphrase (used to encrypt the master key via Argon2id)
- Generates: ML-KEM-768, X25519, ML-DSA-65, Ed25519 key pairs
- Saves keystore to `~/.zk-vault/keystore.json`
- Fails if vault already exists (remove keystore to reinitialize)

### `zk-vault backup`

Encrypt files and store them to one or more targets.

```bash
zk-vault backup [OPTIONS] <PATHS>...
```

| Flag | Description |
|---|---|
| `--local <DIR>` | Save encrypted backups to a local directory (Layer 0) |
| `--chain <URL>` | Register backup on zk-vault chain (e.g., `http://localhost:3030`) |

**Storage target combinations:**

```bash
# Local only (Mode A — Layer 0)
zk-vault backup --local ./backups ./my-data

# S3 only (requires ~/.zk-vault/config.toml)
zk-vault backup ./my-data

# S3 + local
zk-vault backup --local ./backups ./my-data

# Local + chain registration
zk-vault backup --local ./backups --chain http://localhost:3030 ./my-data

# S3 + local + chain registration
zk-vault backup --local ./backups --chain http://localhost:3030 ./my-data
```

**What happens:**

1. Reads and encrypts each file (XChaCha20-Poly1305 + hybrid KEM key wrap)
2. Stores encrypted bundles to selected targets (local / S3)
3. Builds BLAKE3 Merkle tree from all encrypted file hashes
4. Saves manifest to `~/.zk-vault/manifests/<backup-id>.json`
5. If `--chain`: signs Merkle root with Ed25519, submits `RegisterFile` tx to chain RPC

Chain registration is non-fatal — if the chain is unreachable, backup data is already saved.

### `zk-vault restore`

Decrypt and restore files from a backup.

```bash
zk-vault restore <BACKUP> [-o <OUTPUT>]
```

| Arg | Description |
|---|---|
| `<BACKUP>` | Backup ID (UUID) or path to a manifest `.json` file |
| `-o, --output <DIR>` | Output directory (default: `.`) |

```bash
zk-vault restore 019533a2-... -o ./restored
zk-vault restore ~/.zk-vault/manifests/019533a2-....json -o ./restored
```

**What happens:**

1. Loads and verifies manifest (Merkle root integrity check)
2. Unlocks keys with passphrase
3. Downloads encrypted bundles (tries local first, then S3)
4. Decapsulates hybrid KEM → recovers per-file symmetric key
5. Decrypts each file and verifies content hash against manifest
6. Writes restored files to output directory

### `zk-vault verify`

Verify backup integrity without decrypting.

```bash
zk-vault verify <BACKUP>
```

| # | Check | Description |
|---|---|---|
| 1 | Merkle root integrity | Recompute Merkle tree from manifest and compare roots |
| 2 | Storage availability | Check all encrypted bundles exist in at least one location |
| 3 | Bundle hash verification | Download bundles and verify they parse correctly |
| 4 | Manifest consistency | Verify file_count and size totals match |

### `zk-vault status`

Show vault status: keys, storage config, and recent backups.

```bash
zk-vault status
```

Output: vault path, keystore version, public key fingerprints, S3 config, recent backups (up to 5).

---

## Chain RPC Endpoints

Default address: `http://127.0.0.1:3030`

Start a local dev node:

```bash
cargo run -p zk-vault-chain --example local_node
```

### GET /health

```bash
curl localhost:3030/health
# ok
```

### GET /status

```bash
curl -s localhost:3030/status | jq
```

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

Submit a transaction to the mempool. Pre-validated (signature check, state check) before acceptance.

```bash
curl -s -X POST localhost:3030/submit_tx \
  -H 'Content-Type: application/json' \
  -d '{"tx_json":"{\"RegisterFile\":{...}}"}' | jq
```

```json
{ "tx_hash": "abc123..." }
```

Errors: `400` (invalid JSON), `422` (pre-validation failed).

### POST /propose

Trigger a propose + decide cycle (testing / single-validator mode).

```bash
curl -s -X POST localhost:3030/propose | jq
```

```json
{ "height": 1, "tx_count": 3 }
```

### POST /get_file

Query a registered file by merkle root (64 hex chars).

```bash
curl -s -X POST localhost:3030/get_file \
  -H 'Content-Type: application/json' \
  -d '{"merkle_root":"abababab...64 hex chars..."}' | jq
```

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

Errors: `400` (invalid hex or wrong length), `404` (file not found).

### Transaction Types

| Type | Fields | Description |
|---|---|---|
| `RegisterFile` | `merkle_root`, `file_count`, `encrypted_size`, `owner_pk`, `signature` | Register a new backup on-chain |
| `VerifyIntegrity` | `merkle_root`, `verifier_pk`, `signature` | Attest integrity of an existing backup |
| `UpdateValidatorSet` | `validators`, `signature` | Governance: update the validator set |

---

## Configuration

### `~/.zk-vault/config.toml`

```bash
cp config.example.toml ~/.zk-vault/config.toml
```

```toml
[storage.s3]
bucket = "my-zk-vault-backups"
region = "us-east-1"
# endpoint = "https://s3.us-west-000.backblazeb2.com"  # for S3-compatible providers
access_key = ""
secret_key = ""
# path_style = true  # required for MinIO and some S3-compatible providers
```

If no config exists, use `--local` for local-only backups.

### File Layout

```
~/.zk-vault/
├── keystore.json              # Encrypted key pairs
├── config.toml                # Storage settings (user-created)
└── manifests/
    ├── <backup-id-1>.json     # Backup manifest
    └── <backup-id-2>.json
```

### Environment Variables

| Variable | Description |
|---|---|
| `RUST_LOG` | Logging level (e.g., `RUST_LOG=zk_vault=debug`) |

---

## Development Commands

### Build

```bash
cargo build --workspace                    # build all crates
cargo build -p zk-vault-cli --release      # release binary
```

### Test

```bash
cargo test --workspace                     # all tests (117 total)
cargo test -p zk-vault-core               # core: 60 tests
cargo test -p zk-vault-chain              # chain: 57 tests (51 unit + 6 integration)
cargo test -p zk-vault-chain --lib        # chain unit tests only
cargo test -p zk-vault-chain --test integration  # chain integration tests only
cargo test -p zk-vault-cli               # CLI tests
cargo test -- --nocapture                 # with output
```

### Lint & Format

```bash
cargo clippy --workspace -- -D warnings
cargo fmt                                  # auto-format
cargo fmt -- --check                       # check formatting (CI)
```

### Pre-commit Hooks (lefthook)

```bash
brew install lefthook   # or: cargo install lefthook
lefthook install
```

Runs automatically on `git commit`:
1. `cargo fmt` (auto-fix)
2. `cargo fmt -- --check`
3. `cargo clippy -- -D warnings`
4. `cargo test`

---

## End-to-End Workflow

### Chain node workflow (curl)

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
```

### CLI + Chain (E2E)

```bash
# Terminal 1: Start chain node
cargo run -p zk-vault-chain --example local_node

# Terminal 2: CLI workflow
zk-vault init
zk-vault backup --local ./backups --chain http://localhost:3030 ./my-data
# → Backup complete. Chain registration: SUCCESS (tx_hash: ...)

curl -s -X POST localhost:3030/propose | jq
# → height: 1, tx_count: 1

zk-vault verify <backup-id>
# → Verification PASSED (4/4 checks).

zk-vault restore <backup-id> -o ./restored
# → Restore complete.
```

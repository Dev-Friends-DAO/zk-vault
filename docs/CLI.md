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
zk-vault init [--generate-keyfile <PATH>] [--keyfile <PATH>]
```

| Flag | Description |
|---|---|
| `--generate-keyfile <PATH>` | Generate a 64-byte random keyfile and save to the given path (permissions set to 0400) |
| `--keyfile <PATH>` | Use an existing keyfile for PDK derivation |

- Prompts for a passphrase (used to encrypt the master key via Argon2id)
- Generates: ML-KEM-768, X25519, ML-DSA-65, Ed25519 key pairs
- Generates and displays a **24-word BIP-39 mnemonic** that encodes the master key (store this offline for recovery)
- If `--generate-keyfile`: creates a random keyfile and mixes it into PDK derivation via BLAKE3
- If `--keyfile`: reads the keyfile and mixes it into PDK derivation via BLAKE3
- Saves keystore (v2 format) to `~/.zk-vault/keystore.json`
- Fails if vault already exists (remove keystore to reinitialize)

```bash
# Basic init
zk-vault init

# Init with keyfile generation (two-factor: passphrase + keyfile)
zk-vault init --generate-keyfile ~/zk-vault.key

# Init with existing keyfile
zk-vault init --keyfile ~/my-existing.key
```

### `zk-vault backup`

Encrypt files and store them to one or more targets.

```bash
zk-vault backup [OPTIONS] <PATHS>...
```

| Flag | Description |
|---|---|
| `--local <DIR>` | Save encrypted backups to a local directory (Layer 0) |
| `--chain <URL>` | Register backup on zk-vault chain (e.g., `http://localhost:3030`) |
| `--keyfile <PATH>` | Path to keyfile for vault unlock (required if vault was created with a keyfile) |

**Storage target combinations:**

```bash
# Local only (Mode A — Layer 0)
zk-vault backup --local ./backups ./my-data

# S3 only (requires ~/.zk-vault/config.toml)
zk-vault backup ./my-data

# S3 + local
zk-vault backup --local ./backups ./my-data

# Chain only (Mode B — validators store data)
zk-vault backup --chain http://localhost:3030 ./my-data

# Local + chain (Mode B + Layer 0)
zk-vault backup --local ./backups --chain http://localhost:3030 ./my-data

# S3 + local + chain
zk-vault backup --local ./backups --chain http://localhost:3030 ./my-data
```

**What happens:**

1. Reads and encrypts each file (XChaCha20-Poly1305 + hybrid KEM key wrap)
2. Stores encrypted bundles to selected targets (local / S3)
3. Builds BLAKE3 Merkle tree from all encrypted file hashes
4. Saves manifest to `~/.zk-vault/manifests/<backup-id>.json`
5. If `--chain`: signs Merkle root with Ed25519, submits `RegisterFile` tx to chain RPC
6. If `--chain`: uploads encrypted data bundles to chain validators via `/upload_data` (Mode B)

Chain registration and upload are non-fatal — if the chain is unreachable, backup data is already saved locally.

### `zk-vault restore`

Decrypt and restore files from a backup.

```bash
zk-vault restore <BACKUP> [-o <OUTPUT>] [--chain <URL>] [--keyfile <PATH>]
```

| Arg / Flag | Description |
|---|---|
| `<BACKUP>` | Backup ID (UUID) or path to a manifest `.json` file |
| `-o, --output <DIR>` | Output directory (default: `.`) |
| `--chain <URL>` | Download from chain node (Mode B) (e.g., `http://localhost:3030`) |
| `--keyfile <PATH>` | Path to keyfile for vault unlock |

```bash
# Restore from local / S3
zk-vault restore 019533a2-... -o ./restored

# Restore from chain (Mode B)
zk-vault restore 019533a2-... -o ./restored --chain http://localhost:3030

# With explicit manifest path
zk-vault restore ~/.zk-vault/manifests/019533a2-....json -o ./restored
```

**What happens:**

1. Loads and verifies manifest (Merkle root integrity check)
2. Unlocks keys with passphrase
3. Downloads encrypted bundles (tries: local → S3 → chain, in order per storage location)
4. Decapsulates hybrid KEM → recovers per-file symmetric key
5. Decrypts each file and verifies content hash against manifest
6. Writes restored files to output directory

### `zk-vault verify`

Verify backup integrity without decrypting.

```bash
zk-vault verify <BACKUP> [--chain <URL>] [--keyfile <PATH>]
```

| # | Check | Description |
|---|---|---|
| 1 | Merkle root integrity | Recompute Merkle tree from manifest and compare roots |
| 2 | Storage availability | Check all encrypted bundles exist in at least one location |
| 3 | Bundle hash verification | Download bundles and verify they parse correctly |
| 4 | Manifest consistency | Verify file_count and size totals match |

### `zk-vault anchor`

Anchor a backup's Merkle root to Bitcoin (OP_RETURN) and/or Ethereum (calldata).

```bash
zk-vault anchor <BACKUP> --btc --eth
```

| Flag | Description |
|---|---|
| `--btc` | Anchor to Bitcoin via OP_RETURN |
| `--eth` | Anchor to Ethereum via calldata |

```bash
# Anchor to Bitcoin only
zk-vault anchor <backup-id> --btc

# Anchor to Ethereum only
zk-vault anchor <backup-id> --eth

# Anchor to both
zk-vault anchor <backup-id> --btc --eth
```

Requires `[anchor.bitcoin]` and/or `[anchor.ethereum]` in `~/.zk-vault/config.toml`.

Anchor receipts are saved to `~/.zk-vault/manifests/<backup-id>.anchors.json`.

### `zk-vault backup --anchor`

The `--anchor` flag on `backup` automatically anchors the Merkle root to all configured blockchains after backup completes:

```bash
zk-vault backup --local ./backups --anchor ./my-data
zk-vault backup --local ./backups --chain http://localhost:3030 --anchor ./my-data
```

### `zk-vault status`

Show vault status: keys, storage config, and recent backups.

```bash
zk-vault status [--chain <URL>] [--keyfile <PATH>]
```

Output: vault path, keystore version, public key fingerprints, S3 config, recent backups (up to 5).

If `--chain`: also shows chain height, file count, validators, and cross-references local manifests with on-chain registration status.

### `zk-vault recover`

Recover a vault from a 24-word BIP-39 mnemonic phrase.

```bash
zk-vault recover [--keyfile <PATH>] [--generate-keyfile <PATH>]
```

| Flag | Description |
|---|---|
| `--keyfile <PATH>` | Use an existing keyfile for the recovered vault |
| `--generate-keyfile <PATH>` | Generate a new keyfile for the recovered vault |

- Prompts for the 24-word mnemonic phrase
- Prompts for a new passphrase
- Recovers the Master Key from the mnemonic
- Generates fresh key pairs (ML-KEM-768, X25519, ML-DSA-65, Ed25519)
- Encrypts new key pairs under the recovered MK
- Saves new keystore to `~/.zk-vault/keystore.json`
- Warns if an existing keystore will be overwritten

```bash
# Basic recovery
zk-vault recover

# Recovery with new keyfile
zk-vault recover --generate-keyfile ~/new-vault.key
```

### `zk-vault guardian`

Guardian recovery management commands.

#### `zk-vault guardian setup`

Split the Master Key into Shamir shares and encrypt each for a guardian.

```bash
zk-vault guardian setup [--threshold <K>] [--shares <N>] [--output <DIR>] [--keyfile <PATH>]
```

| Flag | Description |
|---|---|
| `--threshold <K>` | Number of shares required for recovery (default: 3) |
| `--shares <N>` | Total number of shares to generate (default: 5) |
| `--output <DIR>` | Directory to write encrypted share files (default: `.`) |
| `--keyfile <PATH>` | Path to keyfile for vault unlock |

- Unlocks the vault to access the Master Key
- Splits MK into N Shamir shares (GF(256)) with threshold K
- Encrypts each share using hybrid PQ KEM (ML-KEM-768 + X25519)
- Writes one JSON file per share to the output directory
- Each share file is intended for distribution to a specific guardian

```bash
# Default 3-of-5
zk-vault guardian setup

# Custom threshold
zk-vault guardian setup --threshold 2 --shares 3 --output ./shares
```

#### `zk-vault guardian list`

List registered guardians for the current user on chain.

```bash
zk-vault guardian list --chain <URL>
```

#### `zk-vault guardian register`

Register a guardian's encrypted share on chain.

```bash
zk-vault guardian register --share-file <PATH> --chain <URL> [--keyfile <PATH>]
```

| Flag | Description |
|---|---|
| `--share-file <PATH>` | Path to the encrypted share JSON file |
| `--chain <URL>` | Chain node URL |
| `--keyfile <PATH>` | Path to keyfile for vault unlock |

### `zk-vault rotate-keys`

Generate new encryption and signing keys, re-encrypt the Master Key, and optionally submit a `RevokeKeys` transaction to the chain.

```bash
zk-vault rotate-keys [--chain <URL>] [--keyfile <PATH>]
```

| Flag | Description |
|---|---|
| `--chain <URL>` | Submit `RevokeKeys` tx to chain (marks old keys as revoked) |
| `--keyfile <PATH>` | Path to keyfile for vault unlock |

- Unlocks vault with current passphrase
- Generates new ML-KEM-768, X25519, ML-DSA-65, Ed25519 key pairs
- Generates new mnemonic for the new MK
- Re-encrypts MK with the new PDK
- If `--chain`: submits `RevokeKeys` tx to invalidate old keys on chain
- Displays the new mnemonic (must be stored for future recovery)

```bash
# Local-only rotation (Mode A)
zk-vault rotate-keys

# Rotation with chain revocation (Mode B/C)
zk-vault rotate-keys --chain http://localhost:3030
```

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

### POST /upload_data (Mode B)

Upload an encrypted data blob to the validator's store.

```bash
curl -s -X POST localhost:3030/upload_data \
  -H 'Content-Type: application/json' \
  -d '{"key":"user-id/file-id","data_b64":"AQIDBA=="}' | jq
```

```json
{ "key": "user-id/file-id", "size": 4 }
```

### POST /download_data (Mode B)

Download an encrypted data blob by key.

```bash
curl -s -X POST localhost:3030/download_data \
  -H 'Content-Type: application/json' \
  -d '{"key":"user-id/file-id"}' | jq
```

```json
{ "key": "user-id/file-id", "data_b64": "AQIDBA==", "size": 4 }
```

Errors: `404` (blob not found).

### GET /list_data (Mode B)

List all stored blobs and total size.

```bash
curl -s localhost:3030/list_data | jq
```

```json
{ "keys": ["user-id/file-a", "user-id/file-b"], "total_size": 2048 }
```

### GET /anchor_status

Get the Super Merkle Tree root and per-file inclusion proofs for anchoring.

```bash
curl -s localhost:3030/anchor_status | jq
```

```json
{
  "file_count": 3,
  "super_root": "abcdef...",
  "user_proofs": [
    {
      "owner_pk": "0102...",
      "merkle_root": "aabb...",
      "proof_index": 0,
      "proof_hashes": ["ccdd...", "eeff..."]
    }
  ]
}
```

The `super_root` is the single 32-byte hash that gets anchored to BTC/ETH. One transaction covers all registered files.

### POST /get_guardians

Query the guardian set for an owner.

```bash
curl -s -X POST localhost:3030/get_guardians \
  -H 'Content-Type: application/json' \
  -d '{"owner_pk":"0102...64 hex chars..."}' | jq
```

```json
{
  "owner_pk": "0102...",
  "guardians": [
    { "guardian_pk": "aabb...", "share_index": 1 }
  ],
  "threshold": 3,
  "registered_at": 5
}
```

Errors: `400` (invalid hex), `404` (no guardian set for this owner).

### POST /get_recovery_status

Query the recovery request status for an owner.

```bash
curl -s -X POST localhost:3030/get_recovery_status \
  -H 'Content-Type: application/json' \
  -d '{"owner_pk":"0102...64 hex chars..."}' | jq
```

```json
{
  "owner_pk": "0102...",
  "new_pk": "ccdd...",
  "status": "Pending",
  "approvals": 1,
  "threshold": 3,
  "requested_at": 10
}
```

Errors: `400` (invalid hex), `404` (no recovery request for this owner).

### POST /get_key_status

Query the key status (current public key and revoked keys) for an owner.

```bash
curl -s -X POST localhost:3030/get_key_status \
  -H 'Content-Type: application/json' \
  -d '{"owner_pk":"0102...64 hex chars..."}' | jq
```

```json
{
  "current_pk": "eeff...",
  "revoked_pks": ["0102..."],
  "updated_at": 15
}
```

Errors: `400` (invalid hex), `404` (no key entry for this owner).

### Transaction Types

| Type | Fields | Description |
|---|---|---|
| `RegisterFile` | `merkle_root`, `file_count`, `encrypted_size`, `owner_pk`, `signature` | Register a new backup on-chain |
| `VerifyIntegrity` | `merkle_root`, `verifier_pk`, `signature` | Attest integrity of an existing backup |
| `UpdateValidatorSet` | `validators`, `signature` | Governance: update the validator set |
| `RegisterGuardian` | `owner_pk`, `guardian_pk`, `encrypted_share`, `threshold`, `signature` | Register a guardian with their PQ-encrypted Shamir share |
| `RequestRecovery` | `owner_pk`, `new_pk`, `signature` | Initiate key recovery (requires guardian set) |
| `ApproveRecovery` | `owner_pk`, `guardian_pk`, `share_data`, `signature` | Guardian approves recovery with decrypted share |
| `RevokeKeys` | `owner_pk`, `new_pk`, `signature` | Revoke current keys and register new ones |

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

```toml
[anchor.bitcoin]
api_url = "https://mempool.space/testnet/api"
network = "testnet"         # "mainnet", "testnet", or "signet"
wif_private_key = ""        # Bitcoin WIF private key

[anchor.ethereum]
rpc_url = "https://sepolia.infura.io/v3/YOUR_KEY"
network = "sepolia"         # "mainnet", "sepolia", or "holesky"
private_key_hex = ""        # Ethereum private key (hex, no 0x prefix)
chain_id = 11155111         # 1 for mainnet, 11155111 for Sepolia
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
cargo test --workspace                     # all tests (162 total)
cargo test -p zk-vault-core               # core: 81 tests
cargo test -p zk-vault-chain              # chain: 81 tests (72 unit + 9 integration)
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

### CLI + Chain — Mode B (E2E)

```bash
# Terminal 1: Start chain node
cargo run -p zk-vault-chain --example local_node

# Terminal 2: CLI workflow
zk-vault init

# Backup to chain (Mode B: data stored on validators)
zk-vault backup --chain http://localhost:3030 ./my-data
# → Backup complete. Chain registration: SUCCESS
# → Chain upload: 3/3 files uploaded

# Also keep local copy (recommended)
zk-vault backup --local ./backups --chain http://localhost:3030 ./my-data

# Commit the block
curl -s -X POST localhost:3030/propose | jq
# → height: 1, tx_count: 1

# Verify (checks local + chain storage)
zk-vault verify <backup-id> --chain http://localhost:3030
# → Verification PASSED (4/4 checks).

# Restore from chain (no local files needed)
zk-vault restore <backup-id> -o ./restored --chain http://localhost:3030
# → Restore complete.

# Check chain status
zk-vault status --chain http://localhost:3030
# → Chain: height 1, 1 file(s), 3 validators
```

### CLI + Chain — Mode B curl workflow

```bash
# Upload blob directly
curl -s -X POST localhost:3030/upload_data \
  -H 'Content-Type: application/json' \
  -d '{"key":"my-blob","data_b64":"AQIDBA=="}' | jq

# Download blob
curl -s -X POST localhost:3030/download_data \
  -H 'Content-Type: application/json' \
  -d '{"key":"my-blob"}' | jq

# List all blobs
curl -s localhost:3030/list_data | jq
```

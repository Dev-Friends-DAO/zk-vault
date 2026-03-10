# zk-vault CLI Reference

## Install

```bash
cargo build -p zk-vault-cli --release
# Binary: target/release/zk-vault
```

## Quick Start

```bash
zk-vault init                                    # generate keys
zk-vault backup --local ./backups ./my-data      # encrypt + backup
zk-vault verify <backup-id>                      # check integrity
zk-vault restore <backup-id> -o ./restored       # decrypt + restore
```

## Commands

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

**Options:**

| Flag | Description |
|---|---|
| `--local <DIR>` | Save encrypted backups to a local directory (Layer 0) |
| `--chain <URL>` | Register backup on zk-vault chain (e.g., `http://localhost:3030`) |

**Storage targets:**

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

**Chain registration** is non-fatal — if the chain is unreachable, backup data is already saved. You can register later manually via `curl`.

### `zk-vault restore`

Decrypt and restore files from a backup.

```bash
zk-vault restore <BACKUP> [-o <OUTPUT>]
```

**Arguments:**

| Arg | Description |
|---|---|
| `<BACKUP>` | Backup ID (UUID) or path to a manifest `.json` file |
| `-o, --output <DIR>` | Output directory (default: `.`) |

```bash
# Restore by backup ID
zk-vault restore 019533a2-... -o ./restored

# Restore by manifest path
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

**Checks performed:**

| # | Check | Description |
|---|---|---|
| 1 | Merkle root integrity | Recompute Merkle tree from manifest and compare roots |
| 2 | Storage availability | Check that all encrypted bundles exist in at least one storage location |
| 3 | Bundle hash verification | Download bundles and verify they parse as valid encrypted bundles |
| 4 | Manifest consistency | Verify file_count and size totals match |

```bash
zk-vault verify 019533a2-...
# → Verification PASSED (4/4 checks).
```

### `zk-vault status`

Show vault status: keys, storage config, and recent backups.

```bash
zk-vault status
```

**Output includes:**

- Vault path and keystore version
- Public key fingerprints (BLAKE3, first 8 bytes)
- S3 storage config (bucket, region, endpoint)
- Recent backups (up to 5, sorted by date)

## Configuration

The CLI reads `~/.zk-vault/config.toml` for S3 storage settings.

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

## File Layout

```
~/.zk-vault/
├── keystore.json              # Encrypted key pairs
├── config.toml                # Storage settings (user-created)
└── manifests/
    ├── <backup-id-1>.json     # Backup manifest
    └── <backup-id-2>.json
```

## Environment Variables

| Variable | Description |
|---|---|
| `RUST_LOG` | Logging level (e.g., `RUST_LOG=zk_vault=debug`) |

## Examples

### Full E2E: backup → chain → verify

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

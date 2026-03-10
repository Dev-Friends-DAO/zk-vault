# zk-vault-cli

CLI binary for zk-vault: post-quantum secure backup from the command line.

## Install

```bash
cargo build -p zk-vault-cli --release
# Binary: target/release/zk-vault
```

## Commands

| Command | Description |
|---|---|
| `zk-vault init` | Generate PQ + classical key pairs, create vault |
| `zk-vault backup` | Encrypt files and store to local / S3 / chain |
| `zk-vault restore` | Decrypt and restore files from a backup |
| `zk-vault verify` | Verify backup integrity without decrypting |
| `zk-vault status` | Show vault info, keys, storage config, backups |

## Quick Start

```bash
# 1. Create a vault
zk-vault init

# 2. Backup files (local only)
zk-vault backup --local ./backups ./my-data

# 3. Backup + register on chain
zk-vault backup --local ./backups --chain http://localhost:3030 ./my-data

# 4. Verify integrity
zk-vault verify <backup-id>

# 5. Restore
zk-vault restore <backup-id> -o ./restored
```

## Flags

### `zk-vault backup`

| Flag | Description |
|---|---|
| `--local <DIR>` | Save encrypted backups to a local directory (Layer 0) |
| `--chain <URL>` | Register backup on zk-vault chain RPC |

Without `--local`, requires `~/.zk-vault/config.toml` for S3 storage.

### `zk-vault restore`

| Flag | Description |
|---|---|
| `-o, --output <DIR>` | Output directory (default: `.`) |

## Configuration

```bash
cp config.example.toml ~/.zk-vault/config.toml
```

See [docs/CLI.md](../../docs/CLI.md) for full reference (all flags, config details, file layout, E2E examples).

## File Layout

```
~/.zk-vault/
├── keystore.json          # Encrypted key pairs
├── config.toml            # Storage settings (user-created)
└── manifests/
    └── <backup-id>.json   # Backup manifests
```

## Tests

```bash
cargo test -p zk-vault-cli
```

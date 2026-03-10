# zk-vault-cli

CLI binary for zk-vault: post-quantum secure backup from the command line.

## Quick Start

```bash
cargo build -p zk-vault-cli --release     # Binary: target/release/zk-vault

zk-vault init                              # generate keys
zk-vault backup --local ./backups ./data   # encrypt + backup
zk-vault verify <backup-id>                # check integrity
zk-vault restore <backup-id> -o ./out      # decrypt + restore
zk-vault status                            # show vault info
```

## Commands

| Command | Description |
|---|---|
| `init` | Generate PQ + classical key pairs, create vault |
| `backup` | Encrypt files → local / S3 / chain |
| `restore` | Decrypt + restore from backup |
| `verify` | Verify backup integrity without decrypting |
| `status` | Show vault info, keys, storage config, backups |

## Key Flags

| Flag | Command | Description |
|---|---|---|
| `--local <DIR>` | `backup` | Save to local directory (Layer 0) |
| `--chain <URL>` | `backup` | Register on zk-vault chain RPC |
| `-o, --output <DIR>` | `restore` | Output directory |

See [docs/CLI.md](../../docs/CLI.md) for full reference (all flags, config setup, chain RPC, E2E examples).

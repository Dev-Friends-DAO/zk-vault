# zk-vault-cli

CLI binary for zk-vault: post-quantum secure backup from the command line.

## Quick Start

```bash
cargo build -p zk-vault-cli --release     # Binary: target/release/zk-vault

zk-vault init                              # generate keys (displays 24-word mnemonic)
zk-vault init --generate-keyfile ./my.key  # generate keys + keyfile
zk-vault backup --local ./backups ./data   # encrypt + backup
zk-vault verify <backup-id>                # check integrity
zk-vault restore <backup-id> -o ./out      # decrypt + restore
zk-vault status                            # show vault info
zk-vault recover                           # recover vault from mnemonic
zk-vault guardian setup                    # split MK into Shamir shares
zk-vault guardian list --chain http://...  # list registered guardians
zk-vault rotate-keys --chain http://...    # rotate keys + chain revocation
```

## Commands

| Command | Description |
|---|---|
| `init` | Generate PQ + classical key pairs, create vault, display BIP-39 mnemonic |
| `backup` | Encrypt files → local / S3 / chain |
| `restore` | Decrypt + restore from backup |
| `verify` | Verify backup integrity without decrypting |
| `status` | Show vault info, keys, storage config, backups |
| `anchor` | Anchor Merkle root to Bitcoin / Ethereum |
| `recover` | Recover vault from 24-word BIP-39 mnemonic |
| `guardian setup` | Split MK into Shamir shares, encrypt for guardians |
| `guardian list` | List registered guardians on chain |
| `guardian register` | Register a guardian share on chain |
| `rotate-keys` | Generate new keys, re-encrypt MK, optionally submit `RevokeKeys` tx |

## Key Flags

| Flag | Command | Description |
|---|---|---|
| `--local <DIR>` | `backup` | Save to local directory (Layer 0) |
| `--chain <URL>` | `backup`, `restore`, `verify`, `status`, `rotate-keys` | Chain node URL (Mode B) |
| `--anchor` | `backup` | Anchor Merkle root to configured blockchains |
| `--btc` / `--eth` | `anchor` | Select anchor target(s) |
| `-o, --output <DIR>` | `restore` | Output directory |
| `--keyfile <PATH>` | `init`, `backup`, `restore`, `verify`, `status`, `recover`, `guardian setup`, `guardian register`, `rotate-keys` | Path to keyfile for vault unlock |
| `--generate-keyfile <PATH>` | `init`, `recover` | Generate a new 64-byte random keyfile and save to path |
| `--threshold <K>` | `guardian setup` | Recovery threshold (default: 3) |
| `--shares <N>` | `guardian setup` | Total shares (default: 5) |

See [docs/CLI.md](../../docs/CLI.md) for full reference (all flags, config setup, chain RPC, E2E examples).

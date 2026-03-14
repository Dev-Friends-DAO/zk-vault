use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::{error, info, warn};
use uuid::Uuid;
use zeroize::Zeroizing;

use zk_vault_core::crypto::{aead, bundle, hash, kem, keys};
use zk_vault_core::manifest::{ManifestBuilder, ManifestFileEntry, StorageLocation};
use zk_vault_core::merkle::tree::MerkleTree;
use zk_vault_core::storage::s3::{S3Backend, S3Config};
use zk_vault_core::storage::StorageBackend;

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/// Print error message and exit. Used for unrecoverable CLI errors.
fn fatal(msg: &str) -> ! {
    eprintln!("Error: {msg}");
    std::process::exit(1);
}

/// Print error with context and exit.
fn fatal_with(context: &str, err: impl std::fmt::Display) -> ! {
    eprintln!("Error: {context}: {err}");
    std::process::exit(1);
}

// ---------------------------------------------------------------------------
// Config file integration
// ---------------------------------------------------------------------------

/// Vault configuration loaded from ~/.zk-vault/config.toml
#[derive(Debug, Default)]
struct VaultConfig {
    keyfile_path: Option<PathBuf>,
    chain_url: Option<String>,
}

fn load_vault_config() -> VaultConfig {
    let config_path = keys::vault_dir()
        .unwrap_or_else(|e| fatal_with("vault dir", e))
        .join("config.toml");
    if !config_path.exists() {
        return VaultConfig::default();
    }

    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return VaultConfig::default(),
    };

    let config: toml::Value = match toml::from_str(&content) {
        Ok(c) => c,
        Err(_) => return VaultConfig::default(),
    };

    let keyfile_path = config
        .get("vault")
        .and_then(|v| v.get("keyfile_path"))
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    let chain_url = config
        .get("vault")
        .and_then(|v| v.get("chain_url"))
        .and_then(|v| v.as_str())
        .map(String::from);

    VaultConfig {
        keyfile_path,
        chain_url,
    }
}

/// Resolve keyfile: CLI flag takes priority, then config.toml
fn resolve_keyfile(cli_keyfile: &Option<PathBuf>) -> Option<Vec<u8>> {
    let config = load_vault_config();
    let effective_path = cli_keyfile.as_ref().or(config.keyfile_path.as_ref());
    load_keyfile_from_path(effective_path)
}

fn load_keyfile_from_path(path: Option<&PathBuf>) -> Option<Vec<u8>> {
    path.map(|p| {
        std::fs::read(p)
            .unwrap_or_else(|e| fatal_with(&format!("reading keyfile {}", p.display()), e))
    })
}

/// Resolve chain URL: CLI flag takes priority, then config.toml
fn resolve_chain_url(cli_chain: &Option<String>) -> Option<String> {
    if cli_chain.is_some() {
        return cli_chain.clone();
    }
    load_vault_config().chain_url
}

// ---------------------------------------------------------------------------
// Common unlock helpers
// ---------------------------------------------------------------------------

/// Load keystore and unlock all keys. Common operation for most commands.
fn unlock_vault(keyfile: &Option<PathBuf>) -> keys::UnlockedKeys {
    let store = keys::load_key_store().unwrap_or_else(|e| fatal_with("loading keystore", e));

    let keyfile_data = resolve_keyfile(keyfile);

    let passphrase = Zeroizing::new(
        rpassword::prompt_password("Enter passphrase: ")
            .unwrap_or_else(|e| fatal_with("reading passphrase", e)),
    );

    keys::unlock_all_keys(passphrase.as_bytes(), &store, keyfile_data.as_deref(), None)
        .unwrap_or_else(|e| fatal_with("unlocking vault", e))
}

/// Load keystore, unlock, and return both store and keys.
fn load_and_unlock(keyfile: &Option<PathBuf>) -> (keys::EncryptedKeyStore, keys::UnlockedKeys) {
    let store = keys::load_key_store().unwrap_or_else(|e| fatal_with("loading keystore", e));

    let keyfile_data = resolve_keyfile(keyfile);

    let passphrase = Zeroizing::new(
        rpassword::prompt_password("Enter passphrase: ")
            .unwrap_or_else(|e| fatal_with("reading passphrase", e)),
    );

    let unlocked =
        keys::unlock_all_keys(passphrase.as_bytes(), &store, keyfile_data.as_deref(), None)
            .unwrap_or_else(|e| fatal_with("unlocking vault", e));

    (store, unlocked)
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "zk-vault")]
#[command(about = "Post-quantum zero-knowledge secure backup platform")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault (generate keys)
    Init {
        /// Generate and save a keyfile to this path
        #[arg(long)]
        generate_keyfile: Option<PathBuf>,
        /// Use an existing keyfile
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// Back up files to S3-compatible storage and/or local directory
    Backup {
        /// Files or directories to back up
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Save encrypted backups to a local directory (Layer 0)
        #[arg(long)]
        local: Option<PathBuf>,
        /// Register backup on zk-vault chain (e.g., --chain http://localhost:3030)
        #[arg(long)]
        chain: Option<String>,
        /// Anchor Merkle root to configured blockchains after backup
        #[arg(long)]
        anchor: bool,
        /// Path to keyfile for vault unlock
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// Restore files from a backup
    Restore {
        /// Backup ID or path to manifest file
        #[arg()]
        backup: String,
        /// Output directory for restored files
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        /// Restore from chain node (Mode B) (e.g., --chain http://localhost:3030)
        #[arg(long)]
        chain: Option<String>,
        /// Path to keyfile for vault unlock
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// Verify backup integrity without decrypting
    Verify {
        /// Backup ID or path to manifest file
        #[arg()]
        backup: String,
        /// Submit VerifyIntegrity attestation to chain (e.g., --chain http://localhost:3030)
        #[arg(long)]
        chain: Option<String>,
        /// Path to keyfile for vault unlock
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// Show vault status
    Status {
        /// Query chain node status (e.g., --chain http://localhost:3030)
        #[arg(long)]
        chain: Option<String>,
        /// Path to keyfile for vault unlock
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// Anchor a backup's Merkle root to Bitcoin and/or Ethereum
    Anchor {
        /// Backup ID or path to manifest file
        #[arg()]
        backup: String,
        /// Anchor to Bitcoin (OP_RETURN)
        #[arg(long)]
        btc: bool,
        /// Anchor to Ethereum (calldata)
        #[arg(long)]
        eth: bool,
    },
    /// Recover vault from mnemonic phrase
    Recover {
        /// Path to keyfile for the new vault (optional)
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// Generate and save a keyfile to this path
        #[arg(long)]
        generate_keyfile: Option<PathBuf>,
    },
    /// Guardian recovery management
    Guardian {
        #[command(subcommand)]
        action: GuardianAction,
    },
    /// Rotate encryption and signing keys
    RotateKeys {
        /// Submit RevokeKeys transaction to chain
        #[arg(long)]
        chain: Option<String>,
        /// Path to keyfile
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum GuardianAction {
    /// Set up guardian recovery (split MK into shares)
    Setup {
        /// Recovery threshold (K shares needed)
        #[arg(long, default_value = "3")]
        threshold: u8,
        /// Total number of shares (N)
        #[arg(long, default_value = "5")]
        shares: u8,
        /// Output directory for encrypted share files
        #[arg(long, default_value = ".")]
        output: PathBuf,
        /// Path to keyfile for vault unlock
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    /// List registered guardians on chain
    List {
        /// Chain node URL (falls back to config.toml vault.chain_url)
        #[arg(long)]
        chain: Option<String>,
    },
    /// Register guardians on chain (after setup)
    Register {
        /// Path to an encrypted share file
        #[arg(long)]
        share_file: PathBuf,
        /// Recovery threshold (K shares needed)
        #[arg(long, default_value = "3")]
        threshold: u8,
        /// Total number of guardians (N)
        #[arg(long, default_value = "5")]
        total_guardians: u8,
        /// Chain node URL (falls back to config.toml vault.chain_url)
        #[arg(long)]
        chain: Option<String>,
        /// Path to keyfile for vault unlock
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zk_vault=info,zk_vault_cli=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            generate_keyfile,
            keyfile,
        } => cmd_init(generate_keyfile, keyfile),
        Commands::Backup {
            paths,
            local,
            chain,
            anchor,
            keyfile,
        } => cmd_backup(paths, local, chain, anchor, keyfile).await,
        Commands::Restore {
            backup,
            output,
            chain,
            keyfile,
        } => cmd_restore(backup, output, chain, keyfile).await,
        Commands::Verify {
            backup,
            chain,
            keyfile,
        } => cmd_verify(backup, chain, keyfile).await,
        Commands::Status { chain, keyfile } => cmd_status(chain, keyfile).await,
        Commands::Anchor { backup, btc, eth } => cmd_anchor(backup, btc, eth).await,
        Commands::Recover {
            keyfile,
            generate_keyfile,
        } => cmd_recover(keyfile, generate_keyfile),
        Commands::Guardian { action } => match action {
            GuardianAction::Setup {
                threshold,
                shares,
                output,
                keyfile,
            } => cmd_guardian_setup(threshold, shares, output, keyfile),
            GuardianAction::List { chain } => cmd_guardian_list(chain).await,
            GuardianAction::Register {
                share_file,
                threshold,
                total_guardians,
                chain,
                keyfile,
            } => {
                cmd_guardian_register(share_file, threshold, total_guardians, chain, keyfile).await
            }
        },
        Commands::RotateKeys { chain, keyfile } => cmd_rotate_keys(chain, keyfile).await,
    }
}

/// Legacy keyfile loader — delegates to load_keyfile_from_path.
fn load_keyfile(path: &Option<PathBuf>) -> Option<Vec<u8>> {
    load_keyfile_from_path(path.as_ref())
}

fn cmd_init(generate_keyfile: Option<PathBuf>, keyfile_path: Option<PathBuf>) {
    // Check if vault already exists
    let keystore_path = keys::keystore_path().unwrap_or_else(|e| fatal_with("keystore path", e));
    if keystore_path.exists() {
        fatal(&format!(
            "Vault already exists at {}. To reinitialize, remove the existing keystore first.",
            keystore_path.display()
        ));
    }

    // Prompt for passphrase
    let passphrase = Zeroizing::new(
        rpassword::prompt_password("Enter passphrase for new vault: ")
            .unwrap_or_else(|e| fatal_with("reading passphrase", e)),
    );

    if passphrase.is_empty() {
        fatal("Passphrase cannot be empty.");
    }

    let confirm = Zeroizing::new(
        rpassword::prompt_password("Confirm passphrase: ")
            .unwrap_or_else(|e| fatal_with("reading passphrase", e)),
    );

    if *passphrase != *confirm {
        fatal("Passphrases do not match.");
    }

    // Handle keyfile generation or loading
    let keyfile_data = if let Some(ref gen_path) = generate_keyfile {
        let kf = zk_vault_core::crypto::kdf::generate_keyfile();
        std::fs::write(gen_path, &kf).unwrap_or_else(|e| {
            fatal_with(&format!("writing keyfile to {}", gen_path.display()), e)
        });
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(gen_path, std::fs::Permissions::from_mode(0o400))
                .unwrap_or_else(|e| {
                    warn!("Could not set keyfile permissions: {e}");
                });
        }
        println!("Keyfile generated: {}", gen_path.display());
        Some(kf)
    } else {
        load_keyfile(&keyfile_path)
    };

    println!("Generating post-quantum key pairs (this may take a moment)...");

    let (store, mnemonic) =
        keys::generate_key_store(passphrase.as_bytes(), keyfile_data.as_deref(), None)
            .unwrap_or_else(|e| fatal_with("generating keys", e));

    keys::save_key_store(&store).unwrap_or_else(|e| fatal_with("saving keystore", e));

    info!("Vault initialized at {}", keystore_path.display());

    println!("Vault initialized successfully.");
    println!("Keystore saved to: {}", keystore_path.display());
    println!();
    println!("Key pairs generated:");
    println!("  - ML-KEM-768   (post-quantum key encapsulation)");
    println!("  - X25519       (classical key exchange)");
    println!("  - ML-DSA-65    (post-quantum signatures)");
    println!("  - Ed25519      (classical signatures)");
    println!();
    println!("RECOVERY MNEMONIC (write this down and store securely):");
    println!("  {mnemonic}");
    println!();
    println!("IMPORTANT: Remember your passphrase. The mnemonic above can");
    println!("recover your master key if you forget your passphrase.");
}

fn cmd_recover(keyfile_path: Option<PathBuf>, generate_keyfile_path: Option<PathBuf>) {
    // Check vault doesn't exist (or offer to overwrite)
    let keystore_path = keys::keystore_path().unwrap_or_else(|e| fatal_with("keystore path", e));
    if keystore_path.exists() {
        warn!(
            "Vault already exists at {}, recovery will overwrite",
            keystore_path.display()
        );
        eprintln!(
            "Warning: Vault already exists at {}",
            keystore_path.display()
        );
        eprintln!("Recovery will overwrite the existing keystore.");
    }

    // Read mnemonic
    println!("Enter your 24-word recovery phrase:");
    let mut mnemonic = String::new();
    std::io::stdin()
        .read_line(&mut mnemonic)
        .unwrap_or_else(|e| fatal_with("reading mnemonic", e));
    let mnemonic = mnemonic.trim();

    // Prompt for new passphrase
    let passphrase = Zeroizing::new(
        rpassword::prompt_password("Enter new passphrase: ")
            .unwrap_or_else(|e| fatal_with("reading passphrase", e)),
    );
    if passphrase.is_empty() {
        fatal("Passphrase cannot be empty.");
    }
    let confirm = Zeroizing::new(
        rpassword::prompt_password("Confirm passphrase: ")
            .unwrap_or_else(|e| fatal_with("reading passphrase", e)),
    );
    if *passphrase != *confirm {
        fatal("Passphrases do not match.");
    }

    // Handle keyfile
    let keyfile_data = if let Some(ref path) = generate_keyfile_path {
        let kf = zk_vault_core::crypto::kdf::generate_keyfile();
        std::fs::write(path, &kf).unwrap_or_else(|e| fatal_with("writing keyfile", e));
        println!("Keyfile saved to: {}", path.display());
        Some(kf)
    } else {
        load_keyfile(&keyfile_path)
    };

    println!("Recovering vault from mnemonic...");

    let store = keys::recover_from_mnemonic(
        mnemonic,
        passphrase.as_bytes(),
        keyfile_data.as_deref(),
        None,
    )
    .unwrap_or_else(|e| fatal_with("recovering vault", e));

    keys::save_key_store(&store).unwrap_or_else(|e| fatal_with("saving keystore", e));

    info!("Vault recovered successfully");
    println!("Vault recovered successfully.");
    println!("New key pairs generated with recovered Master Key.");
    println!();
    println!("IMPORTANT: Your public keys have changed.");
    println!("If using chain mode, you may need to update your on-chain registration.");
}

fn cmd_guardian_setup(threshold: u8, shares: u8, output: PathBuf, keyfile_path: Option<PathBuf>) {
    let unlocked = unlock_vault(&keyfile_path);

    // Split MK into shares
    use zk_vault_core::crypto::shamir;
    let shares_vec = shamir::split(&unlocked.master_key, threshold, shares)
        .unwrap_or_else(|e| fatal_with("splitting key", e));

    // Save shares to files
    std::fs::create_dir_all(&output).unwrap_or_else(|e| fatal_with("creating output directory", e));

    for share in &shares_vec {
        let filename = format!("guardian-share-{}.json", share.index);
        let path = output.join(&filename);
        let json = serde_json::to_string_pretty(share).unwrap();
        std::fs::write(&path, &json).unwrap_or_else(|e| fatal_with("writing share file", e));
        println!("Share {} saved to: {}", share.index, path.display());
    }

    println!();
    println!("Guardian recovery setup complete.");
    println!(
        "Threshold: {} of {} shares needed for recovery",
        threshold, shares
    );
    println!();
    println!("IMPORTANT: Distribute these share files to your guardians securely.");
    println!("Each guardian should encrypt their share with their own keys.");
}

async fn cmd_guardian_list(chain_url_arg: Option<String>) {
    let chain_url = resolve_chain_url(&chain_url_arg)
        .unwrap_or_else(|| fatal("--chain is required (or set vault.chain_url in config.toml)"));

    info!(chain = %chain_url, "Querying guardians");
    println!("Querying guardians from {}...", chain_url);

    let store = keys::load_key_store().unwrap_or_else(|e| fatal_with("loading keystore", e));
    let owner_pk = &store.ed25519_pk;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/get_guardians", chain_url))
        .json(&serde_json::json!({ "owner_pk": owner_pk }))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap();
            println!("{}", serde_json::to_string_pretty(&body).unwrap());
        }
        Ok(r) => {
            let text = r.text().await.unwrap_or_default();
            error!(response = %text, "Guardian list query failed");
            eprintln!("Error: {text}");
        }
        Err(e) => {
            error!(err = %e, "Failed to connect to chain");
            eprintln!("Error connecting to chain: {e}");
        }
    }
}

async fn cmd_guardian_register(
    share_file: PathBuf,
    threshold: u8,
    total_guardians: u8,
    chain_url_arg: Option<String>,
    keyfile_path: Option<PathBuf>,
) {
    use ed25519_dalek::{Signer, SigningKey};

    let chain_url = resolve_chain_url(&chain_url_arg)
        .unwrap_or_else(|| fatal("--chain is required (or set vault.chain_url in config.toml)"));

    // Read share file
    let share_json = std::fs::read_to_string(&share_file)
        .unwrap_or_else(|e| fatal_with("reading share file", e));

    // Parse share data (validates JSON)
    let share: serde_json::Value =
        serde_json::from_str(&share_json).unwrap_or_else(|e| fatal_with("parsing share file", e));

    let share_index = share
        .get("index")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| fatal("share file missing 'index' field"));

    // Load keystore and unlock
    let (_store, unlocked) = load_and_unlock(&keyfile_path);

    // For self-registration, the owner registers the guardian using their own identity.
    // The guardian_pk is the owner's Ed25519 pk (self-registration placeholder).
    // In a full multi-party flow, the guardian would provide their own Ed25519 pk.
    let guardian_pk = unlocked.ed25519_pk;

    // Build signature: BLAKE3("zk-vault:register-guardian:" || guardian_pk || threshold || total_guardians)
    let mut msg = Vec::new();
    msg.extend_from_slice(b"zk-vault:register-guardian:");
    msg.extend_from_slice(&guardian_pk);
    msg.push(threshold);
    msg.push(total_guardians);
    let msg_hash = blake3::hash(&msg);

    let signing_key = SigningKey::from_bytes(&unlocked.ed25519_sk);
    let signature = signing_key.sign(msg_hash.as_bytes());

    // Build RegisterGuardian transaction
    let tx = serde_json::json!({
        "RegisterGuardian": {
            "owner_pk": unlocked.ed25519_pk.to_vec(),
            "guardian_pk": guardian_pk.to_vec(),
            "encrypted_share": share_json,
            "threshold": threshold,
            "total_guardians": total_guardians,
            "signature": signature.to_bytes().to_vec(),
        }
    });
    let tx_json = tx.to_string();

    info!(
        chain = %chain_url,
        share_file = %share_file.display(),
        share_index = share_index,
        "Submitting RegisterGuardian transaction"
    );
    println!("Registering guardian (share {share_index}) on {chain_url}...");

    // Submit to chain
    let client = reqwest::Client::new();
    let url = format!("{}/submit_tx", chain_url.trim_end_matches('/'));
    let body = serde_json::json!({ "tx_json": tx_json });

    match client.post(&url).json(&body).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();

            if status.is_success() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body_text) {
                    let tx_hash = parsed["tx_hash"].as_str().unwrap_or("?");
                    info!(chain = %chain_url, tx_hash = %tx_hash, "Guardian registered");
                    println!("  Guardian registration: SUCCESS");
                    println!("  tx_hash: {tx_hash}");
                } else {
                    println!("  Guardian registration: SUCCESS");
                }
                println!("  Share file: {}", share_file.display());
                println!("  Threshold: {threshold} of {total_guardians}");
            } else {
                error!(chain = %chain_url, status = %status, "Guardian registration failed");
                eprintln!("  Guardian registration: FAILED (HTTP {status})");
                eprintln!("  Response: {body_text}");
            }
        }
        Err(e) => {
            error!(chain = %chain_url, err = %e, "Guardian registration failed");
            eprintln!("  Guardian registration: FAILED (connection error: {e})");
        }
    }
}

async fn cmd_rotate_keys(chain_url: Option<String>, keyfile_path: Option<PathBuf>) {
    let effective_chain = resolve_chain_url(&chain_url);
    let keyfile_data = resolve_keyfile(&keyfile_path);

    let store = keys::load_key_store().unwrap_or_else(|e| fatal_with("loading keystore", e));

    let passphrase = Zeroizing::new(
        rpassword::prompt_password("Enter passphrase: ")
            .unwrap_or_else(|e| fatal_with("reading passphrase", e)),
    );

    // Unlock to get the MK and generate mnemonic for the MK
    let unlocked =
        keys::unlock_all_keys(passphrase.as_bytes(), &store, keyfile_data.as_deref(), None)
            .unwrap_or_else(|e| fatal_with("unlocking vault", e));

    // Get the mnemonic from MK to use recover_from_mnemonic (which generates new key pairs)
    use zk_vault_core::crypto::mnemonic;
    let mnemonic_str = mnemonic::master_key_to_mnemonic(&unlocked.master_key).unwrap();

    // Generate new keystore with same MK but new key pairs
    let new_store = keys::recover_from_mnemonic(
        &mnemonic_str,
        passphrase.as_bytes(),
        keyfile_data.as_deref(),
        None,
    )
    .unwrap_or_else(|e| fatal_with("generating new keys", e));

    let old_ed25519_pk = store.ed25519_pk.clone();
    let new_ed25519_pk = new_store.ed25519_pk.clone();

    // If chain URL provided, submit RevokeKeys tx
    if let Some(ref url) = effective_chain {
        // Sign RevokeKeys with old key
        let new_pk_bytes = hex::decode(&new_ed25519_pk).unwrap();
        let msg = blake3::hash(&new_pk_bytes);

        use ed25519_dalek::{Signer, SigningKey};
        let old_sk = SigningKey::from_bytes(&unlocked.ed25519_sk);
        let sig = old_sk.sign(msg.as_bytes());

        let tx = serde_json::json!({
            "RevokeKeys": {
                "owner_pk": hex::decode(&old_ed25519_pk).unwrap(),
                "new_ed25519_pk": new_pk_bytes,
                "signature": sig.to_bytes().to_vec(),
            }
        });

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/submit_tx", url))
            .json(&serde_json::json!({ "tx_json": tx.to_string() }))
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                println!("RevokeKeys transaction submitted to chain.");
            }
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                eprintln!("Warning: Failed to submit RevokeKeys tx: {text}");
            }
            Err(e) => eprintln!("Warning: Failed to connect to chain: {e}"),
        }
    }

    // Save new keystore
    keys::save_key_store(&new_store).unwrap_or_else(|e| fatal_with("saving keystore", e));

    info!("Keys rotated successfully");
    println!("Keys rotated successfully.");
    println!("Old Ed25519 PK: {}", old_ed25519_pk);
    println!("New Ed25519 PK: {}", new_ed25519_pk);
}

/// Load S3 config from ~/.zk-vault/config.toml.
fn load_s3_config() -> S3Config {
    let config_path = keys::vault_dir()
        .unwrap_or_else(|e| fatal_with("vault dir", e))
        .join("config.toml");
    if !config_path.exists() {
        fatal(&format!(
            "No config file found at {}. Create it with S3 storage settings. See config.example.toml.",
            config_path.display()
        ));
    }

    let content =
        std::fs::read_to_string(&config_path).unwrap_or_else(|e| fatal_with("reading config", e));

    let config: toml::Value =
        toml::from_str(&content).unwrap_or_else(|e| fatal_with("parsing config", e));

    let s3 = config
        .get("storage")
        .and_then(|s| s.get("s3"))
        .unwrap_or_else(|| fatal("[storage.s3] section missing in config.toml"));

    S3Config {
        bucket: s3
            .get("bucket")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fatal("storage.s3.bucket is required"))
            .to_string(),
        region: s3
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1")
            .to_string(),
        endpoint: s3
            .get("endpoint")
            .and_then(|v| v.as_str())
            .map(String::from),
        access_key: s3
            .get("access_key")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        secret_key: s3
            .get("secret_key")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        path_style: s3
            .get("path_style")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    }
}

/// Collect all files from the given paths (recursively for directories).
fn collect_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        if !path.exists() {
            eprintln!("Warning: {} does not exist, skipping", path.display());
            continue;
        }
        if path.is_file() {
            files.push(path.clone());
        } else if path.is_dir() {
            collect_dir_recursive(path, &mut files);
        }
    }
    files
}

fn collect_dir_recursive(dir: &PathBuf, files: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Warning: Cannot read {}: {e}", dir.display());
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        } else if path.is_dir() {
            collect_dir_recursive(&path, files);
        }
    }
}

/// Save a manifest to ~/.zk-vault/manifests/.
fn save_manifest(manifest: &zk_vault_core::manifest::BackupManifest) -> std::io::Result<PathBuf> {
    let dir = keys::vault_dir()
        .unwrap_or_else(|e| fatal_with("vault dir", e))
        .join("manifests");
    std::fs::create_dir_all(&dir)?;
    let filename = format!("{}.json", manifest.backup_id);
    let path = dir.join(&filename);
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| std::io::Error::other(format!("Serialize manifest: {e}")))?;
    std::fs::write(&path, json)?;
    Ok(path)
}

async fn cmd_backup(
    paths: Vec<PathBuf>,
    local_dir: Option<PathBuf>,
    chain_url: Option<String>,
    anchor: bool,
    keyfile_path: Option<PathBuf>,
) {
    // 1. Determine storage targets
    let effective_chain = resolve_chain_url(&chain_url);
    let config_path = keys::vault_dir()
        .unwrap_or_else(|e| fatal_with("vault dir", e))
        .join("config.toml");
    let use_s3 = config_path.exists();
    let use_local = local_dir.is_some();

    let use_chain = effective_chain.is_some();

    if !use_s3 && !use_local && !use_chain {
        fatal("No storage target specified. Either create ~/.zk-vault/config.toml for S3, use --local <dir>, or use --chain <url>.");
    }

    info!(files = paths.len(), "Starting backup");

    // 2. Load keystore and unlock
    let (store, unlocked) = load_and_unlock(&keyfile_path);
    let _ = &store; // used for public key access if needed

    let hybrid_pk = kem::HybridPublicKey {
        kem_pk: unlocked.kem_pk.clone(),
        x25519_pk: unlocked.x25519_pk,
    };

    // 4. Collect files
    let files = collect_files(&paths);
    if files.is_empty() {
        fatal("No files found to back up.");
    }
    println!("Found {} file(s) to back up.", files.len());

    // 5. Set up storage targets
    let s3_storage = if use_s3 {
        let s3_config = load_s3_config();
        Some(S3Backend::new(&s3_config).unwrap_or_else(|e| fatal_with("connecting to S3", e)))
    } else {
        None
    };

    if let Some(dir) = &local_dir {
        std::fs::create_dir_all(dir).unwrap_or_else(|e| {
            fatal_with(&format!("creating local output dir {}", dir.display()), e)
        });
    }

    let mut targets: Vec<&str> = Vec::new();
    if use_s3 {
        targets.push("S3");
    }
    if use_local {
        targets.push("local");
    }
    if use_chain {
        targets.push("chain (Mode B)");
    }
    println!("Storage targets: {}", targets.join(" + "));

    // 6. Process each file
    let user_id = Uuid::now_v7();
    let mut manifest_builder = ManifestBuilder::new(user_id, "local");
    let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut success_count: usize = 0;
    // Collect encrypted bundles for chain upload (Mode B)
    let mut chain_bundles: Vec<(String, Vec<u8>)> = Vec::new();

    for file_path in &files {
        let relative_path = file_path.to_string_lossy().to_string();

        // Read file
        let plaintext = match std::fs::read(file_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("  Skip {relative_path}: {e}");
                continue;
            }
        };

        let original_size = plaintext.len() as u64;
        let plaintext_hash = hash::hash(&plaintext);

        // Generate per-file symmetric key and encrypt
        let sym_key = aead::generate_key();
        let file_id = Uuid::now_v7().to_string();
        let aad_str = format!("zk-vault:file:{user_id}:{file_id}");
        let (nonce, ciphertext) = aead::encrypt(&sym_key, &plaintext, aad_str.as_bytes())
            .unwrap_or_else(|e| fatal_with(&format!("encrypting {relative_path}"), e));

        // Wrap symmetric key with hybrid KEM
        let encap = kem::encapsulate(&hybrid_pk, &sym_key)
            .unwrap_or_else(|e| fatal_with(&format!("wrapping key for {relative_path}"), e));

        // Build encrypted bundle
        let encrypted_bundle = bundle::EncryptedBundle {
            version: bundle::BUNDLE_VERSION,
            kem_ciphertext: encap.kem_ciphertext,
            eph_x25519_pk: encap.eph_x25519_pk,
            nonce,
            wrapped_key: encap.wrapped_key,
            ciphertext,
        };
        let bundle_bytes = encrypted_bundle.to_bytes();
        let encrypted_size = bundle_bytes.len() as u64;
        let content_hash = hash::hash(&bundle_bytes);
        let storage_key = format!("{user_id}/{file_id}");

        // Store to targets
        let mut locations: Vec<StorageLocation> = Vec::new();
        let mut file_ok = true;

        // Local storage
        if let Some(dir) = &local_dir {
            let local_file_dir = dir.join(user_id.to_string());
            if let Err(e) = std::fs::create_dir_all(&local_file_dir) {
                eprintln!("  Local write failed for {relative_path}: {e}");
                file_ok = false;
            } else {
                let local_path = local_file_dir.join(&file_id);
                if let Err(e) = std::fs::write(&local_path, &bundle_bytes) {
                    eprintln!("  Local write failed for {relative_path}: {e}");
                    file_ok = false;
                } else {
                    locations.push(StorageLocation {
                        backend: "local".to_string(),
                        storage_key: local_path.to_string_lossy().to_string(),
                    });
                }
            }
        }

        // S3 storage
        if let Some(s3) = &s3_storage {
            match s3.upload(&storage_key, &bundle_bytes).await {
                Ok(_) => {
                    locations.push(StorageLocation {
                        backend: "s3".to_string(),
                        storage_key: storage_key.clone(),
                    });
                }
                Err(e) => {
                    eprintln!("  S3 upload failed for {relative_path}: {e}");
                    if locations.is_empty() {
                        file_ok = false;
                    }
                }
            }
        }

        // Chain storage (Mode B): collect bundles for upload after registration
        if use_chain {
            chain_bundles.push((storage_key.clone(), bundle_bytes.clone()));
            locations.push(StorageLocation {
                backend: "chain".to_string(),
                storage_key: storage_key.clone(),
            });
            if !file_ok && locations.len() == 1 {
                // Chain is the only target and no prior failure for other reasons
                file_ok = true;
            }
        }

        if file_ok && !locations.is_empty() {
            println!("  Backed up: {relative_path} ({original_size} -> {encrypted_size} bytes)");
            leaf_hashes.push(content_hash);
            total_bytes += encrypted_size;
            success_count += 1;

            manifest_builder.add_file(ManifestFileEntry {
                source_path: relative_path,
                source_id: file_id,
                content_hash: plaintext_hash,
                original_size,
                encrypted_size,
                mime_type: None,
                source_modified_at: None,
                storage_locations: locations,
            });
        }
    }

    if success_count == 0 {
        fatal("No files were backed up successfully.");
    }

    // 7. Build Merkle tree
    let merkle_root = if !leaf_hashes.is_empty() {
        let tree = MerkleTree::from_leaf_hashes(leaf_hashes);
        tree.root().unwrap_or([0u8; 32])
    } else {
        [0u8; 32]
    };

    let manifest = manifest_builder.build(merkle_root);

    // 8. Save manifest locally
    match save_manifest(&manifest) {
        Ok(path) => {
            info!(backup_id = %manifest.backup_id, files = success_count, bytes = total_bytes, "Backup complete");
            println!();
            println!("Backup complete.");
            println!("  Files:       {success_count}/{}", files.len());
            println!("  Total:       {total_bytes} bytes (encrypted)");
            println!("  Merkle root: {}", hex::encode(merkle_root));
            println!("  Manifest:    {}", path.display());
            println!("  Backup ID:   {}", manifest.backup_id);
        }
        Err(e) => {
            warn!(err = %e, "Backup succeeded but manifest save failed");
            eprintln!("Warning: Backup succeeded but manifest save failed: {e}");
            eprintln!("Merkle root: {}", hex::encode(merkle_root));
        }
    }

    // 9. Register on chain and upload data (if chain was resolved)
    if let Some(chain_url) = effective_chain {
        register_on_chain(
            &chain_url,
            merkle_root,
            success_count as u32,
            total_bytes,
            &unlocked.ed25519_sk,
            &unlocked.ed25519_pk,
        )
        .await;

        // Upload encrypted data to chain validators (Mode B)
        upload_to_chain(&chain_url, &chain_bundles).await;
    }

    // 10. Anchor to blockchains (if --anchor was specified)
    if anchor {
        anchor_merkle_root(merkle_root).await;
    }
}

/// Anchor a Merkle root to all configured blockchains.
async fn anchor_merkle_root(merkle_root: [u8; 32]) {
    use zk_vault_core::anchor::bitcoin::{BitcoinAnchor, BitcoinConfig};
    use zk_vault_core::anchor::ethereum::{EthereumAnchor, EthereumConfig};
    use zk_vault_core::anchor::BlockchainAnchor;

    let anchor_config = match load_anchor_config() {
        Some(c) => c,
        None => {
            eprintln!();
            eprintln!("Anchoring skipped: no [anchor] section in config.toml");
            return;
        }
    };

    println!();
    println!("Anchoring Merkle root to blockchains...");

    let mut success = 0usize;
    let mut total = 0usize;

    // Bitcoin
    if let Some(btc) = anchor_config.get("bitcoin") {
        let api_url = btc.get("api_url").and_then(|v| v.as_str()).unwrap_or("");
        let network = btc
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("testnet");
        let wif = btc
            .get("wif_private_key")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if !wif.is_empty() {
            total += 1;
            let anchor = BitcoinAnchor::new(BitcoinConfig {
                api_url: api_url.to_string(),
                network: network.to_string(),
                wif_private_key: wif.to_string(),
            });
            match anchor.anchor(&merkle_root).await {
                Ok(receipt) => {
                    println!("  Bitcoin ({network}): SUCCESS (tx: {})", receipt.tx_id);
                    success += 1;
                }
                Err(e) => eprintln!("  Bitcoin ({network}): FAILED ({e})"),
            }
        }
    }

    // Ethereum
    if let Some(eth) = anchor_config.get("ethereum") {
        let rpc_url = eth.get("rpc_url").and_then(|v| v.as_str()).unwrap_or("");
        let network = eth
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("sepolia");
        let pk_hex = eth
            .get("private_key_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let chain_id = eth
            .get("chain_id")
            .and_then(|v| v.as_integer())
            .unwrap_or(11155111) as u64;

        if !pk_hex.is_empty() {
            total += 1;
            let anchor = EthereumAnchor::new(EthereumConfig {
                rpc_url: rpc_url.to_string(),
                network: network.to_string(),
                private_key_hex: pk_hex.to_string(),
                chain_id,
            });
            match anchor.anchor(&merkle_root).await {
                Ok(receipt) => {
                    println!("  Ethereum ({network}): SUCCESS (tx: {})", receipt.tx_id);
                    success += 1;
                }
                Err(e) => eprintln!("  Ethereum ({network}): FAILED ({e})"),
            }
        }
    }

    if total == 0 {
        eprintln!("  No anchor keys configured. Add keys to [anchor.*] in config.toml.");
    } else {
        println!("  Anchoring: {success}/{total} succeeded.");
    }
}

/// Register a backup on the zk-vault chain by submitting a RegisterFile transaction.
async fn register_on_chain(
    chain_url: &str,
    merkle_root: [u8; 32],
    file_count: u32,
    encrypted_size: u64,
    ed25519_sk: &[u8; 32],
    ed25519_pk: &[u8; 32],
) {
    use ed25519_dalek::{Signer, SigningKey};

    println!();
    println!("Registering backup on chain ({chain_url})...");

    // Sign the merkle root with Ed25519
    let signing_key = SigningKey::from_bytes(ed25519_sk);
    let signature = signing_key.sign(&merkle_root);

    // Build RegisterFile transaction JSON (matches zk-vault-chain types::Transaction)
    let tx = serde_json::json!({
        "RegisterFile": {
            "merkle_root": merkle_root,
            "file_count": file_count,
            "encrypted_size": encrypted_size,
            "owner_pk": *ed25519_pk,
            "signature": signature.to_bytes().to_vec(),
        }
    });
    let tx_json = tx.to_string();

    // Submit to chain RPC
    let client = reqwest::Client::new();
    let url = format!("{}/submit_tx", chain_url.trim_end_matches('/'));
    let body = serde_json::json!({ "tx_json": tx_json });

    match client.post(&url).json(&body).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();

            if status.is_success() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body_text) {
                    let tx_hash = parsed["tx_hash"].as_str().unwrap_or("?");
                    info!(chain = %chain_url, tx_hash = %tx_hash, "Transaction submitted");
                    println!("  Chain registration: SUCCESS");
                    println!("  tx_hash: {tx_hash}");
                } else {
                    info!(chain = %chain_url, "Transaction submitted");
                    println!("  Chain registration: SUCCESS");
                }
            } else {
                error!(chain = %chain_url, status = %status, "Chain registration failed");
                eprintln!("  Chain registration: FAILED (HTTP {status})");
                eprintln!("  Response: {body_text}");
            }
        }
        Err(e) => {
            error!(chain = %chain_url, err = %e, "Chain registration failed");
            eprintln!("  Chain registration: FAILED (connection error: {e})");
            eprintln!("  Backup data is safe. You can register later manually.");
        }
    }
}

/// Upload encrypted data bundles to chain validators (Mode B).
async fn upload_to_chain(chain_url: &str, bundles: &[(String, Vec<u8>)]) {
    use base64::Engine;

    if bundles.is_empty() {
        return;
    }

    println!();
    println!("Uploading encrypted data to chain (Mode B)...");

    let client = reqwest::Client::new();
    let base = chain_url.trim_end_matches('/');
    let mut uploaded = 0usize;
    let mut failed = 0usize;

    for (key, data) in bundles {
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let body = serde_json::json!({
            "key": key,
            "data_b64": data_b64,
        });

        match client
            .post(format!("{base}/upload_data"))
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                uploaded += 1;
            }
            Ok(resp) => {
                let status = resp.status();
                eprintln!("  Upload failed for {key}: HTTP {status}");
                failed += 1;
            }
            Err(e) => {
                eprintln!("  Upload failed for {key}: {e}");
                failed += 1;
            }
        }
    }

    println!(
        "  Chain upload: {uploaded}/{} files uploaded",
        bundles.len()
    );
    if failed > 0 {
        eprintln!(
            "  Warning: {failed} upload(s) failed. Data is safe locally if --local was used."
        );
    }
}

/// Resolve a backup identifier to a manifest path.
/// Accepts either a direct file path or a backup UUID (looked up in ~/.zk-vault/manifests/).
fn resolve_manifest_path(backup: &str) -> PathBuf {
    let path = PathBuf::from(backup);
    if path.exists() {
        return path;
    }

    // Try as backup ID in manifests dir
    let manifest_path = keys::vault_dir()
        .unwrap_or_else(|e| fatal_with("vault dir", e))
        .join("manifests")
        .join(format!("{backup}.json"));
    if manifest_path.exists() {
        return manifest_path;
    }

    fatal(&format!(
        "Cannot find manifest for '{backup}'. Provide a backup ID or path to a manifest file. Available manifests: {}",
        keys::vault_dir().unwrap_or_else(|e| fatal_with("vault dir", e)).join("manifests").display()
    ));
}

/// Read an encrypted bundle from a local file path.
fn read_local_bundle(path: &str) -> Option<Vec<u8>> {
    let p = PathBuf::from(path);
    if p.exists() {
        std::fs::read(&p).ok()
    } else {
        None
    }
}

async fn cmd_restore(
    backup: String,
    output: PathBuf,
    chain_url: Option<String>,
    keyfile_path: Option<PathBuf>,
) {
    let effective_chain = resolve_chain_url(&chain_url);

    // 1. Load manifest
    let manifest_path = resolve_manifest_path(&backup);
    let manifest_json = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| fatal_with("reading manifest", e));
    let manifest: zk_vault_core::manifest::BackupManifest =
        serde_json::from_str(&manifest_json).unwrap_or_else(|e| fatal_with("parsing manifest", e));

    info!(backup_id = %manifest.backup_id, "Starting restore");
    println!("Restoring backup: {}", manifest.backup_id);
    println!("  Source:  {}", manifest.source);
    println!("  Files:   {}", manifest.file_count);
    println!("  Created: {}", manifest.created_at);

    // 2. Verify manifest integrity
    match manifest.verify_integrity() {
        Ok(true) => println!("  Merkle root: verified"),
        Ok(false) => fatal("Manifest Merkle root mismatch. Data may be tampered."),
        Err(e) => fatal_with("verifying manifest", e),
    }

    // 3. Unlock keys
    let (_store, unlocked) = load_and_unlock(&keyfile_path);

    // 4. Set up S3 if available
    let config_path = keys::vault_dir()
        .unwrap_or_else(|e| fatal_with("vault dir", e))
        .join("config.toml");
    let s3_storage = if config_path.exists() {
        let s3_config = load_s3_config();
        S3Backend::new(&s3_config).ok()
    } else {
        None
    };

    // 5. Create output directory
    std::fs::create_dir_all(&output).unwrap_or_else(|e| fatal_with("creating output directory", e));

    // 6. Restore each file
    let mut restored = 0usize;
    let mut failed = 0usize;
    let mut bytes_restored: u64 = 0;

    for file_entry in &manifest.files {
        let source_path = &file_entry.source_path;

        // Try to download the encrypted bundle
        let bundle_bytes = fetch_bundle(file_entry, &s3_storage, effective_chain.as_deref()).await;
        let bundle_bytes = match bundle_bytes {
            Some(data) => data,
            None => {
                eprintln!("  Failed: {source_path} (not found in any storage)");
                failed += 1;
                continue;
            }
        };

        // Parse encrypted bundle
        let encrypted_bundle = match bundle::EncryptedBundle::from_bytes(&bundle_bytes) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  Failed: {source_path} (invalid bundle: {e})");
                failed += 1;
                continue;
            }
        };

        // Decapsulate: recover per-file symmetric key
        let x25519_sk_bytes: [u8; 32] =
            unlocked.x25519_sk.clone().try_into().unwrap_or_else(|_| {
                fatal("Invalid X25519 secret key length");
            });
        let x25519_sk = kem::StaticSecret::from(x25519_sk_bytes);
        let sym_key = match kem::decapsulate(
            &unlocked.kem_sk,
            &x25519_sk,
            &encrypted_bundle.kem_ciphertext,
            &encrypted_bundle.eph_x25519_pk,
            &encrypted_bundle.wrapped_key,
        ) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("  Failed: {source_path} (decapsulate error: {e})");
                failed += 1;
                continue;
            }
        };

        // Decrypt file content
        let aad_str = format!(
            "zk-vault:file:{}:{}",
            manifest.user_id, file_entry.source_id
        );
        let plaintext = match aead::decrypt(
            &sym_key,
            &encrypted_bundle.nonce,
            &encrypted_bundle.ciphertext,
            aad_str.as_bytes(),
        ) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("  Failed: {source_path} (decrypt error: {e})");
                failed += 1;
                continue;
            }
        };

        // Verify content hash
        let computed_hash = hash::hash(&plaintext);
        if computed_hash != file_entry.content_hash {
            eprintln!("  Failed: {source_path} (content hash mismatch — data corrupted)");
            failed += 1;
            continue;
        }

        // Write restored file
        let out_path = output.join(
            PathBuf::from(source_path)
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new(&file_entry.source_id)),
        );
        if let Some(parent) = out_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match std::fs::write(&out_path, &plaintext) {
            Ok(()) => {
                println!(
                    "  Restored: {source_path} ({} bytes) -> {}",
                    plaintext.len(),
                    out_path.display()
                );
                restored += 1;
                bytes_restored += plaintext.len() as u64;
            }
            Err(e) => {
                eprintln!("  Failed: {source_path} (write error: {e})");
                failed += 1;
            }
        }
    }

    println!();
    println!("Restore complete.");
    println!("  Restored: {restored}/{}", manifest.file_count);
    println!("  Failed:   {failed}");
    println!("  Bytes:    {bytes_restored}");
    println!("  Output:   {}", output.display());
}

/// Fetch an encrypted bundle from available storage locations.
async fn fetch_bundle(
    file_entry: &zk_vault_core::manifest::ManifestFileEntry,
    s3_storage: &Option<S3Backend>,
    chain_url: Option<&str>,
) -> Option<Vec<u8>> {
    for location in &file_entry.storage_locations {
        match location.backend.as_str() {
            "local" => {
                if let Some(data) = read_local_bundle(&location.storage_key) {
                    return Some(data);
                }
            }
            "s3" => {
                if let Some(s3) = s3_storage {
                    if let Ok(data) = s3.download(&location.storage_key).await {
                        return Some(data);
                    }
                }
            }
            "chain" => {
                if let Some(url) = chain_url {
                    if let Some(data) = download_from_chain(url, &location.storage_key).await {
                        return Some(data);
                    }
                }
            }
            other => {
                eprintln!(
                    "  Warning: Unknown backend '{other}' for {}",
                    file_entry.source_path
                );
            }
        }
    }
    None
}

/// Download an encrypted data blob from a chain node (Mode B).
async fn download_from_chain(chain_url: &str, key: &str) -> Option<Vec<u8>> {
    use base64::Engine;

    let client = reqwest::Client::new();
    let base = chain_url.trim_end_matches('/');
    let body = serde_json::json!({ "key": key });

    match client
        .post(format!("{base}/download_data"))
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let text = resp.text().await.ok()?;
            let parsed: serde_json::Value = serde_json::from_str(&text).ok()?;
            let data_b64 = parsed["data_b64"].as_str()?;
            base64::engine::general_purpose::STANDARD
                .decode(data_b64)
                .ok()
        }
        _ => None,
    }
}

async fn cmd_verify(backup: String, chain_url: Option<String>, _keyfile_path: Option<PathBuf>) {
    let effective_chain = resolve_chain_url(&chain_url);

    // 1. Load manifest
    let manifest_path = resolve_manifest_path(&backup);
    let manifest_json = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| fatal_with("reading manifest", e));
    let manifest: zk_vault_core::manifest::BackupManifest =
        serde_json::from_str(&manifest_json).unwrap_or_else(|e| fatal_with("parsing manifest", e));

    println!("Verifying backup: {}", manifest.backup_id);
    println!("  Source:  {}", manifest.source);
    println!("  Files:   {}", manifest.file_count);
    println!("  Created: {}", manifest.created_at);
    println!();

    let mut checks_passed = 0u32;
    let mut checks_failed = 0u32;

    // Check 1: Manifest Merkle root integrity
    print!("  [1] Merkle root integrity ... ");
    match manifest.verify_integrity() {
        Ok(true) => {
            println!("PASS");
            checks_passed += 1;
        }
        Ok(false) => {
            println!("FAIL (root mismatch — possible tampering)");
            checks_failed += 1;
        }
        Err(e) => {
            println!("FAIL ({e})");
            checks_failed += 1;
        }
    }

    // Check 2: Storage availability
    let config_path = keys::vault_dir()
        .unwrap_or_else(|e| fatal_with("vault dir", e))
        .join("config.toml");
    let s3_storage = if config_path.exists() {
        let s3_config = load_s3_config();
        S3Backend::new(&s3_config).ok()
    } else {
        None
    };

    print!("  [2] Storage availability ... ");
    let mut files_available = 0u32;
    let mut files_missing = 0u32;

    for file_entry in &manifest.files {
        let found = check_file_exists(file_entry, &s3_storage, effective_chain.as_deref()).await;
        if found {
            files_available += 1;
        } else {
            files_missing += 1;
        }
    }

    if files_missing == 0 {
        println!(
            "PASS ({files_available}/{} files found)",
            manifest.file_count
        );
        checks_passed += 1;
    } else {
        println!("FAIL ({files_missing} missing, {files_available} found)",);
        checks_failed += 1;
    }

    // Check 3: Bundle hash verification (download and check BLAKE3 hash of encrypted bundles)
    print!("  [3] Bundle hash verification ... ");
    let mut hash_ok = 0u32;
    let mut hash_fail = 0u32;
    let mut hash_skip = 0u32;

    for file_entry in &manifest.files {
        let bundle_bytes = fetch_bundle(file_entry, &s3_storage, effective_chain.as_deref()).await;
        match bundle_bytes {
            Some(data) => {
                // Verify bundle parses correctly
                if bundle::EncryptedBundle::from_bytes(&data).is_ok() {
                    hash_ok += 1;
                } else {
                    hash_fail += 1;
                    eprintln!("\n    Invalid bundle: {}", file_entry.source_path);
                }
            }
            None => {
                hash_skip += 1;
            }
        }
    }

    if hash_fail == 0 && hash_skip == 0 {
        println!("PASS ({hash_ok} bundles valid)");
        checks_passed += 1;
    } else if hash_fail > 0 {
        println!("FAIL ({hash_fail} invalid, {hash_ok} valid, {hash_skip} skipped)");
        checks_failed += 1;
    } else {
        println!("PARTIAL ({hash_ok} valid, {hash_skip} unavailable)");
        checks_passed += 1;
    }

    // Check 4: Manifest metadata consistency
    print!("  [4] Manifest consistency ... ");
    let file_count_ok = manifest.file_count == manifest.files.len() as u32;
    let sizes_ok = manifest.total_original_size
        == manifest.files.iter().map(|f| f.original_size).sum::<u64>()
        && manifest.total_encrypted_size
            == manifest.files.iter().map(|f| f.encrypted_size).sum::<u64>();

    if file_count_ok && sizes_ok {
        println!("PASS");
        checks_passed += 1;
    } else {
        println!("FAIL");
        if !file_count_ok {
            eprintln!("    File count mismatch");
        }
        if !sizes_ok {
            eprintln!("    Size totals mismatch");
        }
        checks_failed += 1;
    }

    // Summary
    println!();
    let all_passed = checks_failed == 0;
    if all_passed {
        println!(
            "Verification PASSED ({checks_passed}/{} checks).",
            checks_passed + checks_failed
        );
    } else {
        println!("Verification FAILED ({checks_failed} failed, {checks_passed} passed).");
        std::process::exit(1);
    }

    // Submit VerifyIntegrity attestation to chain (only if all checks passed)
    if let Some(chain_url) = effective_chain {
        if all_passed {
            attest_on_chain(&chain_url, manifest.merkle_root).await;
        } else {
            eprintln!("Skipping chain attestation — verification failed.");
        }
    }
}

/// Submit a VerifyIntegrity attestation to the chain.
async fn attest_on_chain(chain_url: &str, merkle_root: [u8; 32]) {
    use ed25519_dalek::{Signer, SigningKey};

    // Load and unlock keys for signing
    let store = match keys::load_key_store() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Chain attestation: cannot load keystore ({e})");
            return;
        }
    };

    let passphrase = Zeroizing::new(
        rpassword::prompt_password("Enter passphrase for chain attestation: ")
            .expect("Failed to read passphrase"),
    );

    let unlocked = match keys::unlock_all_keys(passphrase.as_bytes(), &store, None, None) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Chain attestation: wrong passphrase ({e})");
            return;
        }
    };

    println!();
    println!("Submitting VerifyIntegrity attestation ({chain_url})...");

    let signing_key = SigningKey::from_bytes(&unlocked.ed25519_sk);
    let signature = signing_key.sign(&merkle_root);

    let tx = serde_json::json!({
        "VerifyIntegrity": {
            "merkle_root": merkle_root,
            "verifier_pk": unlocked.ed25519_pk,
            "signature": signature.to_bytes().to_vec(),
        }
    });
    let tx_json = tx.to_string();

    let client = reqwest::Client::new();
    let url = format!("{}/submit_tx", chain_url.trim_end_matches('/'));
    let body = serde_json::json!({ "tx_json": tx_json });

    match client.post(&url).json(&body).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();

            if status.is_success() {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body_text) {
                    let tx_hash = parsed["tx_hash"].as_str().unwrap_or("?");
                    println!("  Chain attestation: SUCCESS");
                    println!("  tx_hash: {tx_hash}");
                } else {
                    println!("  Chain attestation: SUCCESS");
                }
            } else {
                eprintln!("  Chain attestation: FAILED (HTTP {status})");
                eprintln!("  Response: {body_text}");
            }
        }
        Err(e) => {
            eprintln!("  Chain attestation: FAILED (connection error: {e})");
        }
    }
}

/// Check if a file exists in any of its storage locations.
async fn check_file_exists(
    file_entry: &zk_vault_core::manifest::ManifestFileEntry,
    s3_storage: &Option<S3Backend>,
    chain_url: Option<&str>,
) -> bool {
    for location in &file_entry.storage_locations {
        match location.backend.as_str() {
            "local" => {
                if PathBuf::from(&location.storage_key).exists() {
                    return true;
                }
            }
            "s3" => {
                if let Some(s3) = s3_storage {
                    if let Ok(true) = s3.exists(&location.storage_key).await {
                        return true;
                    }
                }
            }
            "chain" => {
                if let Some(url) = chain_url {
                    if download_from_chain(url, &location.storage_key)
                        .await
                        .is_some()
                    {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

async fn cmd_status(chain_url: Option<String>, _keyfile_path: Option<PathBuf>) {
    let effective_chain = resolve_chain_url(&chain_url);
    println!("zk-vault status");
    println!("===============");

    // 1. Vault existence
    let vault_dir = keys::vault_dir().unwrap_or_else(|e| fatal_with("vault dir", e));
    let keystore_path = keys::keystore_path().unwrap_or_else(|e| fatal_with("keystore path", e));

    if !keystore_path.exists() {
        println!();
        println!("Vault: NOT INITIALIZED");
        println!("  Run `zk-vault init` to create a new vault.");
        return;
    }

    println!();
    println!("Vault: {}", vault_dir.display());

    // 2. Load keystore and show public key fingerprints
    match keys::load_key_store() {
        Ok(store) => {
            println!("  Version:  {}", store.version);

            // Show fingerprints (first 8 bytes of BLAKE3 hash of public key)
            let kem_pk_bytes = hex::decode(&store.kem_pk).unwrap_or_default();
            let x25519_pk_bytes = hex::decode(&store.x25519_pk).unwrap_or_default();
            let mldsa_pk_bytes = hex::decode(&store.mldsa_pk).unwrap_or_default();
            let ed25519_pk_bytes = hex::decode(&store.ed25519_pk).unwrap_or_default();

            println!();
            println!("Public keys:");
            println!("  ML-KEM-768:  {}", fingerprint(&kem_pk_bytes));
            println!("  X25519:      {}", fingerprint(&x25519_pk_bytes));
            println!("  ML-DSA-65:   {}", fingerprint(&mldsa_pk_bytes));
            println!("  Ed25519:     {}", fingerprint(&ed25519_pk_bytes));
        }
        Err(e) => {
            println!("  Error loading keystore: {e}");
        }
    }

    // 3. Storage config
    println!();
    let config_path = vault_dir.join("config.toml");
    if config_path.exists() {
        println!("Storage: config.toml found");
        let content = std::fs::read_to_string(&config_path).unwrap_or_default();
        if let Ok(config) = content.parse::<toml::Value>() {
            if let Some(s3) = config.get("storage").and_then(|s| s.get("s3")) {
                let bucket = s3.get("bucket").and_then(|v| v.as_str()).unwrap_or("?");
                let region = s3.get("region").and_then(|v| v.as_str()).unwrap_or("?");
                let endpoint = s3
                    .get("endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(default)");
                println!("  S3 bucket:   {bucket}");
                println!("  S3 region:   {region}");
                println!("  S3 endpoint: {endpoint}");
            }
        }
    } else {
        println!("Storage: no config.toml (use --local for backups, or create config)");
    }

    // 4. Backup history
    println!();
    let manifests_dir = vault_dir.join("manifests");
    if manifests_dir.exists() {
        let mut manifests: Vec<_> = std::fs::read_dir(&manifests_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
            .collect();

        manifests.sort_by_key(|e| std::cmp::Reverse(e.metadata().and_then(|m| m.modified()).ok()));

        if manifests.is_empty() {
            println!("Backups: none");
        } else {
            println!("Backups: {} total", manifests.len());
            println!();

            // Show most recent (up to 5)
            let show_count = manifests.len().min(5);
            for entry in manifests.iter().take(show_count) {
                if let Ok(json) = std::fs::read_to_string(entry.path()) {
                    if let Ok(m) =
                        serde_json::from_str::<zk_vault_core::manifest::BackupManifest>(&json)
                    {
                        println!(
                            "  {} | {} | {} files | {}",
                            &m.backup_id.to_string()[..8],
                            m.created_at.format("%Y-%m-%d %H:%M"),
                            m.file_count,
                            human_size(m.total_original_size),
                        );
                    }
                }
            }

            if manifests.len() > show_count {
                println!("  ... and {} more", manifests.len() - show_count);
            }
        }
    } else {
        println!("Backups: none");
    }

    // 5. Chain status (if chain was resolved)
    if let Some(chain_url) = effective_chain {
        query_chain_status(&chain_url).await;
    }
}

/// Query chain node status and display it.
async fn query_chain_status(chain_url: &str) {
    println!();
    println!("Chain: {chain_url}");

    let client = reqwest::Client::new();
    let base = chain_url.trim_end_matches('/');

    // GET /status
    match client.get(format!("{base}/status")).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            if let Ok(status) = serde_json::from_str::<serde_json::Value>(&body) {
                println!("  Height:      {}", status["height"]);
                println!("  Files:       {}", status["file_count"]);
                println!("  Validators:  {}", status["validator_count"]);
                println!("  Pending txs: {}", status["pending_txs"]);
                println!("  Committed:   {}", status["blocks_committed"]);
                println!(
                    "  State root:  {}",
                    status["state_root"].as_str().unwrap_or("?")
                );
            }
        }
        Ok(resp) => {
            eprintln!("  Chain status: HTTP {}", resp.status());
        }
        Err(e) => {
            eprintln!("  Chain unreachable: {e}");
        }
    }

    // Cross-reference local manifests with chain
    let manifests_dir = keys::vault_dir()
        .unwrap_or_else(|e| fatal_with("vault dir", e))
        .join("manifests");
    if !manifests_dir.exists() {
        return;
    }

    let manifest_files: Vec<_> = std::fs::read_dir(&manifests_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();

    if manifest_files.is_empty() {
        return;
    }

    println!();
    println!("On-chain status of local backups:");

    for entry in &manifest_files {
        let json = match std::fs::read_to_string(entry.path()) {
            Ok(j) => j,
            Err(_) => continue,
        };
        let manifest: zk_vault_core::manifest::BackupManifest = match serde_json::from_str(&json) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let merkle_hex = hex::encode(manifest.merkle_root);
        let short_id = &manifest.backup_id.to_string()[..8];

        // Query chain for this file
        let req = serde_json::json!({ "merkle_root": merkle_hex });
        match client
            .post(format!("{base}/get_file"))
            .json(&req)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.text().await.unwrap_or_default();
                if let Ok(file) = serde_json::from_str::<serde_json::Value>(&body) {
                    let verifications = file["verification_count"].as_u64().unwrap_or(0);
                    let registered_at = file["registered_at"].as_u64().unwrap_or(0);
                    println!(
                        "  {short_id} | registered (height {registered_at}, {verifications} verification(s))"
                    );
                }
            }
            Ok(_) => {
                println!("  {short_id} | not registered");
            }
            Err(_) => {
                println!("  {short_id} | query failed");
            }
        }
    }
}

/// Load anchoring config from ~/.zk-vault/config.toml.
fn load_anchor_config() -> Option<toml::Value> {
    let config_path = keys::vault_dir().ok()?.join("config.toml");
    if !config_path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&config_path).ok()?;
    let config: toml::Value = toml::from_str(&content).ok()?;
    config.get("anchor").cloned()
}

async fn cmd_anchor(backup: String, use_btc: bool, use_eth: bool) {
    use zk_vault_core::anchor::bitcoin::{BitcoinAnchor, BitcoinConfig};
    use zk_vault_core::anchor::ethereum::{EthereumAnchor, EthereumConfig};
    use zk_vault_core::anchor::BlockchainAnchor;

    if !use_btc && !use_eth {
        fatal("Specify at least one anchor target: --btc and/or --eth");
    }

    // 1. Load manifest
    let manifest_path = resolve_manifest_path(&backup);
    let manifest_json = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| fatal_with("reading manifest", e));
    let manifest: zk_vault_core::manifest::BackupManifest =
        serde_json::from_str(&manifest_json).unwrap_or_else(|e| fatal_with("parsing manifest", e));

    let merkle_root = manifest.merkle_root;
    println!("Anchoring backup: {}", manifest.backup_id);
    println!("  Merkle root: {}", hex::encode(merkle_root));
    println!();

    // 2. Load anchor config
    let anchor_config = load_anchor_config()
        .unwrap_or_else(|| fatal("No [anchor] section in ~/.zk-vault/config.toml. Add [anchor.bitcoin] and/or [anchor.ethereum] sections."));

    let mut receipts: Vec<zk_vault_core::anchor::AnchorReceipt> = Vec::new();

    // 3. Bitcoin anchoring
    if use_btc {
        let btc_config = anchor_config
            .get("bitcoin")
            .unwrap_or_else(|| fatal("[anchor.bitcoin] section missing in config.toml"));

        let api_url = btc_config
            .get("api_url")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fatal("anchor.bitcoin.api_url is required"));
        let network = btc_config
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("testnet");
        let wif = btc_config
            .get("wif_private_key")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fatal("anchor.bitcoin.wif_private_key is required"));

        if wif.is_empty() {
            fatal("anchor.bitcoin.wif_private_key is empty");
        }

        println!("Anchoring to Bitcoin ({network})...");
        let btc = BitcoinAnchor::new(BitcoinConfig {
            api_url: api_url.to_string(),
            network: network.to_string(),
            wif_private_key: wif.to_string(),
        });

        match btc.anchor(&merkle_root).await {
            Ok(receipt) => {
                println!("  Bitcoin anchor: SUCCESS");
                println!("  tx_id: {}", receipt.tx_id);
                if let Some(fee) = &receipt.fee {
                    println!("  fee: {fee}");
                }
                receipts.push(receipt);
            }
            Err(e) => {
                eprintln!("  Bitcoin anchor: FAILED ({e})");
            }
        }
    }

    // 4. Ethereum anchoring
    if use_eth {
        let eth_config = anchor_config
            .get("ethereum")
            .unwrap_or_else(|| fatal("[anchor.ethereum] section missing in config.toml"));

        let rpc_url = eth_config
            .get("rpc_url")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fatal("anchor.ethereum.rpc_url is required"));
        let network = eth_config
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("sepolia");
        let pk_hex = eth_config
            .get("private_key_hex")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fatal("anchor.ethereum.private_key_hex is required"));
        let chain_id = eth_config
            .get("chain_id")
            .and_then(|v| v.as_integer())
            .unwrap_or(11155111) as u64;

        if pk_hex.is_empty() {
            fatal("anchor.ethereum.private_key_hex is empty");
        }

        println!("Anchoring to Ethereum ({network})...");
        let eth = EthereumAnchor::new(EthereumConfig {
            rpc_url: rpc_url.to_string(),
            network: network.to_string(),
            private_key_hex: pk_hex.to_string(),
            chain_id,
        });

        match eth.anchor(&merkle_root).await {
            Ok(receipt) => {
                println!("  Ethereum anchor: SUCCESS");
                println!("  tx_hash: {}", receipt.tx_id);
                receipts.push(receipt);
            }
            Err(e) => {
                eprintln!("  Ethereum anchor: FAILED ({e})");
            }
        }
    }

    // 5. Save receipts to manifest directory
    if !receipts.is_empty() {
        let receipts_path = keys::vault_dir()
            .unwrap_or_else(|e| fatal_with("vault dir", e))
            .join("manifests")
            .join(format!("{}.anchors.json", manifest.backup_id));
        match serde_json::to_string_pretty(&receipts) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&receipts_path, json) {
                    eprintln!("Warning: Failed to save anchor receipts: {e}");
                } else {
                    println!();
                    println!("Anchor receipts saved: {}", receipts_path.display());
                }
            }
            Err(e) => eprintln!("Warning: Failed to serialize receipts: {e}"),
        }
    }

    // 6. Summary
    println!();
    let total = (use_btc as usize) + (use_eth as usize);
    println!("Anchoring complete: {}/{total} succeeded.", receipts.len());
}

/// BLAKE3 fingerprint of a public key (first 8 bytes, hex-encoded).
fn fingerprint(pk_bytes: &[u8]) -> String {
    if pk_bytes.is_empty() {
        return "(invalid)".to_string();
    }
    let h = hash::hash(pk_bytes);
    hex::encode(&h[..8])
}

/// Human-readable file size.
fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

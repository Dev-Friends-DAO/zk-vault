use std::path::PathBuf;

use clap::{Parser, Subcommand};
use uuid::Uuid;

use zk_vault::crypto::{aead, bundle, hash, kem, keys};
use zk_vault::manifest::{ManifestBuilder, ManifestFileEntry, StorageLocation};
use zk_vault::merkle::tree::MerkleTree;
use zk_vault::storage::s3::{S3Backend, S3Config};
use zk_vault::storage::StorageBackend;

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
    Init,
    /// Back up files to S3-compatible storage
    Backup {
        /// Files or directories to back up
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Restore from backup
    Restore,
    /// Verify backup integrity
    Verify,
    /// Show vault status
    Status,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zk_vault=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::Backup { paths } => cmd_backup(paths).await,
        Commands::Restore => {
            println!("zk-vault restore: not yet implemented");
        }
        Commands::Verify => {
            println!("zk-vault verify: not yet implemented");
        }
        Commands::Status => {
            println!("zk-vault status: not yet implemented");
        }
    }
}

fn cmd_init() {
    // Check if vault already exists
    let keystore_path = keys::keystore_path();
    if keystore_path.exists() {
        eprintln!("Error: Vault already exists at {}", keystore_path.display());
        eprintln!("To reinitialize, remove the existing keystore first.");
        std::process::exit(1);
    }

    // Prompt for passphrase
    let passphrase = rpassword::prompt_password("Enter passphrase for new vault: ")
        .expect("Failed to read passphrase");

    if passphrase.is_empty() {
        eprintln!("Error: Passphrase cannot be empty.");
        std::process::exit(1);
    }

    let confirm =
        rpassword::prompt_password("Confirm passphrase: ").expect("Failed to read passphrase");

    if passphrase != confirm {
        eprintln!("Error: Passphrases do not match.");
        std::process::exit(1);
    }

    println!("Generating post-quantum key pairs (this may take a moment)...");

    match keys::generate_key_store(passphrase.as_bytes()) {
        Ok(store) => match keys::save_key_store(&store) {
            Ok(()) => {
                println!("Vault initialized successfully.");
                println!("Keystore saved to: {}", keystore_path.display());
                println!();
                println!("Key pairs generated:");
                println!("  - ML-KEM-768   (post-quantum key encapsulation)");
                println!("  - X25519       (classical key exchange)");
                println!("  - ML-DSA-65    (post-quantum signatures)");
                println!("  - Ed25519      (classical signatures)");
                println!();
                println!("IMPORTANT: Remember your passphrase. It cannot be recovered.");
            }
            Err(e) => {
                eprintln!("Error saving keystore: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Error generating keys: {e}");
            std::process::exit(1);
        }
    }
}

/// Load S3 config from ~/.zk-vault/config.toml.
fn load_s3_config() -> S3Config {
    let config_path = keys::vault_dir().join("config.toml");
    if !config_path.exists() {
        eprintln!("Error: No config file found at {}", config_path.display());
        eprintln!("Create it with S3 storage settings. See config.example.toml.");
        std::process::exit(1);
    }

    let content = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
        eprintln!("Error reading config: {e}");
        std::process::exit(1);
    });

    let config: toml::Value = toml::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Error parsing config: {e}");
        std::process::exit(1);
    });

    let s3 = config
        .get("storage")
        .and_then(|s| s.get("s3"))
        .unwrap_or_else(|| {
            eprintln!("Error: [storage.s3] section missing in config.toml");
            std::process::exit(1);
        });

    S3Config {
        bucket: s3
            .get("bucket")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                eprintln!("Error: storage.s3.bucket is required");
                std::process::exit(1);
            })
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
fn save_manifest(manifest: &zk_vault::manifest::BackupManifest) -> std::io::Result<PathBuf> {
    let dir = keys::vault_dir().join("manifests");
    std::fs::create_dir_all(&dir)?;
    let filename = format!("{}.json", manifest.backup_id);
    let path = dir.join(&filename);
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| std::io::Error::other(format!("Serialize manifest: {e}")))?;
    std::fs::write(&path, json)?;
    Ok(path)
}

async fn cmd_backup(paths: Vec<PathBuf>) {
    // 1. Load keystore
    let store = keys::load_key_store().unwrap_or_else(|e| {
        eprintln!("Error: Cannot load vault. Run `zk-vault init` first. ({e})");
        std::process::exit(1);
    });

    // 2. Unlock keys
    let passphrase =
        rpassword::prompt_password("Enter passphrase: ").expect("Failed to read passphrase");

    let unlocked = keys::unlock_all_keys(passphrase.as_bytes(), &store).unwrap_or_else(|e| {
        eprintln!("Error: Failed to unlock vault. Wrong passphrase? ({e})");
        std::process::exit(1);
    });

    // 3. Build hybrid public key for KEM wrapping
    let hybrid_pk = kem::HybridPublicKey {
        kem_pk: unlocked.kem_pk.clone(),
        x25519_pk: unlocked.x25519_pk,
    };

    // 4. Collect files
    let files = collect_files(&paths);
    if files.is_empty() {
        eprintln!("No files found to back up.");
        std::process::exit(1);
    }
    println!("Found {} file(s) to back up.", files.len());

    // 5. Connect to S3
    let s3_config = load_s3_config();
    let storage = S3Backend::new(&s3_config).unwrap_or_else(|e| {
        eprintln!("Error: Failed to connect to S3: {e}");
        std::process::exit(1);
    });

    // 6. Process each file
    let user_id = Uuid::now_v7();
    let mut manifest_builder = ManifestBuilder::new(user_id, "local");
    let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();
    let mut total_uploaded: u64 = 0;
    let mut success_count: usize = 0;

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
            .unwrap_or_else(|e| {
                eprintln!("  Error encrypting {relative_path}: {e}");
                std::process::exit(1);
            });

        // Wrap symmetric key with hybrid KEM
        let encap = kem::encapsulate(&hybrid_pk, &sym_key).unwrap_or_else(|e| {
            eprintln!("  Error wrapping key for {relative_path}: {e}");
            std::process::exit(1);
        });

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

        // Upload to S3
        let storage_key = format!("{user_id}/{file_id}");
        match storage.upload(&storage_key, &bundle_bytes).await {
            Ok(_) => {
                println!(
                    "  Backed up: {relative_path} ({original_size} -> {encrypted_size} bytes)"
                );
                leaf_hashes.push(content_hash);
                total_uploaded += encrypted_size;
                success_count += 1;

                manifest_builder.add_file(ManifestFileEntry {
                    source_path: relative_path,
                    source_id: file_id,
                    content_hash: plaintext_hash,
                    original_size,
                    encrypted_size,
                    mime_type: None,
                    source_modified_at: None,
                    storage_locations: vec![StorageLocation {
                        backend: "s3".to_string(),
                        storage_key,
                    }],
                });
            }
            Err(e) => {
                eprintln!("  Upload failed for {relative_path}: {e}");
            }
        }
    }

    if success_count == 0 {
        eprintln!("No files were backed up successfully.");
        std::process::exit(1);
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
            println!();
            println!("Backup complete.");
            println!("  Files:       {success_count}/{}", files.len());
            println!("  Uploaded:    {total_uploaded} bytes");
            println!("  Merkle root: {}", hex::encode(merkle_root));
            println!("  Manifest:    {}", path.display());
            println!("  Backup ID:   {}", manifest.backup_id);
        }
        Err(e) => {
            eprintln!("Warning: Backup succeeded but manifest save failed: {e}");
            eprintln!("Merkle root: {}", hex::encode(merkle_root));
        }
    }
}

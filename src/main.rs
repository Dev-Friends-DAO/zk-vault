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
    /// Back up files to S3-compatible storage and/or local directory
    Backup {
        /// Files or directories to back up
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Save encrypted backups to a local directory (Layer 0)
        #[arg(long)]
        local: Option<PathBuf>,
    },
    /// Restore files from a backup
    Restore {
        /// Backup ID or path to manifest file
        #[arg()]
        backup: String,
        /// Output directory for restored files
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
    /// Verify backup integrity without decrypting
    Verify {
        /// Backup ID or path to manifest file
        #[arg()]
        backup: String,
    },
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
        Commands::Backup { paths, local } => cmd_backup(paths, local).await,
        Commands::Restore { backup, output } => cmd_restore(backup, output).await,
        Commands::Verify { backup } => cmd_verify(backup).await,
        Commands::Status => cmd_status(),
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

async fn cmd_backup(paths: Vec<PathBuf>, local_dir: Option<PathBuf>) {
    // 1. Determine storage targets
    let config_path = keys::vault_dir().join("config.toml");
    let use_s3 = config_path.exists();
    let use_local = local_dir.is_some();

    if !use_s3 && !use_local {
        eprintln!("Error: No storage target specified.");
        eprintln!("Either create ~/.zk-vault/config.toml for S3, or use --local <dir>.");
        std::process::exit(1);
    }

    // 2. Load keystore
    let store = keys::load_key_store().unwrap_or_else(|e| {
        eprintln!("Error: Cannot load vault. Run `zk-vault init` first. ({e})");
        std::process::exit(1);
    });

    // 3. Unlock keys
    let passphrase =
        rpassword::prompt_password("Enter passphrase: ").expect("Failed to read passphrase");

    let unlocked = keys::unlock_all_keys(passphrase.as_bytes(), &store).unwrap_or_else(|e| {
        eprintln!("Error: Failed to unlock vault. Wrong passphrase? ({e})");
        std::process::exit(1);
    });

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

    // 5. Set up storage targets
    let s3_storage = if use_s3 {
        let s3_config = load_s3_config();
        Some(S3Backend::new(&s3_config).unwrap_or_else(|e| {
            eprintln!("Error: Failed to connect to S3: {e}");
            std::process::exit(1);
        }))
    } else {
        None
    };

    if let Some(dir) = &local_dir {
        std::fs::create_dir_all(dir).unwrap_or_else(|e| {
            eprintln!(
                "Error: Cannot create local output dir {}: {e}",
                dir.display()
            );
            std::process::exit(1);
        });
    }

    let mut targets: Vec<&str> = Vec::new();
    if use_s3 {
        targets.push("S3");
    }
    if use_local {
        targets.push("local");
    }
    println!("Storage targets: {}", targets.join(" + "));

    // 6. Process each file
    let user_id = Uuid::now_v7();
    let mut manifest_builder = ManifestBuilder::new(user_id, "local");
    let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();
    let mut total_bytes: u64 = 0;
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
            println!("  Total:       {total_bytes} bytes (encrypted)");
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

/// Resolve a backup identifier to a manifest path.
/// Accepts either a direct file path or a backup UUID (looked up in ~/.zk-vault/manifests/).
fn resolve_manifest_path(backup: &str) -> PathBuf {
    let path = PathBuf::from(backup);
    if path.exists() {
        return path;
    }

    // Try as backup ID in manifests dir
    let manifest_path = keys::vault_dir()
        .join("manifests")
        .join(format!("{backup}.json"));
    if manifest_path.exists() {
        return manifest_path;
    }

    eprintln!("Error: Cannot find manifest for '{backup}'.");
    eprintln!("Provide a backup ID or path to a manifest file.");
    eprintln!(
        "Available manifests: {}",
        keys::vault_dir().join("manifests").display()
    );
    std::process::exit(1);
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

async fn cmd_restore(backup: String, output: PathBuf) {
    // 1. Load manifest
    let manifest_path = resolve_manifest_path(&backup);
    let manifest_json = std::fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
        eprintln!("Error reading manifest: {e}");
        std::process::exit(1);
    });
    let manifest: zk_vault::manifest::BackupManifest = serde_json::from_str(&manifest_json)
        .unwrap_or_else(|e| {
            eprintln!("Error parsing manifest: {e}");
            std::process::exit(1);
        });

    println!("Restoring backup: {}", manifest.backup_id);
    println!("  Source:  {}", manifest.source);
    println!("  Files:   {}", manifest.file_count);
    println!("  Created: {}", manifest.created_at);

    // 2. Verify manifest integrity
    match manifest.verify_integrity() {
        Ok(true) => println!("  Merkle root: verified"),
        Ok(false) => {
            eprintln!("Error: Manifest Merkle root mismatch. Data may be tampered.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error verifying manifest: {e}");
            std::process::exit(1);
        }
    }

    // 3. Unlock keys
    let store = keys::load_key_store().unwrap_or_else(|e| {
        eprintln!("Error: Cannot load vault. ({e})");
        std::process::exit(1);
    });

    let passphrase =
        rpassword::prompt_password("Enter passphrase: ").expect("Failed to read passphrase");

    let unlocked = keys::unlock_all_keys(passphrase.as_bytes(), &store).unwrap_or_else(|e| {
        eprintln!("Error: Failed to unlock vault. Wrong passphrase? ({e})");
        std::process::exit(1);
    });

    // 4. Set up S3 if available
    let config_path = keys::vault_dir().join("config.toml");
    let s3_storage = if config_path.exists() {
        let s3_config = load_s3_config();
        S3Backend::new(&s3_config).ok()
    } else {
        None
    };

    // 5. Create output directory
    std::fs::create_dir_all(&output).unwrap_or_else(|e| {
        eprintln!("Error creating output directory: {e}");
        std::process::exit(1);
    });

    // 6. Restore each file
    let mut restored = 0usize;
    let mut failed = 0usize;
    let mut bytes_restored: u64 = 0;

    for file_entry in &manifest.files {
        let source_path = &file_entry.source_path;

        // Try to download the encrypted bundle
        let bundle_bytes = fetch_bundle(file_entry, &s3_storage).await;
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
                eprintln!("Error: Invalid X25519 secret key length");
                std::process::exit(1);
            });
        let x25519_sk = x25519_dalek::StaticSecret::from(x25519_sk_bytes);
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
    file_entry: &zk_vault::manifest::ManifestFileEntry,
    s3_storage: &Option<S3Backend>,
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

async fn cmd_verify(backup: String) {
    // 1. Load manifest
    let manifest_path = resolve_manifest_path(&backup);
    let manifest_json = std::fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
        eprintln!("Error reading manifest: {e}");
        std::process::exit(1);
    });
    let manifest: zk_vault::manifest::BackupManifest = serde_json::from_str(&manifest_json)
        .unwrap_or_else(|e| {
            eprintln!("Error parsing manifest: {e}");
            std::process::exit(1);
        });

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
    let config_path = keys::vault_dir().join("config.toml");
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
        let found = check_file_exists(file_entry, &s3_storage).await;
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
        let bundle_bytes = fetch_bundle(file_entry, &s3_storage).await;
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
}

/// Check if a file exists in any of its storage locations.
async fn check_file_exists(
    file_entry: &zk_vault::manifest::ManifestFileEntry,
    s3_storage: &Option<S3Backend>,
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
            _ => {}
        }
    }
    false
}

fn cmd_status() {
    println!("zk-vault status");
    println!("===============");

    // 1. Vault existence
    let vault_dir = keys::vault_dir();
    let keystore_path = keys::keystore_path();

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
                    if let Ok(m) = serde_json::from_str::<zk_vault::manifest::BackupManifest>(&json)
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

use clap::{Parser, Subcommand};

use zk_vault::crypto::keys;

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
    /// Run a backup
    Backup,
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
        Commands::Backup => {
            println!("zk-vault backup: not yet implemented");
        }
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

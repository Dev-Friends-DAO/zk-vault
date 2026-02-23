use clap::{Parser, Subcommand};

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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            println!("zk-vault init: key generation not yet implemented");
        }
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

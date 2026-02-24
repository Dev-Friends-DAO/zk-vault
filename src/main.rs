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
    /// Run the API server
    Serve {
        /// Listen address
        #[arg(long, default_value = "0.0.0.0:3000")]
        addr: String,
        /// Database URL
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        /// JWT secret
        #[arg(long, env = "JWT_SECRET")]
        jwt_secret: String,
    },
    /// Run batch job (Super Merkle Tree aggregation + blockchain anchoring)
    Batch {
        /// Database URL
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
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
                .unwrap_or_else(|_| "zk_vault=info,tower_http=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            println!("zk-vault init: key generation not yet implemented");
        }
        Commands::Serve {
            addr,
            database_url,
            jwt_secret,
        } => {
            let db = zk_vault::state::Database::connect(&database_url)
                .await
                .expect("Failed to connect to database");

            db.migrate().await.expect("Failed to run migrations");

            let state = zk_vault::server::AppState { db, jwt_secret };

            zk_vault::server::serve(state, &addr)
                .await
                .expect("Server error");
        }
        Commands::Batch { database_url } => {
            let db = zk_vault::state::Database::connect(&database_url)
                .await
                .expect("Failed to connect to database");

            db.migrate().await.expect("Failed to run migrations");

            tracing::info!("Running batch job: Super Merkle Tree aggregation + anchoring");
            // TODO: Fetch all pending user Merkle roots from DB,
            // build Super Merkle Tree, anchor to Bitcoin + Ethereum,
            // distribute proofs back to users.
            tracing::info!("Batch job complete");
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

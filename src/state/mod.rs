/// Database state layer for zk-vault.
///
/// Manages PostgreSQL connections and provides typed access to:
/// - Users and authentication state
/// - Backup jobs and their status
/// - Data source connections
/// - Anchor receipts (blockchain proofs)
pub mod models;
pub mod repository;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::error::{Result, VaultError};

/// Database connection pool wrapper.
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Connect to PostgreSQL and run migrations.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        Ok(Self { pool })
    }

    /// Run pending migrations.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| {
                VaultError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Migration failed: {e}"),
                ))
            })
    }

    /// Get a reference to the underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

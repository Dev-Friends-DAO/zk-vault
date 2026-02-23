/// Repository layer: typed database queries for zk-vault.
///
/// All queries use sqlx runtime-checked queries (not compile-time checked)
/// to avoid requiring a live database during development builds.
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use super::models::*;
use crate::error::{Result, VaultError};

fn db_err(e: sqlx::Error) -> VaultError {
    VaultError::Io(std::io::Error::other(e))
}

// ── Users ──

pub async fn create_user(
    pool: &PgPool,
    opaque_registration: &[u8],
    encrypted_key_store: &[u8],
) -> Result<User> {
    let id = Uuid::now_v7();
    let now = Utc::now();

    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, opaque_registration, encrypted_key_store, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(opaque_registration)
    .bind(encrypted_key_store)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(user)
}

pub async fn get_user(pool: &PgPool, user_id: Uuid) -> Result<Option<User>> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)
}

// ── Backup Jobs ──

pub async fn create_backup_job(
    pool: &PgPool,
    user_id: Uuid,
    source_type: &str,
) -> Result<BackupJob> {
    let id = Uuid::now_v7();
    let now = Utc::now();

    let job = sqlx::query_as::<_, BackupJob>(
        r#"
        INSERT INTO backup_jobs (id, user_id, source_type, status, files_processed, bytes_uploaded, started_at)
        VALUES ($1, $2, $3, 'pending', 0, 0, $4)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(source_type)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(job)
}

pub async fn update_backup_job_status(
    pool: &PgPool,
    job_id: Uuid,
    status: BackupStatus,
    merkle_root: Option<&[u8]>,
    error_message: Option<&str>,
) -> Result<()> {
    let completed_at = match status {
        BackupStatus::Completed | BackupStatus::Failed => Some(Utc::now()),
        _ => None,
    };

    sqlx::query(
        r#"
        UPDATE backup_jobs
        SET status = $2, merkle_root = $3, error_message = $4, completed_at = $5
        WHERE id = $1
        "#,
    )
    .bind(job_id)
    .bind(status)
    .bind(merkle_root)
    .bind(error_message)
    .bind(completed_at)
    .execute(pool)
    .await
    .map_err(db_err)?;

    Ok(())
}

pub async fn get_user_backup_jobs(
    pool: &PgPool,
    user_id: Uuid,
    limit: i64,
) -> Result<Vec<BackupJob>> {
    sqlx::query_as::<_, BackupJob>(
        "SELECT * FROM backup_jobs WHERE user_id = $1 ORDER BY started_at DESC LIMIT $2",
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

// ── Source Connections ──

pub async fn upsert_source_connection(
    pool: &PgPool,
    user_id: Uuid,
    source_type: &str,
    encrypted_tokens: &[u8],
    token_nonce: &[u8],
) -> Result<SourceConnection> {
    let id = Uuid::now_v7();
    let now = Utc::now();

    let conn = sqlx::query_as::<_, SourceConnection>(
        r#"
        INSERT INTO source_connections (id, user_id, source_type, encrypted_tokens, token_nonce, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (user_id, source_type)
        DO UPDATE SET encrypted_tokens = $4, token_nonce = $5
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(source_type)
    .bind(encrypted_tokens)
    .bind(token_nonce)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(conn)
}

pub async fn get_source_connection(
    pool: &PgPool,
    user_id: Uuid,
    source_type: &str,
) -> Result<Option<SourceConnection>> {
    sqlx::query_as::<_, SourceConnection>(
        "SELECT * FROM source_connections WHERE user_id = $1 AND source_type = $2",
    )
    .bind(user_id)
    .bind(source_type)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

pub async fn update_sync_cursor(pool: &PgPool, connection_id: Uuid, cursor: &str) -> Result<()> {
    sqlx::query("UPDATE source_connections SET sync_cursor = $2, last_sync_at = $3 WHERE id = $1")
        .bind(connection_id)
        .bind(cursor)
        .bind(Utc::now())
        .execute(pool)
        .await
        .map_err(db_err)?;

    Ok(())
}

// ── Anchor Receipts ──

pub async fn create_anchor_receipt(
    pool: &PgPool,
    super_root: &[u8],
    chain: &str,
    tx_hash: &str,
) -> Result<AnchorReceipt> {
    let id = Uuid::now_v7();
    let now = Utc::now();

    let receipt = sqlx::query_as::<_, AnchorReceipt>(
        r#"
        INSERT INTO anchor_receipts (id, super_root, chain, tx_hash, anchored_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(super_root)
    .bind(chain)
    .bind(tx_hash)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(receipt)
}

pub async fn get_latest_anchor(pool: &PgPool, chain: &str) -> Result<Option<AnchorReceipt>> {
    sqlx::query_as::<_, AnchorReceipt>(
        "SELECT * FROM anchor_receipts WHERE chain = $1 ORDER BY anchored_at DESC LIMIT 1",
    )
    .bind(chain)
    .fetch_optional(pool)
    .await
    .map_err(db_err)
}

// ── Backed Up Files ──

#[allow(clippy::too_many_arguments)]
pub async fn insert_backed_up_file(
    pool: &PgPool,
    user_id: Uuid,
    backup_job_id: Uuid,
    source_file_id: &str,
    file_name: &str,
    original_size: i64,
    encrypted_size: i64,
    content_hash: &[u8],
    storage_key: Option<&str>,
    ipfs_cid: Option<&str>,
) -> Result<BackedUpFile> {
    let id = Uuid::now_v7();
    let now = Utc::now();

    let file = sqlx::query_as::<_, BackedUpFile>(
        r#"
        INSERT INTO backed_up_files
        (id, user_id, backup_job_id, source_file_id, file_name, original_size, encrypted_size, content_hash, storage_key, ipfs_cid, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(backup_job_id)
    .bind(source_file_id)
    .bind(file_name)
    .bind(original_size)
    .bind(encrypted_size)
    .bind(content_hash)
    .bind(storage_key)
    .bind(ipfs_cid)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;

    Ok(file)
}

pub async fn get_files_by_backup_job(
    pool: &PgPool,
    backup_job_id: Uuid,
) -> Result<Vec<BackedUpFile>> {
    sqlx::query_as::<_, BackedUpFile>(
        "SELECT * FROM backed_up_files WHERE backup_job_id = $1 ORDER BY created_at",
    )
    .bind(backup_job_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)
}

/// REST API routes for zk-vault.
///
/// All data handled by these routes is already encrypted client-side.
/// The server acts as a blind relay — it routes ciphertext without
/// ever accessing plaintext.
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::ErrorResponse;
use super::middleware::AuthUser;
use super::AppState;
use crate::state::models::BackupStatus;

// ─── Health ──────────────────────────────────────────────

/// Health check response.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

/// GET /health
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub fn health_routes() -> Router<Arc<AppState>> {
    Router::new().route("/health", get(health))
}

// ─── Auth ────────────────────────────────────────────────

pub fn auth_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/auth/register", post(super::auth::register))
        .route("/api/auth/login", post(super::auth::login))
}

// ─── Backup ──────────────────────────────────────────────

/// Request to start a new backup job.
#[derive(Debug, Deserialize)]
struct StartBackupRequest {
    source_type: String,
}

/// Backup job response.
#[derive(Debug, Serialize)]
struct BackupJobResponse {
    job_id: Uuid,
    status: String,
    files_processed: i64,
    bytes_uploaded: i64,
    started_at: String,
    completed_at: Option<String>,
}

/// POST /api/backups — Start a new backup job.
async fn start_backup(
    user: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartBackupRequest>,
) -> Result<(StatusCode, Json<BackupJobResponse>), (StatusCode, Json<ErrorResponse>)> {
    let job_id = Uuid::now_v7();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO backup_jobs (id, user_id, source_type, status, files_processed, bytes_uploaded, started_at)
        VALUES ($1, $2, $3, $4, 0, 0, $5)
        "#,
    )
    .bind(job_id)
    .bind(user.user_id)
    .bind(&req.source_type)
    .bind(BackupStatus::Pending)
    .bind(now)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to create backup job: {e}"),
            }),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(BackupJobResponse {
            job_id,
            status: "pending".to_string(),
            files_processed: 0,
            bytes_uploaded: 0,
            started_at: now.to_rfc3339(),
            completed_at: None,
        }),
    ))
}

/// GET /api/backups — List backup jobs for the authenticated user.
async fn list_backups(
    user: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<BackupJobResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let jobs: Vec<crate::state::models::BackupJob> = sqlx::query_as(
        "SELECT * FROM backup_jobs WHERE user_id = $1 ORDER BY started_at DESC LIMIT 50",
    )
    .bind(user.user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to list backups: {e}"),
            }),
        )
    })?;

    let responses: Vec<BackupJobResponse> = jobs
        .into_iter()
        .map(|j| BackupJobResponse {
            job_id: j.id,
            status: format!("{:?}", j.status).to_lowercase(),
            files_processed: j.files_processed,
            bytes_uploaded: j.bytes_uploaded,
            started_at: j.started_at.to_rfc3339(),
            completed_at: j.completed_at.map(|t| t.to_rfc3339()),
        })
        .collect();

    Ok(Json(responses))
}

pub fn backup_routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/backups", post(start_backup).get(list_backups))
}

// ─── Source Connections ──────────────────────────────────

/// Request to connect a data source.
#[derive(Debug, Deserialize)]
struct ConnectSourceRequest {
    source_type: String,
    /// Encrypted OAuth tokens (encrypted client-side).
    encrypted_tokens: Vec<u8>,
    /// Nonce for token encryption.
    token_nonce: Vec<u8>,
}

/// Source connection response.
#[derive(Debug, Serialize)]
struct SourceConnectionResponse {
    id: Uuid,
    source_type: String,
    created_at: String,
}

/// POST /api/sources — Connect a new data source.
async fn connect_source(
    user: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectSourceRequest>,
) -> Result<(StatusCode, Json<SourceConnectionResponse>), (StatusCode, Json<ErrorResponse>)> {
    let id = Uuid::now_v7();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO source_connections (id, user_id, source_type, encrypted_tokens, token_nonce, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(id)
    .bind(user.user_id)
    .bind(&req.source_type)
    .bind(&req.encrypted_tokens)
    .bind(&req.token_nonce)
    .bind(now)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to connect source: {e}"),
            }),
        )
    })?;

    Ok((
        StatusCode::CREATED,
        Json(SourceConnectionResponse {
            id,
            source_type: req.source_type,
            created_at: now.to_rfc3339(),
        }),
    ))
}

/// GET /api/sources — List connected data sources.
async fn list_sources(
    user: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<SourceConnectionResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let sources: Vec<crate::state::models::SourceConnection> =
        sqlx::query_as("SELECT * FROM source_connections WHERE user_id = $1 ORDER BY created_at")
            .bind(user.user_id)
            .fetch_all(state.db.pool())
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to list sources: {e}"),
                    }),
                )
            })?;

    let responses: Vec<SourceConnectionResponse> = sources
        .into_iter()
        .map(|s| SourceConnectionResponse {
            id: s.id,
            source_type: s.source_type,
            created_at: s.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(responses))
}

pub fn source_routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/sources", post(connect_source).get(list_sources))
}

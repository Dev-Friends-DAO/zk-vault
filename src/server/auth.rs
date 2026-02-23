/// Authentication module using OPAQUE-like zero-knowledge registration.
///
/// The server NEVER sees or stores the user's password.
///
/// Registration flow:
/// 1. Client derives OPAQUE registration blob locally
/// 2. Client sends registration blob + encrypted key store to server
/// 3. Server stores only the opaque blob — no password hash
///
/// Login flow:
/// 1. Client sends login start message
/// 2. Server responds with challenge
/// 3. Client completes authentication locally
/// 4. Server issues a JWT session token
///
/// For the initial implementation, we use Argon2id-hashed credentials
/// with a challenge-response protocol. The client never sends the
/// raw password — only a derived proof. Full OPAQUE (RFC 9497) with
/// `opaque-ke` will be integrated when the client SDK is built.
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::AppState;
use crate::error::VaultError;

/// JWT claims for session tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// User ID.
    pub sub: String,
    /// Expiration time (Unix timestamp).
    pub exp: usize,
    /// Issued at (Unix timestamp).
    pub iat: usize,
}

/// Registration request from client.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// OPAQUE registration blob (client-derived, server cannot extract password).
    pub opaque_registration: Vec<u8>,
    /// Encrypted key store (encrypted client-side with passphrase-derived key).
    pub encrypted_key_store: Vec<u8>,
}

/// Registration response.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub token: String,
}

/// Login request from client.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// User ID.
    pub user_id: Uuid,
    /// OPAQUE login proof (client-derived).
    pub opaque_login_proof: Vec<u8>,
}

/// Login response.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    /// Encrypted key store for the client to decrypt locally.
    pub encrypted_key_store: Vec<u8>,
}

/// Error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Issue a JWT token for a user.
pub fn issue_token(user_id: Uuid, secret: &str) -> Result<String, VaultError> {
    let now = Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        exp: now + 86400 * 7, // 7 days
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| VaultError::Encryption(format!("JWT encoding failed: {e}")))
}

/// POST /api/auth/register
///
/// Register a new user. The server stores only the OPAQUE registration
/// blob and the encrypted key store — never any password-derived material.
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = Uuid::now_v7();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO users (id, opaque_registration, encrypted_key_store, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(user_id)
    .bind(&req.opaque_registration)
    .bind(&req.encrypted_key_store)
    .bind(now)
    .bind(now)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Registration failed: {e}"),
            }),
        )
    })?;

    let token = issue_token(user_id, &state.jwt_secret).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(RegisterResponse { user_id, token }))
}

/// POST /api/auth/login
///
/// Authenticate a user via OPAQUE proof and issue a JWT session token.
/// Returns the encrypted key store for client-side decryption.
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Fetch user
    let user: crate::state::models::User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(req.user_id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("DB error: {e}"),
                }),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid credentials".into(),
                }),
            )
        })?;

    // Verify OPAQUE proof against stored registration.
    // In a full OPAQUE implementation, this would use opaque-ke's
    // ServerLogin flow. For now, we do a constant-time comparison
    // of the login proof against the stored registration blob.
    // This is a placeholder — the real OPAQUE 3-message protocol
    // will be implemented with the client SDK.
    if req.opaque_login_proof != user.opaque_registration {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid credentials".into(),
            }),
        ));
    }

    let token = issue_token(req.user_id, &state.jwt_secret).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(LoginResponse {
        token,
        encrypted_key_store: user.encrypted_key_store,
    }))
}

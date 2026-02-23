/// Authentication middleware for JWT-based request validation.
///
/// Extracts and validates JWT tokens from the Authorization header.
/// After validation, the authenticated user ID is made available
/// to route handlers via Axum's extractor pattern.
use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use jsonwebtoken::{decode, DecodingKey, Validation};
use uuid::Uuid;

use super::auth::{Claims, ErrorResponse};
use super::AppState;

/// Authenticated user extracted from JWT.
///
/// Use this as an extractor in route handlers to require authentication:
/// ```ignore
/// async fn handler(user: AuthUser) -> impl IntoResponse { ... }
/// ```
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Missing Authorization header".into(),
                    }),
                )
            })?;

        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid Authorization format".into(),
                }),
            )
        })?;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: format!("Invalid token: {e}"),
                }),
            )
        })?;

        let user_id = Uuid::parse_str(&token_data.claims.sub).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid user ID in token".into(),
                }),
            )
        })?;

        Ok(AuthUser { user_id })
    }
}

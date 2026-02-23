/// API Server for zk-vault.
///
/// The server is a thin routing layer — it never sees plaintext data.
/// All encryption/decryption happens client-side. The server:
/// - Routes encrypted blobs to/from storage backends
/// - Manages user accounts via OPAQUE (zero-knowledge auth)
/// - Tracks backup job metadata
/// - Broadcasts real-time status via WebSocket
pub mod auth;
pub mod middleware;
pub mod routes;
pub mod ws;

use std::sync::Arc;

use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::Database;

/// Shared application state available to all handlers.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool.
    pub db: Database,
    /// JWT signing secret.
    pub jwt_secret: String,
}

/// Build the Axum application with all routes and middleware.
pub fn build_app(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .merge(routes::health_routes())
        .merge(routes::auth_routes())
        .merge(routes::backup_routes())
        .merge(routes::source_routes())
        .merge(ws::ws_routes())
        .with_state(Arc::new(state))
        .layer(CompressionLayer::new())
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}

/// Start the API server.
pub async fn serve(state: AppState, addr: &str) -> crate::error::Result<()> {
    let app = build_app(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(crate::error::VaultError::Io)?;

    tracing::info!("zk-vault API server listening on {addr}");

    axum::serve(listener, app)
        .await
        .map_err(crate::error::VaultError::Io)?;

    Ok(())
}

/// WebSocket endpoint for real-time backup status updates.
///
/// Clients connect via WebSocket after authentication and receive
/// live progress updates for their backup/restore operations.
///
/// Message format (server → client):
/// ```json
/// {
///   "type": "backup_progress",
///   "job_id": "...",
///   "files_processed": 42,
///   "bytes_uploaded": 1048576,
///   "status": "in_progress"
/// }
/// ```
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde::Serialize;

use super::AppState;

/// WebSocket status message sent to clients.
#[derive(Debug, Serialize)]
struct StatusMessage {
    #[serde(rename = "type")]
    msg_type: String,
    job_id: Option<String>,
    files_processed: Option<i64>,
    bytes_uploaded: Option<i64>,
    status: String,
}

/// GET /ws — Upgrade to WebSocket connection.
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

/// Handle an individual WebSocket connection.
async fn handle_socket(mut socket: WebSocket) {
    // Send a welcome message
    let welcome = StatusMessage {
        msg_type: "connected".to_string(),
        job_id: None,
        files_processed: None,
        bytes_uploaded: None,
        status: "connected".to_string(),
    };

    if let Ok(msg) = serde_json::to_string(&welcome) {
        let _ = socket.send(Message::Text(msg.into())).await;
    }

    // Keep connection alive, process client messages
    while let Some(Ok(msg)) = socket.recv().await {
        match msg {
            Message::Text(text) => {
                // Echo acknowledgment for now.
                // In production: parse subscription requests,
                // filter updates by user's jobs, etc.
                let ack = serde_json::json!({
                    "type": "ack",
                    "received": text.as_str(),
                });
                let _ = socket.send(Message::Text(ack.to_string().into())).await;
            }
            Message::Ping(data) => {
                let _ = socket.send(Message::Pong(data)).await;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

pub fn ws_routes() -> Router<Arc<AppState>> {
    Router::new().route("/ws", get(ws_handler))
}

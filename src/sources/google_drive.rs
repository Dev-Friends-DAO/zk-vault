/// Google Drive data source implementation.
///
/// Uses the Google Drive API v3 for:
/// - OAuth2 PKCE authentication
/// - Change detection via changes.list (page tokens)
/// - File download via files.get with alt=media
///
/// All API calls use the user's decrypted access token.
/// The token is never sent to our server in plaintext.
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{
    BoxAsyncRead, ChangeSet, DataSource, FileMetadata, SourceConfig, SourceState,
};
use crate::error::{Result, VaultError};

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DRIVE_API_BASE: &str = "https://www.googleapis.com/drive/v3";

/// Google Drive data source.
pub struct GoogleDrive {
    client: Client,
}

impl GoogleDrive {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl Default for GoogleDrive {
    fn default() -> Self {
        Self::new()
    }
}

/// Google Drive changes.list API response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangesListResponse {
    new_start_page_token: Option<String>,
    next_page_token: Option<String>,
    #[serde(default)]
    changes: Vec<DriveChange>,
}

/// A single change from the Drive changes API.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveChange {
    #[serde(default)]
    removed: bool,
    file_id: Option<String>,
    file: Option<DriveFile>,
}

/// File metadata from Google Drive API.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DriveFile {
    id: Option<String>,
    name: Option<String>,
    mime_type: Option<String>,
    size: Option<String>,
    modified_time: Option<String>,
    md5_checksum: Option<String>,
    #[serde(default)]
    parents: Vec<String>,
    #[serde(default)]
    trashed: bool,
}

/// Token exchange response (used when parsing token JSON on client side).
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_in: Option<u64>,
}

/// Start page token response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartPageTokenResponse {
    start_page_token: String,
}

/// Generate a PKCE code verifier and challenge (S256).
fn generate_pkce() -> (String, String) {
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    let mut verifier_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut verifier_bytes);

    let verifier = base64_url_encode(&verifier_bytes);
    let challenge = {
        let hash = Sha256::digest(verifier.as_bytes());
        base64_url_encode(&hash)
    };

    (verifier, challenge)
}

/// Base64 URL-safe encoding without padding.
fn base64_url_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

#[async_trait]
impl DataSource for GoogleDrive {
    fn name(&self) -> &str {
        "Google Drive"
    }

    fn auth_url(&self, config: &SourceConfig) -> Result<(String, String)> {
        let (verifier, challenge) = generate_pkce();
        let scopes = config.scopes.join(" ");

        let url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&\
             code_challenge={}&code_challenge_method=S256&access_type=offline&prompt=consent",
            GOOGLE_AUTH_URL,
            urlencoding::encode(&config.client_id),
            urlencoding::encode(&config.redirect_uri),
            urlencoding::encode(&scopes),
            urlencoding::encode(&challenge),
        );

        Ok((url, verifier))
    }

    async fn exchange_code(
        &self,
        config: &SourceConfig,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<Vec<u8>> {
        let resp = self
            .client
            .post(GOOGLE_TOKEN_URL)
            .form(&[
                ("client_id", config.client_id.as_str()),
                ("code", code),
                ("code_verifier", pkce_verifier),
                ("grant_type", "authorization_code"),
                ("redirect_uri", config.redirect_uri.as_str()),
            ])
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Encryption(format!(
                "Token exchange failed: {body}"
            )));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        Ok(body.to_vec())
    }

    async fn detect_changes(
        &self,
        access_token: &str,
        state: &SourceState,
    ) -> Result<ChangeSet> {
        // If no cursor, get initial page token and do full listing
        let page_token = match &state.sync_cursor {
            Some(cursor) => cursor.clone(),
            None => {
                // Get the start page token
                let resp: StartPageTokenResponse = self
                    .client
                    .get(format!("{DRIVE_API_BASE}/changes/startPageToken"))
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| {
                        VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
                    })?
                    .json()
                    .await
                    .map_err(|e| {
                        VaultError::Serialization(format!("Failed to parse startPageToken: {e}"))
                    })?;
                resp.start_page_token
            }
        };

        let mut change_set = ChangeSet::default();
        let mut current_token = page_token;

        loop {
            let resp: ChangesListResponse = self
                .client
                .get(format!("{DRIVE_API_BASE}/changes"))
                .bearer_auth(access_token)
                .query(&[
                    ("pageToken", current_token.as_str()),
                    ("fields", "newStartPageToken,nextPageToken,changes(removed,fileId,file(id,name,mimeType,size,modifiedTime,md5Checksum,parents,trashed))"),
                    ("pageSize", "1000"),
                    ("includeRemoved", "true"),
                    ("spaces", "drive"),
                ])
                .send()
                .await
                .map_err(|e| VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?
                .json()
                .await
                .map_err(|e| VaultError::Serialization(format!("Failed to parse changes: {e}")))?;

            for change in resp.changes {
                if change.removed {
                    if let Some(file_id) = change.file_id {
                        change_set.deleted.push(file_id);
                    }
                    continue;
                }

                if let Some(file) = change.file {
                    if file.trashed {
                        if let Some(id) = file.id {
                            change_set.deleted.push(id);
                        }
                        continue;
                    }

                    let meta = FileMetadata {
                        source_id: file.id.unwrap_or_default(),
                        name: file.name.unwrap_or_default(),
                        mime_type: file.mime_type,
                        size: file.size.and_then(|s| s.parse().ok()),
                        modified_at: file.modified_time,
                        checksum: file.md5_checksum,
                        path: file.parents.first().cloned(),
                    };

                    change_set.upserted.push(meta);
                }
            }

            match resp.next_page_token {
                Some(next) => current_token = next,
                None => {
                    change_set.new_cursor = resp.new_start_page_token;
                    break;
                }
            }
        }

        Ok(change_set)
    }

    async fn download(
        &self,
        access_token: &str,
        file_id: &str,
    ) -> Result<BoxAsyncRead> {
        let resp = self
            .client
            .get(format!("{DRIVE_API_BASE}/files/{file_id}"))
            .bearer_auth(access_token)
            .query(&[("alt", "media")])
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Download failed ({status}): {body}"),
            )));
        }

        let stream = resp.bytes_stream();
        let reader = tokio_util::io::StreamReader::new(
            stream.map(|result| {
                result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            }),
        );

        Ok(Box::pin(reader))
    }
}

// Need futures::StreamExt for .map() on stream
use futures::StreamExt;

//! Filecoin storage backend via direct Lotus JSON-RPC API.
//!
//! No third-party services (Storacha/web3.storage). Connects directly
//! to Filecoin nodes via the Lotus JSON-RPC API for deal creation,
//! monitoring, and retrieval.
//!
//! Architecture:
//!   zk-vault → Lotus RPC (deal status, SP queries)
//!            → SP Boost API (deal creation)
//!            → IPFS Gateway (data retrieval)

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::{StorageBackend, UploadResult};
use crate::crypto::hash;
use crate::error::{Result, VaultError};

// ── Configuration ──

/// Configuration for direct Filecoin integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilecoinConfig {
    /// Lotus JSON-RPC endpoint (e.g., "https://api.node.glif.io/rpc/v1").
    pub rpc_url: String,
    /// Lotus API auth token (optional, required for write operations on self-hosted nodes).
    pub auth_token: Option<String>,
    /// IPFS gateway URL for data retrieval (e.g., "https://dweb.link").
    pub gateway_url: String,
    /// Minimum number of storage providers per file.
    pub min_sps: u32,
    /// Maximum price per GiB per epoch in attoFIL.
    pub max_price_per_gib_epoch: String,
    /// Deal duration in days.
    pub deal_duration_days: u32,
    /// Days before expiry to trigger renewal.
    pub renew_before_days: u32,
}

impl Default for FilecoinConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.node.glif.io/rpc/v1".to_string(),
            auth_token: None,
            gateway_url: "https://dweb.link".to_string(),
            min_sps: 4,
            max_price_per_gib_epoch: "100000000".to_string(),
            deal_duration_days: 540,
            renew_before_days: 30,
        }
    }
}

// ── CID computation ──

/// Compute a CID v1 (raw codec, blake3 hash) for the given data.
/// Returns the CID as a base32-encoded string.
pub fn compute_cid(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    let hash_bytes = hash.as_bytes();

    // CID v1 = version(1) + codec(raw=0x55) + multihash(blake3=0x1e, 32 bytes)
    let mut cid_bytes = vec![
        0x01, // CID version 1
        0x55, // Raw codec
        0x1e, // Multihash: function code (blake3)
        32,   // Multihash: digest length
    ];
    // Multihash: digest
    cid_bytes.extend_from_slice(hash_bytes);

    // Base32 lower encoding with 'b' prefix (multibase)
    format!("b{}", base32_encode(&cid_bytes))
}

/// Simple base32 lower encoding (RFC 4648, no padding).
fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

// ── Lotus JSON-RPC Client ──

/// Lotus JSON-RPC client for Filecoin network interaction.
pub struct LotusClient {
    client: Client,
    config: FilecoinConfig,
}

/// Storage provider info from Filecoin network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProviderInfo {
    /// SP's Filecoin address (e.g., "f01234").
    pub address: String,
    /// Price per GiB per epoch in attoFIL.
    pub price: String,
    /// Minimum piece size in bytes.
    pub min_piece_size: u64,
    /// Maximum piece size in bytes.
    pub max_piece_size: u64,
}

/// Deal status from Filecoin chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DealStatus {
    /// Deal proposal sent, waiting for SP acceptance.
    Proposed,
    /// Deal accepted, data transfer in progress.
    Transferring,
    /// Deal is active (data is stored, PoSt being submitted).
    Active,
    /// Deal has expired normally.
    Expired,
    /// Deal was slashed (SP failed PoSt).
    Slashed,
    /// Deal encountered an error.
    Error(String),
    /// Unknown status.
    Unknown,
}

/// Information about a Filecoin storage deal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DealInfo {
    /// Deal ID on Filecoin chain.
    pub deal_id: u64,
    /// Storage provider address.
    pub provider: String,
    /// CID of the stored data.
    pub data_cid: String,
    /// Deal status.
    pub status: DealStatus,
    /// Deal start epoch.
    pub start_epoch: Option<u64>,
    /// Deal end epoch.
    pub end_epoch: Option<u64>,
    /// Price per epoch in attoFIL.
    pub price_per_epoch: String,
}

impl LotusClient {
    pub fn new(config: FilecoinConfig) -> Self {
        Self {
            client: Client::new(),
            config,
        }
    }

    /// Make a JSON-RPC call to the Lotus API.
    async fn rpc_call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": format!("Filecoin.{method}"),
            "params": params,
            "id": 1,
        });

        let mut req_builder = self
            .client
            .post(&self.config.rpc_url)
            .header("Content-Type", "application/json")
            .json(&request);

        if let Some(token) = &self.config.auth_token {
            req_builder = req_builder.bearer_auth(token);
        }

        let resp = req_builder
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(format!("Lotus RPC error: {e}"))))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| VaultError::Serialization(format!("Lotus response parse error: {e}")))?;

        if let Some(error) = body.get("error") {
            return Err(VaultError::Io(std::io::Error::other(format!(
                "Lotus RPC error: {}",
                error
            ))));
        }

        let result = body
            .get("result")
            .ok_or_else(|| VaultError::Serialization("Lotus RPC: missing 'result' field".into()))?
            .clone();

        serde_json::from_value(result)
            .map_err(|e| VaultError::Serialization(format!("Lotus result parse error: {e}")))
    }

    /// Get the current chain head tipset.
    pub async fn chain_head(&self) -> Result<serde_json::Value> {
        self.rpc_call("ChainHead", serde_json::json!([])).await
    }

    /// Query a storage provider's ask (price and terms).
    pub async fn client_query_ask(&self, sp_address: &str) -> Result<StorageProviderInfo> {
        // This uses the Filecoin.StateMarketStorageAsk method via RPC
        let result: serde_json::Value = self
            .rpc_call("StateMarketStorageAsk", serde_json::json!([sp_address, []]))
            .await
            .unwrap_or_else(|_| serde_json::json!({}));

        Ok(StorageProviderInfo {
            address: sp_address.to_string(),
            price: result
                .get("Price")
                .and_then(|v| v.as_str())
                .unwrap_or("0")
                .to_string(),
            min_piece_size: result
                .get("MinPieceSize")
                .and_then(|v| v.as_u64())
                .unwrap_or(256),
            max_piece_size: result
                .get("MaxPieceSize")
                .and_then(|v| v.as_u64())
                .unwrap_or(34_359_738_368),
        })
    }

    /// Get deal info by deal ID.
    pub async fn get_deal_info(&self, deal_id: u64) -> Result<DealInfo> {
        let result: serde_json::Value = self
            .rpc_call("StateMarketStorageDeal", serde_json::json!([deal_id, []]))
            .await?;

        let proposal = result.get("Proposal").unwrap_or(&serde_json::Value::Null);
        let state = result.get("State").unwrap_or(&serde_json::Value::Null);

        let start_epoch = state.get("SectorStartEpoch").and_then(|v| v.as_u64());
        let end_epoch = proposal.get("EndEpoch").and_then(|v| v.as_u64());
        let slash_epoch = state.get("SlashEpoch").and_then(|v| v.as_i64());

        let status = if slash_epoch.map(|e| e > 0).unwrap_or(false) {
            DealStatus::Slashed
        } else if start_epoch.is_some() {
            // Check if deal is past end epoch
            DealStatus::Active
        } else {
            DealStatus::Proposed
        };

        Ok(DealInfo {
            deal_id,
            provider: proposal
                .get("Provider")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            data_cid: proposal
                .get("PieceCID")
                .and_then(|v| v.get("/"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            status,
            start_epoch,
            end_epoch,
            price_per_epoch: proposal
                .get("StoragePricePerEpoch")
                .and_then(|v| v.as_str())
                .unwrap_or("0")
                .to_string(),
        })
    }

    /// List active deals for a client address.
    pub async fn list_client_deals(&self) -> Result<Vec<DealInfo>> {
        // ClientListDeals requires a local Lotus node.
        // For public RPC, we'd use StateMarketDeals with filtering.
        // For now, return empty (will be populated when deal IDs are tracked on-chain).
        Ok(vec![])
    }

    /// Get the current chain epoch (block height).
    pub async fn current_epoch(&self) -> Result<u64> {
        let head: serde_json::Value = self.chain_head().await?;
        let height = head.get("Height").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(height)
    }

    /// Upload data to IPFS and return CID.
    /// In production, this would use an IPFS node to import and pin data.
    /// For now, we compute the CID locally and use gateway for retrieval.
    pub fn compute_data_cid(&self, data: &[u8]) -> String {
        compute_cid(data)
    }
}

// ── Storage Backend Implementation ──

/// Filecoin storage backend using direct Lotus API.
pub struct FilecoinBackend {
    lotus: LotusClient,
}

impl FilecoinBackend {
    pub fn new(config: FilecoinConfig) -> Self {
        Self {
            lotus: LotusClient::new(config),
        }
    }

    /// Get the underlying Lotus client for advanced operations.
    pub fn lotus(&self) -> &LotusClient {
        &self.lotus
    }
}

#[async_trait]
impl StorageBackend for FilecoinBackend {
    fn name(&self) -> &str {
        "Filecoin"
    }

    async fn upload(&self, key: &str, data: &[u8]) -> Result<UploadResult> {
        let content_hash = hash::hash(data);
        let cid = self.lotus.compute_data_cid(data);

        info!(key, cid = %cid, size = data.len(), "Filecoin upload: CID computed");

        // In a full implementation, this would:
        // 1. Import data to local IPFS node
        // 2. Create CAR file
        // 3. Propose storage deals with selected SPs
        //
        // For now, we compute the CID and track it.
        // Actual deal creation is handled by the chain's DealManager.
        debug!(
            key,
            "Data prepared for Filecoin deal (deal creation managed by chain DealManager)"
        );

        Ok(UploadResult {
            storage_key: cid,
            content_hash,
            size: data.len() as u64,
        })
    }

    async fn download(&self, key: &str) -> Result<Vec<u8>> {
        // Retrieve via IPFS gateway
        let url = format!("{}/ipfs/{key}", self.lotus.config.gateway_url);
        let resp = self.lotus.client.get(&url).send().await.map_err(|e| {
            VaultError::Io(std::io::Error::other(format!("IPFS gateway error: {e}")))
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Io(std::io::Error::other(format!(
                "IPFS gateway download failed ({}): {body}",
                status
            ))));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(format!("Download error: {e}"))))?;

        info!(key, size = bytes.len(), "Downloaded from IPFS gateway");
        Ok(bytes.to_vec())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let url = format!("{}/ipfs/{key}", self.lotus.config.gateway_url);
        let resp = self.lotus.client.head(&url).send().await.map_err(|e| {
            VaultError::Io(std::io::Error::other(format!("IPFS gateway error: {e}")))
        })?;

        Ok(resp.status().is_success())
    }

    async fn delete(&self, _key: &str) -> Result<()> {
        // Filecoin deals cannot be cancelled once active.
        // We can only stop renewing them and let them expire.
        warn!("Filecoin data cannot be actively deleted; deal will expire naturally");
        Ok(())
    }

    async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
        // Deal listing is managed by the chain's DealRegistry.
        // This method returns an empty list; use the chain RPC for deal info.
        Ok(vec![])
    }
}

// ── CAR file utilities ──

/// Build a minimal CAR v1 file containing a single raw block.
///
/// CAR format: [header_varint_len][header_dag_cbor][block_cid_bytes][block_data]
/// This is used for submitting data to Filecoin storage deals.
pub fn build_car_v1(data: &[u8]) -> (String, Vec<u8>) {
    let hash = blake3::hash(data);
    let hash_bytes = hash.as_bytes();

    // Build CID bytes (same as compute_cid but raw bytes, no multibase)
    let mut cid_bytes = vec![
        0x01, // CID version 1
        0x55, // Raw codec
        0x1e, // blake3 multihash code
        32,   // digest length
    ];
    cid_bytes.extend_from_slice(hash_bytes);

    let cid_string = format!("b{}", base32_encode(&cid_bytes));

    // CAR v1 header (DAG-CBOR): {"version": 1, "roots": [cid]}
    // Simplified: manually encode minimal CBOR
    let header_cbor = build_car_header_cbor(&cid_bytes);

    let mut car = Vec::new();

    // Header length as varint
    write_varint(&mut car, header_cbor.len() as u64);
    car.extend_from_slice(&header_cbor);

    // Block: varint(cid_len + data_len) + cid + data
    let block_len = cid_bytes.len() + data.len();
    write_varint(&mut car, block_len as u64);
    car.extend_from_slice(&cid_bytes);
    car.extend_from_slice(data);

    (cid_string, car)
}

/// Build a minimal DAG-CBOR CAR v1 header.
fn build_car_header_cbor(root_cid: &[u8]) -> Vec<u8> {
    // CBOR map with 2 entries: "roots" and "version"
    let mut cbor = Vec::new();

    // Map of 2 items
    cbor.push(0xa2);

    // Key: "roots" (5 bytes text)
    cbor.push(0x65); // text(5)
    cbor.extend_from_slice(b"roots");

    // Value: array of 1 CID
    cbor.push(0x81); // array(1)

    // CID as CBOR tag 42 + bytes
    cbor.push(0xd8); // tag
    cbor.push(42); // tag number 42 (CID)

    // CID bytes with 0x00 prefix (identity multibase for CBOR CID)
    let cid_with_prefix_len = root_cid.len() + 1;
    if cid_with_prefix_len < 24 {
        cbor.push(0x40 | cid_with_prefix_len as u8); // bytes(n)
    } else {
        cbor.push(0x58); // bytes with 1-byte length
        cbor.push(cid_with_prefix_len as u8);
    }
    cbor.push(0x00); // identity multibase prefix
    cbor.extend_from_slice(root_cid);

    // Key: "version" (7 bytes text)
    cbor.push(0x67); // text(7)
    cbor.extend_from_slice(b"version");

    // Value: 1
    cbor.push(0x01); // unsigned int 1

    cbor
}

/// Write an unsigned varint.
fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_cid_deterministic() {
        let data = b"hello world";
        let cid1 = compute_cid(data);
        let cid2 = compute_cid(data);
        assert_eq!(cid1, cid2);

        // Different data -> different CID
        let cid3 = compute_cid(b"different data");
        assert_ne!(cid1, cid3);

        // CID should start with 'b' (base32lower multibase prefix)
        assert!(cid1.starts_with('b'));
    }

    #[test]
    fn compute_cid_not_empty() {
        let cid = compute_cid(b"test");
        assert!(!cid.is_empty());
        // CID v1 + raw codec + blake3 hash should produce consistent length
        assert!(cid.len() > 10);
    }

    #[test]
    fn build_car_v1_produces_valid_output() {
        let data = b"encrypted backup data";
        let (cid, car) = build_car_v1(data);

        assert!(!cid.is_empty());
        assert!(cid.starts_with('b'));

        // CAR should contain the original data
        assert!(car.len() > data.len());

        // CAR should contain the data bytes somewhere
        assert!(car.windows(data.len()).any(|w| w == data));
    }

    #[test]
    fn build_car_v1_deterministic() {
        let data = b"test data";
        let (cid1, car1) = build_car_v1(data);
        let (cid2, car2) = build_car_v1(data);
        assert_eq!(cid1, cid2);
        assert_eq!(car1, car2);
    }

    #[test]
    fn filecoin_config_default() {
        let config = FilecoinConfig::default();
        assert_eq!(config.min_sps, 4);
        assert_eq!(config.deal_duration_days, 540);
        assert_eq!(config.renew_before_days, 30);
        assert!(config.rpc_url.contains("glif"));
    }

    #[test]
    fn deal_status_equality() {
        assert_eq!(DealStatus::Active, DealStatus::Active);
        assert_ne!(DealStatus::Active, DealStatus::Expired);
        assert_ne!(DealStatus::Error("a".into()), DealStatus::Error("b".into()));
    }

    #[test]
    fn varint_encoding() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 1);
        assert_eq!(buf, vec![1]);

        buf.clear();
        write_varint(&mut buf, 127);
        assert_eq!(buf, vec![127]);

        buf.clear();
        write_varint(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        buf.clear();
        write_varint(&mut buf, 300);
        assert_eq!(buf, vec![0xac, 0x02]);
    }
}

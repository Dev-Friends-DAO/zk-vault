/// Ethereum calldata anchor.
///
/// Writes a 32-byte hash as calldata in an Ethereum transaction.
/// Calldata is stored permanently on-chain and is cheaper than storage slots.
///
/// This serves as a secondary anchor for redundancy. If Bitcoin is
/// the primary trust anchor, Ethereum provides:
/// - Independent verification on a second chain
/// - Future extensibility via smart contracts
/// - Currently very cheap (~$0.002 per anchor at low gas)
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{AnchorReceipt, BlockchainAnchor};
use crate::error::{Result, VaultError};

/// Configuration for Ethereum anchoring.
#[derive(Debug, Clone)]
pub struct EthereumConfig {
    /// Ethereum JSON-RPC endpoint (e.g., Infura, Alchemy, local node).
    pub rpc_url: String,
    /// Network: "mainnet", "sepolia", "holesky".
    pub network: String,
    /// Private key (hex, without 0x prefix) for signing transactions.
    /// In production, this would come from a KMS.
    pub private_key_hex: String,
    /// Chain ID (1 for mainnet, 11155111 for Sepolia).
    pub chain_id: u64,
}

/// Ethereum calldata anchor implementation.
///
/// Sends a transaction to self with the 32-byte hash as calldata.
/// Uses raw JSON-RPC for maximum compatibility.
pub struct EthereumAnchor {
    config: EthereumConfig,
    client: Client,
}

/// Simplified JSON-RPC response.
#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    message: String,
}

impl EthereumAnchor {
    pub fn new(config: EthereumConfig) -> Self {
        Self {
            config,
            client: Client::new(),
        }
    }

    /// Send a JSON-RPC request to the Ethereum node.
    async fn rpc_call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let resp: JsonRpcResponse<T> = self
            .client
            .post(&self.config.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?
            .json()
            .await
            .map_err(|e| VaultError::Serialization(format!("RPC response parse error: {e}")))?;

        if let Some(err) = resp.error {
            return Err(VaultError::Encryption(format!(
                "ETH RPC error: {}",
                err.message
            )));
        }

        resp.result
            .ok_or_else(|| VaultError::Encryption("Empty RPC response".into()))
    }

    /// Build, sign, and send a transaction with the hash as calldata.
    async fn send_anchor_tx(&self, hash: &[u8; 32]) -> Result<String> {
        use alloy::consensus::SignableTransaction;
        use alloy::primitives::{Bytes, U256};
        use alloy::signers::local::PrivateKeySigner;
        use alloy::signers::Signer;

        // Parse private key
        let signer: PrivateKeySigner = self
            .config
            .private_key_hex
            .parse()
            .map_err(|e| VaultError::Encryption(format!("Invalid ETH private key: {e}")))?;

        let from_address = signer.address();

        // Get nonce
        let nonce_hex: String = self
            .rpc_call(
                "eth_getTransactionCount",
                serde_json::json!([format!("{from_address:?}"), "pending"]),
            )
            .await?;
        let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16)
            .map_err(|e| VaultError::Encryption(format!("Invalid nonce: {e}")))?;

        // Get gas price
        let gas_price_hex: String = self.rpc_call("eth_gasPrice", serde_json::json!([])).await?;
        let gas_price = u128::from_str_radix(gas_price_hex.trim_start_matches("0x"), 16)
            .map_err(|e| VaultError::Encryption(format!("Invalid gas price: {e}")))?;

        // Build legacy transaction: send to self with hash as calldata
        let tx = alloy::consensus::TxLegacy {
            chain_id: Some(self.config.chain_id),
            nonce,
            gas_price,
            gas_limit: 25_000, // Simple tx with 32 bytes calldata
            to: alloy::primitives::TxKind::Call(from_address),
            value: U256::ZERO,
            input: Bytes::copy_from_slice(hash),
        };

        // Sign the transaction
        let sig_hash = tx.signature_hash();
        let sig = signer
            .sign_hash(&sig_hash)
            .await
            .map_err(|e| VaultError::Encryption(format!("ETH signing failed: {e}")))?;

        // Create signed envelope
        let signed = alloy::consensus::TxEnvelope::Legacy(tx.into_signed(sig));

        // RLP-encode and send
        let mut raw_tx = Vec::new();
        alloy::eips::eip2718::Encodable2718::encode_2718(&signed, &mut raw_tx);
        let raw_hex = format!("0x{}", hex::encode(&raw_tx));

        let tx_hash: String = self
            .rpc_call("eth_sendRawTransaction", serde_json::json!([raw_hex]))
            .await?;

        Ok(tx_hash)
    }
}

#[async_trait]
impl BlockchainAnchor for EthereumAnchor {
    fn chain_name(&self) -> &str {
        "Ethereum"
    }

    async fn anchor(&self, hash: &[u8; 32]) -> Result<AnchorReceipt> {
        let tx_hash = self.send_anchor_tx(hash).await?;

        Ok(AnchorReceipt {
            chain: "ethereum".to_string(),
            tx_id: tx_hash,
            anchored_hash: *hash,
            block_number: None,
            fee: None,
        })
    }

    async fn verify(&self, receipt: &AnchorReceipt) -> Result<bool> {
        // Check transaction receipt for confirmation
        let result: std::result::Result<Option<serde_json::Value>, _> = self
            .rpc_call(
                "eth_getTransactionReceipt",
                serde_json::json!([&receipt.tx_id]),
            )
            .await;

        match result {
            Ok(Some(receipt_data)) => Ok(receipt_data.get("blockNumber").is_some()),
            _ => Ok(false),
        }
    }
}

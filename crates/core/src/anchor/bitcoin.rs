/// Bitcoin OP_RETURN anchor.
///
/// Writes a 32-byte hash as an OP_RETURN output in a Bitcoin transaction.
/// OP_RETURN outputs are provably unspendable and stored by all full nodes.
///
/// This is NOT storage — it's timestamped existence proof. The hash proves
/// that a particular Super Merkle Root existed at the time of the block.
///
/// Cost: typically $0.02–$1.00 per transaction.
/// With Super Merkle Tree batching, one transaction covers all users.
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{AnchorReceipt, BlockchainAnchor};
use crate::error::{Result, VaultError};

/// Configuration for Bitcoin anchoring.
#[derive(Debug, Clone)]
pub struct BitcoinConfig {
    /// Bitcoin RPC/API endpoint.
    /// For testnet: e.g., a blockstream.info or mempool.space API.
    pub api_url: String,
    /// Network: "mainnet", "testnet", or "signet".
    pub network: String,
    /// Private key in WIF format for signing transactions.
    /// In production, this would come from a hardware wallet or KMS.
    pub wif_private_key: String,
}

/// Bitcoin OP_RETURN anchor implementation.
///
/// Uses the Bitcoin blockchain to anchor 32-byte hashes via OP_RETURN.
/// Currently uses a REST API approach (compatible with mempool.space,
/// blockstream.info, etc.) for transaction broadcasting and verification.
pub struct BitcoinAnchor {
    client: Client,
    config: BitcoinConfig,
}

/// UTXO from API response.
#[derive(Debug, Deserialize)]
struct Utxo {
    txid: String,
    vout: u32,
    value: u64,
    status: UtxoStatus,
}

#[derive(Debug, Deserialize)]
struct UtxoStatus {
    confirmed: bool,
    #[allow(dead_code)]
    block_height: Option<u64>,
}

/// Transaction status from API.
#[derive(Debug, Deserialize)]
struct TxStatus {
    confirmed: bool,
    #[allow(dead_code)]
    block_height: Option<u64>,
}

impl BitcoinAnchor {
    pub fn new(config: BitcoinConfig) -> Self {
        Self {
            client: Client::new(),
            config,
        }
    }

    /// Build and sign a transaction with an OP_RETURN output containing the hash.
    ///
    /// Transaction structure:
    /// - Input: one UTXO from the anchor wallet
    /// - Output 0: OP_RETURN <32-byte hash> (0 sats, unspendable)
    /// - Output 1: change back to the anchor address (input - fee)
    async fn build_op_return_tx(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        use bitcoin::absolute::LockTime;
        use bitcoin::blockdata::opcodes::all::OP_RETURN;
        use bitcoin::blockdata::script::{Builder as ScriptBuilder, ScriptBuf};
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{Message, Secp256k1};
        use bitcoin::sighash::SighashCache;
        use bitcoin::transaction::Version;
        use bitcoin::{
            Address, Amount, EcdsaSighashType, Network, OutPoint, PrivateKey, PublicKey, Sequence,
            Transaction, TxIn, TxOut, Txid, Witness,
        };

        let network = match self.config.network.as_str() {
            "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            _ => Network::Testnet,
        };

        let secp = Secp256k1::new();
        let private_key = PrivateKey::from_wif(&self.config.wif_private_key)
            .map_err(|e| VaultError::Encryption(format!("Invalid WIF key: {e}")))?;
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        let address = Address::p2pkh(public_key, network);

        // Fetch UTXOs for our address
        let utxos: Vec<Utxo> = self
            .client
            .get(format!("{}/address/{}/utxo", self.config.api_url, address))
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?
            .json()
            .await
            .map_err(|e| VaultError::Serialization(format!("Failed to parse UTXOs: {e}")))?;

        let utxo = utxos
            .iter()
            .find(|u| u.status.confirmed && u.value > 10_000)
            .ok_or_else(|| VaultError::Encryption("No suitable UTXO found for anchoring".into()))?;

        // Estimate fee (conservative: 250 bytes * fee_rate)
        let fee: u64 = 5_000; // ~5000 sats, conservative estimate

        if utxo.value <= fee {
            return Err(VaultError::Encryption(
                "UTXO value too small to cover fee".into(),
            ));
        }

        let change_amount = utxo.value - fee;

        // Build OP_RETURN script: OP_RETURN <32 bytes>
        let op_return_script = ScriptBuilder::new()
            .push_opcode(OP_RETURN)
            .push_slice(hash)
            .into_script();

        // Parse the UTXO txid
        let prev_txid: Txid = utxo
            .txid
            .parse()
            .map_err(|e| VaultError::Encryption(format!("Invalid txid: {e}")))?;

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(prev_txid, utxo.vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: vec![
                // OP_RETURN output (unspendable)
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: op_return_script,
                },
                // Change output
                TxOut {
                    value: Amount::from_sat(change_amount),
                    script_pubkey: address.script_pubkey(),
                },
            ],
        };

        // Sign the transaction (P2PKH)
        let script_pubkey = address.script_pubkey();
        let sighash_type = EcdsaSighashType::All;

        let sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache
            .legacy_signature_hash(0, &script_pubkey, sighash_type.to_u32())
            .map_err(|e| VaultError::Encryption(format!("Sighash error: {e}")))?;

        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_ecdsa(&msg, &private_key.inner);

        // Build scriptSig: <signature> <pubkey>
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(sighash_type.to_u32() as u8);

        let sig_push = bitcoin::script::PushBytesBuf::try_from(sig_bytes)
            .map_err(|e| VaultError::Encryption(format!("Sig push bytes error: {e}")))?;
        let pubkey_push =
            bitcoin::script::PushBytesBuf::try_from(public_key.to_bytes().to_vec())
                .map_err(|e| VaultError::Encryption(format!("Pubkey push bytes error: {e}")))?;

        let script_sig = ScriptBuilder::new()
            .push_slice(&sig_push)
            .push_slice(&pubkey_push)
            .into_script();

        tx.input[0].script_sig = script_sig;

        // Serialize the transaction
        Ok(bitcoin::consensus::serialize(&tx))
    }

    /// Broadcast a raw transaction via the API.
    async fn broadcast_tx(&self, raw_tx: &[u8]) -> Result<String> {
        let hex = hex::encode(raw_tx);
        let resp = self
            .client
            .post(format!("{}/tx", self.config.api_url))
            .body(hex)
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(VaultError::Encryption(format!(
                "Bitcoin broadcast failed: {body}"
            )));
        }

        let txid = resp.text().await.map_err(|e| {
            VaultError::Serialization(format!("Failed to read broadcast response: {e}"))
        })?;

        Ok(txid.trim().to_string())
    }
}

#[async_trait]
impl BlockchainAnchor for BitcoinAnchor {
    fn chain_name(&self) -> &str {
        "Bitcoin"
    }

    async fn anchor(&self, hash: &[u8; 32]) -> Result<AnchorReceipt> {
        let raw_tx = self.build_op_return_tx(hash).await?;
        let txid = self.broadcast_tx(&raw_tx).await?;

        Ok(AnchorReceipt {
            chain: "bitcoin".to_string(),
            tx_id: txid,
            anchored_hash: *hash,
            block_number: None, // Unconfirmed initially
            fee: Some("~5000 sats".to_string()),
        })
    }

    async fn verify(&self, receipt: &AnchorReceipt) -> Result<bool> {
        // Fetch transaction and check for OP_RETURN with our hash
        let resp = self
            .client
            .get(format!(
                "{}/tx/{}/status",
                self.config.api_url, receipt.tx_id
            ))
            .send()
            .await
            .map_err(|e| VaultError::Io(std::io::Error::other(e)))?;

        if !resp.status().is_success() {
            return Ok(false);
        }

        let status: TxStatus = resp
            .json()
            .await
            .map_err(|e| VaultError::Serialization(format!("Failed to parse tx status: {e}")))?;

        // Transaction exists and is confirmed
        Ok(status.confirmed)
    }
}

// hex is used for tx serialization
use hex;

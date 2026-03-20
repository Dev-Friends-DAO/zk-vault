//! zk-vault chain node: Malachite BFT consensus for Mode B/C.
//!
//! This crate contains:
//! - Block and transaction types ([`types`])
//! - Malachite BFT Context implementation ([`consensus`])
//! - Chain state machine and FileRegistry ([`state`])
//! - Transaction mempool and block builder ([`mempool`])
//! - Node actor / consensus driver ([`node`])
//! - JSON-RPC server ([`rpc`])

pub mod blob_store;
pub mod blob_sync;
pub mod consensus;
pub mod mempool;
pub mod node;
pub mod p2p;
pub mod rpc;
pub mod state;
pub mod storage;
pub mod types;

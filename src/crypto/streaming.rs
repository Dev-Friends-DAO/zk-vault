/// Streaming (chunked) AEAD encryption for large files.
///
/// Files larger than 64 MiB are split into 64 KiB chunks.
/// Each chunk is encrypted with the same key but a unique nonce:
///   chunk_nonce = base_nonce XOR chunk_index
/// The final chunk has "final" in its AAD to prevent truncation attacks.
use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::sensitive::SensitiveBytes32;
use crate::error::{Result, VaultError};

pub const CHUNK_SIZE: usize = 64 * 1024; // 64 KiB

/// Derive a per-chunk nonce by XORing the base nonce with the chunk index.
fn chunk_nonce(base: &[u8; NONCE_LEN], index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *base;
    let idx_bytes = index.to_le_bytes();
    for i in 0..8 {
        nonce[i] ^= idx_bytes[i];
    }
    nonce
}

/// Encrypt data in chunks. Returns (base_nonce, concatenated_encrypted_chunks).
/// Each chunk: [chunk_len(4 LE) | encrypted_chunk_with_tag]
pub fn encrypt_chunked(
    key: &SensitiveBytes32,
    plaintext: &[u8],
    base_aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let base_nonce = aead::generate_nonce();
    let total_chunks = (plaintext.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let total_chunks = if total_chunks == 0 { 1 } else { total_chunks };

    let mut output = Vec::new();

    for i in 0..total_chunks {
        let start = i * CHUNK_SIZE;
        let end = std::cmp::min(start + CHUNK_SIZE, plaintext.len());
        let chunk = &plaintext[start..end];
        let is_final = i == total_chunks - 1;

        // Build AAD: base_aad | chunk_index(8 LE) | is_final(1)
        let mut chunk_aad = Vec::with_capacity(base_aad.len() + 9);
        chunk_aad.extend_from_slice(base_aad);
        chunk_aad.extend_from_slice(&(i as u64).to_le_bytes());
        chunk_aad.push(if is_final { 1 } else { 0 });

        let nonce = chunk_nonce(&base_nonce, i as u64);
        let encrypted = aead::encrypt_with_nonce(key, &nonce, chunk, &chunk_aad)?;

        // Write chunk length and encrypted data
        let chunk_len = encrypted.len() as u32;
        output.extend_from_slice(&chunk_len.to_le_bytes());
        output.extend_from_slice(&encrypted);
    }

    Ok((base_nonce, output))
}

/// Decrypt chunked data.
pub fn decrypt_chunked(
    key: &SensitiveBytes32,
    base_nonce: &[u8; NONCE_LEN],
    data: &[u8],
    base_aad: &[u8],
) -> Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    let mut offset = 0;
    let mut chunk_index: u64 = 0;

    while offset < data.len() {
        if offset + 4 > data.len() {
            return Err(VaultError::Decryption("Truncated chunk header".into()));
        }
        let chunk_len =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if offset + chunk_len > data.len() {
            return Err(VaultError::Decryption("Truncated chunk data".into()));
        }
        let encrypted_chunk = &data[offset..offset + chunk_len];
        offset += chunk_len;

        let is_final = offset >= data.len();

        // Reconstruct AAD
        let mut chunk_aad = Vec::with_capacity(base_aad.len() + 9);
        chunk_aad.extend_from_slice(base_aad);
        chunk_aad.extend_from_slice(&chunk_index.to_le_bytes());
        chunk_aad.push(if is_final { 1 } else { 0 });

        let nonce = chunk_nonce(base_nonce, chunk_index);
        let decrypted = aead::decrypt(key, &nonce, encrypted_chunk, &chunk_aad)?;

        plaintext.extend_from_slice(&decrypted);
        chunk_index += 1;
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::generate_key;

    #[test]
    fn test_chunked_roundtrip_small() {
        let key = generate_key();
        let data = b"small data that fits in one chunk";
        let aad = b"test";

        let (nonce, encrypted) = encrypt_chunked(&key, data, aad).unwrap();
        let decrypted = decrypt_chunked(&key, &nonce, &encrypted, aad).unwrap();

        assert_eq!(&decrypted, data);
    }

    #[test]
    fn test_chunked_roundtrip_multi_chunk() {
        let key = generate_key();
        // 3.5 chunks worth of data
        let data = vec![0xAB; CHUNK_SIZE * 3 + CHUNK_SIZE / 2];
        let aad = b"multi-chunk";

        let (nonce, encrypted) = encrypt_chunked(&key, &data, aad).unwrap();
        let decrypted = decrypt_chunked(&key, &nonce, &encrypted, aad).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_chunked_empty() {
        let key = generate_key();
        let (nonce, encrypted) = encrypt_chunked(&key, b"", b"").unwrap();
        let decrypted = decrypt_chunked(&key, &nonce, &encrypted, b"").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_chunked_exact_chunk_boundary() {
        let key = generate_key();
        let data = vec![0xFF; CHUNK_SIZE * 2]; // exactly 2 chunks
        let aad = b"boundary";

        let (nonce, encrypted) = encrypt_chunked(&key, &data, aad).unwrap();
        let decrypted = decrypt_chunked(&key, &nonce, &encrypted, aad).unwrap();

        assert_eq!(decrypted, data);
    }
}

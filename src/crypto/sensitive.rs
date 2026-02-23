/// Wrappers for sensitive key material that is automatically zeroized on drop.
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte sensitive value that is zeroized when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveBytes32([u8; 32]);

impl SensitiveBytes32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }
}

impl AsRef<[u8]> for SensitiveBytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A variable-length sensitive buffer that is zeroized when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveVec(Vec<u8>);

impl SensitiveVec {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for SensitiveVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_bytes32() {
        let key = SensitiveBytes32::new([0xAA; 32]);
        assert_eq!(key.as_bytes(), &[0xAA; 32]);
    }

    #[test]
    fn test_sensitive_bytes32_from_slice() {
        assert!(SensitiveBytes32::from_slice(&[0u8; 32]).is_some());
        assert!(SensitiveBytes32::from_slice(&[0u8; 16]).is_none());
    }

    #[test]
    fn test_sensitive_vec() {
        let v = SensitiveVec::new(vec![1, 2, 3]);
        assert_eq!(v.len(), 3);
        assert!(!v.is_empty());
    }
}

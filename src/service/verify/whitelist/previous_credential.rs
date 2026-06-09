#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct PreviousCredentialVerifier {
    store: Arc<RwLock<HashMap<String, String>>>,
}

impl PreviousCredentialVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, user_id: &str, credential_hash: &str) {
        self.store
            .write()
            .await
            .insert(user_id.to_string(), credential_hash.to_string());
    }

    pub async fn verify(&self, user_id: &str, credential_hash: &str) -> Result<bool> {
        let store = self.store.read().await;
        if let Some(stored) = store.get(user_id) {
            let a = stored.as_bytes();
            let b = credential_hash.as_bytes();
            if a.len() != b.len() {
                return Ok(false);
            }
            let mut diff = 0u8;
            for (x, y) in a.iter().zip(b.iter()) {
                diff |= x ^ y;
            }
            return Ok(diff == 0);
        }
        Ok(false)
    }
}

impl Default for PreviousCredentialVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_verify() {
        let v = PreviousCredentialVerifier::new();
        v.register("user-1", "hash-of-old-password").await;
        assert!(v.verify("user-1", "hash-of-old-password").await.unwrap());
    }

    #[tokio::test]
    async fn test_wrong_hash() {
        let v = PreviousCredentialVerifier::new();
        v.register("user-1", "hash-of-old-password").await;
        assert!(!v.verify("user-1", "wrong-hash").await.unwrap());
    }

    #[tokio::test]
    async fn test_unknown_user() {
        let v = PreviousCredentialVerifier::new();
        assert!(!v.verify("unknown", "any-hash").await.unwrap());
    }
}

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use async_trait::async_trait;
use rand::Rng;

use super::Credential;

pub struct OneTimeCredential {
    token: String,
    used: bool,
}

impl OneTimeCredential {
    #[must_use]
    pub fn new(token: String) -> Self {
        Self { token, used: false }
    }

    pub fn generate() -> Self {
        let token = Self::generate_token(32);
        Self { token, used: false }
    }

    pub fn is_used(&self) -> bool {
        self.used
    }

    fn generate_token(len: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        (0..len)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                char::from(CHARSET[idx])
            })
            .collect()
    }
}

impl Credential for OneTimeCredential {
    fn verify(&self, token: &str) -> Result<bool> {
        if self.used {
            return Ok(false);
        }
        let a = self.token.as_bytes();
        let b = token.as_bytes();
        if a.len() != b.len() {
            return Ok(false);
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        Ok(diff == 0)
    }
}

struct PendingToken {
    #[allow(dead_code)]
    token_hash: String,
    expires_at: Instant,
}

pub struct InMemoryOneTimeStore {
    tokens: Arc<RwLock<HashMap<String, PendingToken>>>,
}

impl InMemoryOneTimeStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryOneTimeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait OneTimeStore: Send + Sync {
    async fn claim(&self, token: &str) -> Result<bool>;
    async fn issue(&self, ttl_secs: u64) -> Result<String>;
}

#[async_trait]
impl OneTimeStore for InMemoryOneTimeStore {
    async fn claim(&self, token: &str) -> Result<bool> {
        let mut tokens = self.tokens.write().await;
        if let Some(pending) = tokens.remove(token) {
            if Instant::now() < pending.expires_at {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn issue(&self, ttl_secs: u64) -> Result<String> {
        let cred = OneTimeCredential::generate();
        let token = cred.token.clone();
        let mut tokens = self.tokens.write().await;
        tokens.insert(
            token.clone(),
            PendingToken {
                token_hash: token.clone(),
                expires_at: Instant::now() + Duration::from_secs(ttl_secs),
            },
        );
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify() {
        let cred = OneTimeCredential::generate();
        let token = cred.token.clone();
        assert!(!cred.is_used());
        assert!(cred.verify(&token).unwrap());
    }

    #[test]
    fn test_wrong_token() {
        let cred = OneTimeCredential::generate();
        assert!(!cred.verify("wrong-token").unwrap());
    }

    #[tokio::test]
    async fn test_store_issue_and_claim() {
        let store = InMemoryOneTimeStore::new();
        let token = store.issue(300).await.unwrap();
        assert!(!token.is_empty());
        assert!(store.claim(&token).await.unwrap());
        assert!(!store.claim(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_store_claim_unknown_token() {
        let store = InMemoryOneTimeStore::new();
        assert!(!store.claim("nonexistent").await.unwrap());
    }
}

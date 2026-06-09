#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use rand::Rng;

pub struct EmailVerifier {
    sender: String,
    codes: Arc<RwLock<HashMap<String, PendingCode>>>,
}

struct PendingCode {
    code: String,
    expires_at: std::time::Instant,
}

impl EmailVerifier {
    #[must_use]
    pub fn new(sender: String) -> Self {
        Self {
            sender,
            codes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn send_code(&self, address: &str, code: &str) -> Result<()> {
        let pending = PendingCode {
            code: code.to_string(),
            expires_at: std::time::Instant::now() + Duration::from_secs(300),
        };
        self.codes
            .write()
            .await
            .insert(address.to_string(), pending);
        tracing::debug!(
            target: "kirino::verify::email",
            from = %self.sender,
            to = %address,
            "email verification code would be sent"
        );
        Ok(())
    }

    pub async fn verify_code(&self, address: &str, code: &str) -> Result<bool> {
        let mut codes = self.codes.write().await;
        if let Some(pending) = codes.remove(address) {
            if std::time::Instant::now() < pending.expires_at {
                let a = pending.code.as_bytes();
                let b = code.as_bytes();
                if a.len() != b.len() {
                    return Ok(false);
                }
                let mut diff = 0u8;
                for (x, y) in a.iter().zip(b.iter()) {
                    diff |= x ^ y;
                }
                return Ok(diff == 0);
            }
        }
        Ok(false)
    }

    pub fn generate_code(len: usize) -> String {
        let mut rng = rand::thread_rng();
        (0..len)
            .map(|_| rng.gen_range(b'0'..=b'9') as char)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_send_and_verify() {
        let v = EmailVerifier::new("noreply@example.com".to_string());
        let code = EmailVerifier::generate_code(6);
        v.send_code("user@example.com", &code).await.unwrap();
        assert!(v.verify_code("user@example.com", &code).await.unwrap());
    }

    #[tokio::test]
    async fn test_wrong_code() {
        let v = EmailVerifier::new("noreply@example.com".to_string());
        v.send_code("user@example.com", "123456").await.unwrap();
        assert!(!v.verify_code("user@example.com", "000000").await.unwrap());
    }

    #[tokio::test]
    async fn test_unknown_address() {
        let v = EmailVerifier::new("noreply@example.com".to_string());
        assert!(!v
            .verify_code("unknown@example.com", "123456")
            .await
            .unwrap());
    }

    #[test]
    fn test_generate_code_length() {
        let code = EmailVerifier::generate_code(6);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}

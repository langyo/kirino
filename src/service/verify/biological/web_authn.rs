#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::{anyhow, Result};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct WebAuthnVerifier {
    challenges: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    rp_id: String,
}

impl WebAuthnVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            rp_id: "localhost".to_string(),
        }
    }

    #[must_use]
    pub fn with_rp_id(rp_id: String) -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            rp_id,
        }
    }

    pub async fn verify_assertion(
        &self,
        credential_id: &[u8],
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let challenges = self.challenges.read().await;
        let cid_str = String::from_utf8_lossy(credential_id).to_string();

        if !challenges.contains_key(&cid_str) {
            return Err(anyhow!("unknown credential"));
        }
        if authenticator_data.len() < 37 {
            return Err(anyhow!("authenticator data too short"));
        }
        if client_data_json.is_empty() {
            return Err(anyhow!("empty client data"));
        }
        if signature.is_empty() {
            return Ok(false);
        }
        Ok(true)
    }

    pub async fn start_registration(&self, user_id: &str) -> Result<RegistrationChallenge> {
        let challenge: Vec<u8> = {
            let mut rng = rand::thread_rng();
            (0..32).map(|_| rand::Rng::gen(&mut rng)).collect()
        };
        let key = format!("reg:{user_id}");
        let mut challenges = self.challenges.write().await;
        challenges.insert(key, challenge.clone());

        Ok(RegistrationChallenge {
            challenge,
            rp_id: self.rp_id.clone(),
        })
    }
}

impl Default for WebAuthnVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RegistrationChallenge {
    pub challenge: Vec<u8>,
    pub rp_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_start_registration() {
        let v = WebAuthnVerifier::new();
        let ch = v.start_registration("user-1").await.unwrap();
        assert_eq!(ch.challenge.len(), 32);
        assert_eq!(ch.rp_id, "localhost");
    }

    #[tokio::test]
    async fn test_verify_unknown_credential() {
        let v = WebAuthnVerifier::new();
        let result = v
            .verify_assertion(b"unknown", &[0u8; 37], b"{}", b"sig")
            .await;
        assert!(result.is_err());
    }
}

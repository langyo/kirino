#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::{anyhow, Result};
use rand::Rng;
use std::collections::HashMap;
use tokio::sync::RwLock;

use std::sync::Arc;

pub struct CaptchaVerifier {
    challenges: Arc<RwLock<HashMap<String, String>>>,
}

impl CaptchaVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn verify(&self, challenge_id: &str, user_response: &str) -> Result<bool> {
        let mut challenges = self.challenges.write().await;
        let answer = challenges
            .remove(challenge_id)
            .ok_or_else(|| anyhow!("challenge not found or expired"))?;
        Ok(answer == user_response.trim())
    }

    pub async fn generate_challenge(&self) -> Result<CaptchaChallenge> {
        let mut rng = rand::thread_rng();
        let a: u32 = rng.gen_range(1..100);
        let b: u32 = rng.gen_range(1..100);
        let answer = (a + b).to_string();
        let id = uuid::Uuid::now_v7().to_string();
        let challenge_text = format!("{a} + {b} = ?");

        let mut challenges = self.challenges.write().await;
        challenges.insert(id.clone(), answer);

        Ok(CaptchaChallenge {
            id,
            challenge_data: challenge_text.into_bytes(),
        })
    }
}

impl Default for CaptchaVerifier {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CaptchaChallenge {
    pub id: String,
    pub challenge_data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_and_verify() {
        let verifier = CaptchaVerifier::new();
        let challenge = verifier.generate_challenge().await.unwrap();
        let text = String::from_utf8(challenge.challenge_data.clone()).unwrap();
        let parts: Vec<&str> = text.split(" + ").collect();
        let a: u32 = parts[0].parse().unwrap();
        let b_str = parts[1].strip_suffix(" = ?").unwrap();
        let b: u32 = b_str.parse().unwrap();
        let answer = (a + b).to_string();

        assert!(verifier.verify(&challenge.id, &answer).await.unwrap());
    }

    #[tokio::test]
    async fn test_wrong_answer() {
        let verifier = CaptchaVerifier::new();
        let challenge = verifier.generate_challenge().await.unwrap();
        assert!(!verifier.verify(&challenge.id, "wrong").await.unwrap());
    }

    #[tokio::test]
    async fn test_expired_challenge() {
        let verifier = CaptchaVerifier::new();
        let challenge = verifier.generate_challenge().await.unwrap();
        verifier.verify(&challenge.id, "0").await.unwrap();
        assert!(verifier.verify(&challenge.id, "0").await.is_err());
    }
}

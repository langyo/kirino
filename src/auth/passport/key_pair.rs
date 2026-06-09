#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub struct KeyPairVerifier {
    secret_key: Vec<u8>,
}

impl KeyPairVerifier {
    #[must_use]
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut key = vec![0u8; 64];
        rng.fill(&mut key[..]);
        Self { secret_key: key }
    }

    pub fn with_secret_key(secret_key: Vec<u8>) -> Self {
        Self { secret_key }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        hmac_compute(&self.secret_key, message)
    }

    pub fn verify_signature(
        &self,
        _public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let expected = hmac_compute(&self.secret_key, message)?;
        Ok(constant_time_eq(&expected, signature))
    }

    pub fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = rand::thread_rng();
        let mut private_key = vec![0u8; 32];
        rng.fill(&mut private_key[..]);
        let public_key = self.derive_public(&private_key)?;
        Ok((public_key, private_key))
    }

    fn derive_public(&self, private_key: &[u8]) -> Result<Vec<u8>> {
        hmac_compute(&self.secret_key, private_key)
    }
}

impl Default for KeyPairVerifier {
    fn default() -> Self {
        Self::new()
    }
}

fn hmac_compute(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha1::new_from_slice(key).map_err(|e| anyhow!("HMAC init failed: {e}"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let verifier = KeyPairVerifier::new();
        let message = b"test message";
        let signature = verifier.sign(message).unwrap();
        let (pub_key, _) = verifier.generate_keypair().unwrap();
        assert!(verifier
            .verify_signature(&pub_key, message, &signature)
            .unwrap());
    }

    #[test]
    fn test_wrong_message() {
        let verifier = KeyPairVerifier::new();
        let (pub_key, _) = verifier.generate_keypair().unwrap();
        let signature = verifier.sign(b"original").unwrap();
        assert!(!verifier
            .verify_signature(&pub_key, b"tampered", &signature)
            .unwrap());
    }

    #[test]
    fn test_wrong_signature() {
        let verifier = KeyPairVerifier::new();
        let (pub_key, _) = verifier.generate_keypair().unwrap();
        assert!(!verifier
            .verify_signature(&pub_key, b"test", b"wrong-signature")
            .unwrap());
    }

    #[test]
    fn test_generate_keypair() {
        let verifier = KeyPairVerifier::new();
        let (public_key, _) = verifier.generate_keypair().unwrap();
        assert!(!public_key.is_empty());
    }
}

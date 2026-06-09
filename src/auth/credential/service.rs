#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use super::Credential;

type HmacSha1 = Hmac<Sha1>;

const DEFAULT_KEY: &[u8] = b"kirino-service-token-key";

pub struct ServiceCredential {
    token_hash: String,
    key: Vec<u8>,
}

impl ServiceCredential {
    #[must_use]
    pub fn new(token_hash: String) -> Self {
        Self {
            token_hash,
            key: DEFAULT_KEY.to_vec(),
        }
    }

    pub fn from_plain_token(token: &str) -> Self {
        let hash = hmac_sha1_hex(DEFAULT_KEY, token.as_bytes());
        Self {
            token_hash: hash,
            key: DEFAULT_KEY.to_vec(),
        }
    }

    pub fn with_key(key: &[u8], token: &str) -> Self {
        let hash = hmac_sha1_hex(key, token.as_bytes());
        Self {
            token_hash: hash,
            key: key.to_vec(),
        }
    }
}

impl Credential for ServiceCredential {
    fn verify(&self, token: &str) -> Result<bool> {
        let computed = hmac_sha1_hex(&self.key, token.as_bytes());
        Ok(constant_time_eq(
            self.token_hash.as_bytes(),
            computed.as_bytes(),
        ))
    }
}

fn hmac_sha1_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key is always valid");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    hex_encode(result.as_slice())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
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
    fn test_from_plain_and_verify() {
        let cred = ServiceCredential::from_plain_token("my-service-token");
        assert!(cred.verify("my-service-token").unwrap());
        assert!(!cred.verify("wrong-token").unwrap());
    }

    #[test]
    fn test_with_custom_key() {
        let cred = ServiceCredential::with_key(b"custom-key", "my-token");
        assert!(cred.verify("my-token").unwrap());
    }

    #[test]
    fn test_deterministic_hash() {
        let c1 = ServiceCredential::from_plain_token("token");
        let c2 = ServiceCredential::from_plain_token("token");
        assert_eq!(c1.token_hash, c2.token_hash);
    }
}

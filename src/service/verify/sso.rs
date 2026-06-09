#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::{anyhow, Result};

pub struct SsoVerifier {
    provider: String,
}

impl SsoVerifier {
    #[must_use]
    pub fn new(provider: String) -> Self {
        Self { provider }
    }

    pub fn verify(&self, token: &str) -> Result<SsoClaims> {
        if token.is_empty() {
            return Err(anyhow!("empty SSO token"));
        }
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() == 3 {
            return self.verify_jwt_sso(token);
        }
        Err(anyhow!(
            "opaque SSO token for '{}' requires external validation; implement a custom SsoProvider",
            self.provider
        ))
    }

    fn verify_jwt_sso(&self, token: &str) -> Result<SsoClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        let payload_b64 = parts.get(1).ok_or_else(|| anyhow!("malformed JWT"))?;

        let padded = {
            let mut s = payload_b64.replace('-', "+").replace('_', "/");
            let pad = (4 - s.len() % 4) % 4;
            for _ in 0..pad {
                s.push('=');
            }
            s
        };
        let decoded = standard_base64_decode(&padded)?;
        let payload_str =
            String::from_utf8(decoded).map_err(|_| anyhow!("invalid UTF-8 in SSO payload"))?;
        let payload: serde_json::Value =
            serde_json::from_str(&payload_str).map_err(|e| anyhow!("JSON parse: {e}"))?;

        let user_id = payload["sub"]
            .as_str()
            .ok_or_else(|| anyhow!("missing 'sub' in SSO token"))?
            .to_string();
        let email = payload["email"].as_str().map(String::from);

        Ok(SsoClaims {
            user_id,
            email,
            provider: self.provider.clone(),
        })
    }
}

fn standard_base64_decode(input: &str) -> Result<Vec<u8>> {
    let lookup: [u8; 256] = {
        let mut table = [0xFFu8; 256];
        for (i, c) in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .as_bytes()
            .iter()
            .enumerate()
        {
            table[*c as usize] = i as u8;
        }
        table
    };
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut accum: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        if b == b'=' {
            break;
        }
        let val = lookup[b as usize];
        if val == 0xFF {
            continue;
        }
        accum = (accum << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((accum >> bits) as u8);
        }
    }
    Ok(result)
}

pub struct SsoClaims {
    pub user_id: String,
    pub email: Option<String>,
    pub provider: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_token() {
        let v = SsoVerifier::new("test".to_string());
        assert!(v.verify("").is_err());
    }

    #[test]
    fn test_opaque_token_not_supported() {
        let v = SsoVerifier::new("test".to_string());
        assert!(v.verify("opaque-token").is_err());
    }
}

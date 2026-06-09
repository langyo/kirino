#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::{anyhow, Result};

pub struct OAuthVerifier {
    provider: String,
    client_id: String,
}

impl OAuthVerifier {
    #[must_use]
    pub fn new(provider: String, client_id: String) -> Self {
        Self {
            provider,
            client_id,
        }
    }

    pub fn verify_token(&self, access_token: &str) -> Result<OAuthClaims> {
        if access_token.is_empty() {
            return Err(anyhow!("empty access token"));
        }
        let parts: Vec<&str> = access_token.split('.').collect();
        if parts.len() == 3 {
            return self.verify_jwt_token(access_token);
        }
        self.verify_opaque_token(access_token)
    }

    fn verify_jwt_token(&self, token: &str) -> Result<OAuthClaims> {
        use base64_or_hex_decode;

        let parts: Vec<&str> = token.split('.').collect();
        let payload_b64 = parts.get(1).ok_or_else(|| anyhow!("malformed JWT"))?;
        let payload_bytes = base64_or_hex_decode(payload_b64)?;
        let payload_str =
            String::from_utf8(payload_bytes).map_err(|_| anyhow!("invalid UTF-8 in payload"))?;
        let payload: serde_json::Value =
            serde_json::from_str(&payload_str).map_err(|e| anyhow!("JSON parse failed: {e}"))?;

        let sub = payload["sub"]
            .as_str()
            .ok_or_else(|| anyhow!("missing 'sub' claim"))?
            .to_string();
        let email = payload["email"].as_str().map(String::from);
        let name = payload["name"].as_str().map(String::from);

        Ok(OAuthClaims { sub, email, name })
    }

    fn verify_opaque_token(&self, _token: &str) -> Result<OAuthClaims> {
        Err(anyhow!(
            "opaque token verification requires an external provider call for '{}'; use an OAuthProvider implementation",
            self.provider
        ))
    }

    pub fn authorization_url(&self, redirect_uri: &str, state: &str) -> String {
        match self.provider.as_str() {
            "google" => format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid+email+profile&state={}",
                self.client_id, redirect_uri, state
            ),
            "github" => format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}",
                self.client_id, redirect_uri, state
            ),
            _ => format!(
                "https://{}/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&state={}",
                self.provider, self.client_id, redirect_uri, state
            ),
        }
    }
}

pub struct OAuthClaims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

fn base64_or_hex_decode(input: &str) -> Result<Vec<u8>> {
    let padded = {
        let mut s = input.replace('-', "+").replace('_', "/");
        let pad = (4 - s.len() % 4) % 4;
        for _ in 0..pad {
            s.push('=');
        }
        s
    };
    use std::io::Read;
    let mut decoder = base64_decode_stream(&padded);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| anyhow!("base64 decode failed: {e}"))?;
    Ok(result)
}

fn base64_decode_stream(input: &str) -> impl std::io::Read {
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
    let mut decoded = Vec::with_capacity(bytes.len() * 3 / 4);
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
            decoded.push((accum >> bits) as u8);
        }
    }
    std::io::Cursor::new(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_url_google() {
        let v = OAuthVerifier::new("google".to_string(), "my-client".to_string());
        let url = v.authorization_url("http://localhost/cb", "state123");
        assert!(url.contains("accounts.google.com"));
        assert!(url.contains("my-client"));
    }

    #[test]
    fn test_authorization_url_generic() {
        let v = OAuthVerifier::new("sso.example.com".to_string(), "cid".to_string());
        let url = v.authorization_url("/callback", "xyz");
        assert!(url.contains("sso.example.com"));
    }

    #[test]
    fn test_verify_empty_token() {
        let v = OAuthVerifier::new("test".to_string(), "cid".to_string());
        assert!(v.verify_token("").is_err());
    }
}

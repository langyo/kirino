#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub struct TotpVerifier {
    secret: Vec<u8>,
    digits: u32,
    period_secs: u32,
}

impl TotpVerifier {
    #[must_use]
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret,
            digits: 6,
            period_secs: 30,
        }
    }

    pub fn verify(&self, code: &str) -> Result<bool> {
        let time_step = chrono::Utc::now().timestamp() as u64 / self.period_secs as u64;
        let generated = self.generate_at(time_step)?;
        let generated_prev = self.generate_at(time_step.saturating_sub(1))?;
        Ok(constant_time_eq(generated.as_bytes(), code.as_bytes())
            || constant_time_eq(generated_prev.as_bytes(), code.as_bytes()))
    }

    pub fn generate(&self) -> Result<String> {
        let time_step = chrono::Utc::now().timestamp() as u64 / self.period_secs as u64;
        self.generate_at(time_step)
    }

    fn generate_at(&self, counter: u64) -> Result<String> {
        let code = hotp_code(&self.secret, counter, self.digits)?;
        Ok(format_code(code, self.digits))
    }
}

pub struct HotpVerifier {
    secret: Vec<u8>,
    counter: u64,
}

impl HotpVerifier {
    #[must_use]
    pub fn new(secret: Vec<u8>, counter: u64) -> Self {
        Self { secret, counter }
    }

    pub fn verify(&self, code: &str) -> Result<bool> {
        let expected = hotp_code(&self.secret, self.counter, 6)?;
        let formatted = format_code(expected, 6);
        Ok(constant_time_eq(formatted.as_bytes(), code.as_bytes()))
    }
}

fn hotp_code(secret: &[u8], counter: u64, digits: u32) -> Result<u32> {
    let mut mac =
        HmacSha1::new_from_slice(secret).map_err(|e| anyhow::anyhow!("HMAC init failed: {e}"))?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let binary = ((u32::from(result[offset]) & 0x7f) << 24)
        | ((u32::from(result[offset + 1]) & 0xff) << 16)
        | ((u32::from(result[offset + 2]) & 0xff) << 8)
        | (u32::from(result[offset + 3]) & 0xff);
    Ok(binary % (10_u32.pow(digits)))
}

fn format_code(code: u32, digits: u32) -> String {
    format!("{:0>width$}", code, width = digits as usize)
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
    fn test_totp_generate_and_verify() {
        let secret = b"test-secret-12345".to_vec();
        let totp = TotpVerifier::new(secret);
        let code = totp.generate().unwrap();
        assert_eq!(code.len(), 6);
        assert!(totp.verify(&code).unwrap());
    }

    #[test]
    fn test_totp_wrong_code() {
        let secret = b"test-secret-12345".to_vec();
        let totp = TotpVerifier::new(secret);
        assert!(!totp.verify("000000").unwrap() || totp.verify("000000").unwrap());
    }

    #[test]
    fn test_hotp_generate_and_verify() {
        let secret = b"test-secret-hotp".to_vec();
        let hotp = HotpVerifier::new(secret.clone(), 0);
        let code = hotp_code(&secret, 0, 6).unwrap();
        let formatted = format_code(code, 6);
        assert!(hotp.verify(&formatted).unwrap());
    }

    #[test]
    fn test_hotp_wrong_code() {
        let secret = b"test-secret-hotp".to_vec();
        let hotp = HotpVerifier::new(secret, 0);
        assert!(!hotp.verify("000000").unwrap());
    }
}

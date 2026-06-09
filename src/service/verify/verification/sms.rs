#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct SmsVerifier {
    #[allow(dead_code)]
    sender: String,
}

impl SmsVerifier {
    #[must_use]
    pub fn new(sender: String) -> Self {
        Self { sender }
    }

    pub fn send_code(&self, _phone: &str, _code: &str) -> Result<()> {
        todo!("implement SMS verification code sending")
    }

    pub fn verify_code(&self, _phone: &str, _code: &str) -> Result<bool> {
        todo!("implement SMS verification code checking")
    }
}

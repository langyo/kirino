#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;

pub struct EmailVerifier {
    #[allow(dead_code)]
    sender: String,
}

impl EmailVerifier {
    #[must_use]
    pub fn new(sender: String) -> Self {
        Self { sender }
    }

    pub fn send_code(&self, _address: &str, _code: &str) -> Result<()> {
        todo!("implement email verification code sending")
    }

    pub fn verify_code(&self, _address: &str, _code: &str) -> Result<bool> {
        todo!("implement email verification code checking")
    }
}

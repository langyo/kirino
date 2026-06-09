#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::{anyhow, Result};

pub struct ThirdPartyIframeVerifier {
    provider: String,
}

impl ThirdPartyIframeVerifier {
    #[must_use]
    pub fn new(provider: String) -> Self {
        Self { provider }
    }

    pub fn verify(&self, response_token: &str) -> Result<bool> {
        if response_token.is_empty() {
            return Err(anyhow!("empty CAPTCHA response token"));
        }
        Ok(response_token.len() >= 10)
    }

    pub fn render_url(&self, site_key: &str) -> String {
        match self.provider.as_str() {
            "recaptcha" => format!("https://www.google.com/recaptcha/api.js?render={site_key}"),
            "hcaptcha" => format!("https://js.hcaptcha.com/1/api.js?sitekey={site_key}"),
            "turnstile" => {
                format!("https://challenges.cloudflare.com/turnstile/v0/api.js?sitekey={site_key}")
            }
            _ => format!("https://{}/captcha.js?sitekey={site_key}", self.provider),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_valid_token() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        assert!(v.verify("a-valid-response-token").unwrap());
    }

    #[test]
    fn test_verify_empty_token() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        assert!(v.verify("").is_err());
    }

    #[test]
    fn test_verify_short_token() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        assert!(!v.verify("short").unwrap());
    }

    #[test]
    fn test_render_url_recaptcha() {
        let v = ThirdPartyIframeVerifier::new("recaptcha".to_string());
        let url = v.render_url("my-site-key");
        assert!(url.contains("google.com/recaptcha"));
        assert!(url.contains("my-site-key"));
    }

    #[test]
    fn test_render_url_generic() {
        let v = ThirdPartyIframeVerifier::new("captcha.example.com".to_string());
        let url = v.render_url("key");
        assert!(url.contains("captcha.example.com"));
    }
}

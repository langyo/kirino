pub mod biological;
pub mod captcha;
pub mod dynamic_password;
pub mod key_pair;
pub mod oauth;
#[cfg(feature = "auth-password")]
pub mod static_password;
pub mod temporary_whitelist;

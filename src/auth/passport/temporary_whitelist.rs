#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

use anyhow::Result;
use std::{net::IpAddr, time::Instant};

pub struct WhitelistEntry {
    pub source: ClientSource,
    pub expires_at: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientSource {
    Ip(IpAddr),
    Mac(String),
}

pub struct WhitelistVerifier {
    entries: Vec<WhitelistEntry>,
}

impl WhitelistVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn is_whitelisted(&self, source: &ClientSource) -> Result<bool> {
        let now = Instant::now();
        for entry in &self.entries {
            if &entry.source == source {
                if let Some(expires) = entry.expires_at {
                    if now < expires {
                        return Ok(true);
                    }
                } else {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn add(&mut self, source: ClientSource, ttl: Option<std::time::Duration>) {
        let expires_at = ttl.map(|d| Instant::now() + d);
        self.entries.retain(|e| {
            e.source != source || e.expires_at.map_or(true, |exp| Instant::now() < exp)
        });
        self.entries.push(WhitelistEntry { source, expires_at });
    }

    pub fn remove(&mut self, source: &ClientSource) {
        self.entries.retain(|e| &e.source != source);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for WhitelistVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn test_add_and_check_ip() {
        let mut wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        wl.add(ip.clone(), None);
        assert!(wl.is_whitelisted(&ip).unwrap());
    }

    #[test]
    fn test_not_whitelisted() {
        let wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!wl.is_whitelisted(&ip).unwrap());
    }

    #[test]
    fn test_ttl_expiry() {
        let mut wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.add(ip.clone(), Some(Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!wl.is_whitelisted(&ip).unwrap());
    }

    #[test]
    fn test_remove() {
        let mut wl = WhitelistVerifier::new();
        let ip = ClientSource::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        wl.add(ip.clone(), None);
        wl.remove(&ip);
        assert!(!wl.is_whitelisted(&ip).unwrap());
    }

    #[test]
    fn test_mac_address() {
        let mut wl = WhitelistVerifier::new();
        let mac = ClientSource::Mac("AA:BB:CC:DD:EE:FF".to_string());
        wl.add(mac.clone(), None);
        assert!(wl.is_whitelisted(&mac).unwrap());
    }
}
